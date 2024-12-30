#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <json-c/json.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>


#define BINDING_FILE "ip_mac_bindings.json"
#define LOG_FILE "arp_defense.log"

#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARNING 1
#define LOG_LEVEL_ERROR 0

int log_level = LOG_LEVEL_INFO;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *packet);
void load_bindings(const char *filename);
bool is_valid_binding(const char *ip, const char *mac);
void log_event(const char *event_type, const char *ip, const char *mac, const char *reason, const char *action, bool success);
void broadcast_arp_response(const char *iface, const char *ip, const char *mac);
void setup_firewall_rule(const char *ip);
void handle_signal(int signal);
void rotate_logs(const char *log_file);

struct json_object *bindings = NULL;
bool running = true;

// ctril+c 結束程式
void handle_signal(int signal) {
    if (signal == SIGINT) {
        printf("\nStopping ARP Spoofing Defense System...\n");
        running = false;
    }
}

int main(int argc, char *argv[]) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    load_bindings(BINDING_FILE);

    // 查找可用的網路介面
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 指定enp0s3 作為網路介面
    dev = "enp0s3";
    printf("Using device: %s\n", dev);

    // 使用 pcap 庫抓取 ARP 封包
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_freealldevs(alldevs);
    signal(SIGINT, handle_signal);

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("Starting ARP monitoring... Press Ctrl+C to stop.\n");

    // 處理封包
    while (running) {
        pcap_dispatch(handle, -1, packet_handler, (u_char *)dev);
    }

    pcap_close(handle);
    json_object_put(bindings);

    return 0;
}
//封包處理器
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP) return;

    struct ether_arp *arp_packet = (struct ether_arp *) (packet + sizeof(struct ether_header));
    char sender_ip[INET_ADDRSTRLEN], sender_mac[18];
    char target_ip[INET_ADDRSTRLEN], target_mac[18];

    inet_ntop(AF_INET, arp_packet->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_packet->arp_tpa, target_ip, INET_ADDRSTRLEN);
    snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_packet->arp_sha[0], arp_packet->arp_sha[1], arp_packet->arp_sha[2],
             arp_packet->arp_sha[3], arp_packet->arp_sha[4], arp_packet->arp_sha[5]);
    snprintf(target_mac, sizeof(target_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_packet->arp_tha[0], arp_packet->arp_tha[1], arp_packet->arp_tha[2],
             arp_packet->arp_tha[3], arp_packet->arp_tha[4], arp_packet->arp_tha[5]);

    if (log_level >= LOG_LEVEL_DEBUG) {
        printf("[DEBUG] Captured ARP packet: Sender IP: %s, Sender MAC: %s, Target IP: %s, Target MAC: %s\n",
               sender_ip, sender_mac, target_ip, target_mac);
    }

    //偵測與防禦
    bool valid = is_valid_binding(sender_ip, sender_mac);
    if (!valid) {
        printf("[ALERT] Spoofing detected!\n");
        printf("  - Spoofing Source: IP = %s, MAC = %s\n", sender_ip, sender_mac);
        printf("  - Target Victim: IP = %s\n", target_ip);

        log_event("spoofing_detected", sender_ip, sender_mac, "Invalid MAC for IP", "firewall_block", true);
        setup_firewall_rule(sender_ip);

        //對照IP_MAC表
        struct json_object *correct_mac_obj;
        if (json_object_object_get_ex(bindings, sender_ip, &correct_mac_obj)) {
            const char *correct_mac = json_object_get_string(correct_mac_obj);
            broadcast_arp_response((char *)user_data, sender_ip, correct_mac);
            printf("[INFO] Broadcasted ARP response: Correct MAC for IP %s -> %s\n", sender_ip, correct_mac);
            log_event("defense", sender_ip, correct_mac, "Broadcast correct ARP", "broadcast_arp", true);
        } else {
            printf("[WARNING] Correct MAC for %s not found in bindings.\n", sender_ip);
            log_event("defense", sender_ip, sender_mac, "No binding found", "broadcast_arp", false);
        }
    }
}

//加載IP_MAC表
void load_bindings(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening bindings file");
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(length + 1);
    if (!content) {
        perror("Memory allocation failed");
        fclose(file);
        exit(1);
    }

    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);

    bindings = json_tokener_parse(content);
    free(content);

    if (!bindings) {
        fprintf(stderr, "Error parsing bindings file\n");
        exit(1);
    }

    if (log_level >= LOG_LEVEL_INFO) {
        printf("[INFO] Loaded IP-MAC bindings: %s\n", json_object_to_json_string(bindings));
    }
}

//將偵測到的ip、mac與設定的IP_MAC表進行比較
bool is_valid_binding(const char *ip, const char *mac) {
    struct json_object *value;
    if (json_object_object_get_ex(bindings, ip, &value)) {
        const char *expected_mac = json_object_get_string(value);
        return strcmp(mac, expected_mac) == 0;
    }
    return false;
}

//紀錄活動
void log_event(const char *event_type, const char *ip, const char *mac, const char *reason, const char *action, bool success) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    struct json_object *log_entry = json_object_new_object();
    json_object_object_add(log_entry, "timestamp", json_object_new_string(timestamp));
    json_object_object_add(log_entry, "event_type", json_object_new_string(event_type));
    json_object_object_add(log_entry, "ip", json_object_new_string(ip));
    json_object_object_add(log_entry, "mac", json_object_new_string(mac));
    json_object_object_add(log_entry, "reason", json_object_new_string(reason));
    json_object_object_add(log_entry, "action", json_object_new_string(action));
    json_object_object_add(log_entry, "success", json_object_new_boolean(success));

    fprintf(log, "%s\n", json_object_to_json_string(log_entry));
    fclose(log);
    json_object_put(log_entry);
}

//使用防火牆進行防禦
void setup_firewall_rule(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -A INPUT -s %s -j DROP", ip);

    if (system(command) == 0) {
        printf("[INFO] Firewall rule added to block IP: %s\n", ip);
    } else {
        printf("[ERROR] Failed to add firewall rule for IP: %s\n", ip);
    }
}

//廣播
void broadcast_arp_response(const char *iface, const char *ip, const char *mac) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("[ERROR] Failed to create socket for ARP response");
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("[ERROR] Failed to get interface index");
        close(sockfd);
        return;
    }

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = ETH_ALEN;

    unsigned char packet[42];
    struct ether_header *eth = (struct ether_header *) packet;
    struct ether_arp *arp = (struct ether_arp *) (packet + sizeof(struct ether_header));

    memset(eth->ether_dhost, 0xff, ETH_ALEN);
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &eth->ether_shost[0], &eth->ether_shost[1], &eth->ether_shost[2],
           &eth->ether_shost[3], &eth->ether_shost[4], &eth->ether_shost[5]);
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &arp->arp_sha[0], &arp->arp_sha[1], &arp->arp_sha[2],
           &arp->arp_sha[3], &arp->arp_sha[4], &arp->arp_sha[5]);
    inet_pton(AF_INET, ip, arp->arp_spa);
    memset(arp->arp_tha, 0xff, ETH_ALEN);
    inet_pton(AF_INET, ip, arp->arp_tpa);

    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] Failed to send ARP response");
    } else {
        printf("[INFO] ARP response sent for IP: %s, MAC: %s\n", ip, mac);
    }

    close(sockfd);
}

void rotate_logs(const char *log_file) {
    char rotated_file[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", t);

    snprintf(rotated_file, sizeof(rotated_file), "%s.%s", log_file, timestamp);
    rename(log_file, rotated_file);
    printf("[INFO] Log file rotated to %s\n", rotated_file);
}