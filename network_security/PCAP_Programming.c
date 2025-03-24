#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // IPv4만 처리
    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    // TCP만 처리
    if (ip->iph_protocol != IPPROTO_TCP) return;

    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    int total_headers_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_headers_size;
    const u_char *payload = packet + total_headers_size;

    // IP 출력 안전하게 처리 (inet_ntoa는 static buffer 사용 주의!)
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    strncpy(src_ip, inet_ntoa(ip->iph_sourceip), INET_ADDRSTRLEN);
    strncpy(dst_ip, inet_ntoa(ip->iph_destip), INET_ADDRSTRLEN);

    // 출력
    printf("\n• Ethernet Header:\n");
    printf("  src → %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  dst → %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("• IP Header:\n");
    printf("  src → %s\n", src_ip);
    printf("  dst → %s\n", dst_ip);

    printf("• TCP Header:\n");
    printf("  src → %d\n", ntohs(tcp->tcp_sport));
    printf("  dst → %d\n", ntohs(tcp->tcp_dport));

    printf("• Message:\n");
    if (payload_len > 0) {
        printf("  ");
        for (int i = 0; i < payload_len && i < 50; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    } else {
        printf("  (없음)\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    // 네트워크 인터페이스 이름 확인 후 수정
    handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
