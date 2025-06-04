#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <errno.h>

#define REDIRECT_MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

void DumpHex(const void* data, int size) {
    char ascii[17];
    int i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int get_interface_info(const char *dev, unsigned char mac_out[6], uint32_t *ip_out) {
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // MAC 주소 가져오기
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(fd);
        return -1;
    }
    memcpy(mac_out, (unsigned char *)ifr.ifr_hwaddr.sa_data, 6);

    // IPv4 주소 가져오기
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(fd);
        return -1;
    }
    *ip_out = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    close(fd);

    // 출력
    printf("My MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac_out[0], mac_out[1], mac_out[2],
           mac_out[3], mac_out[4], mac_out[5]);

    struct in_addr ia;
    ia.s_addr = *ip_out;
    printf("My IP : %s\n", inet_ntoa(ia));

    return 0;
}

uint16_t CheckSum(uint16_t *buffer, int size) {
    uint32_t cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= 2;
    }
    if (size > 0) {
        cksum += *(uint8_t *)buffer;
    }
    while (cksum >> 16) {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }
    return (uint16_t)(~cksum);
}

#pragma pack(push, 1)
typedef struct {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t  reserved;
    uint8_t  proto;
    uint16_t tcpLen;
} PseudoHdr;
#pragma pack(pop)

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char *pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1) libpcap 으로 인터페이스 열기
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

    // 2) 내 MAC, IP 주소 얻기
    unsigned char my_mac[6];
    uint32_t my_ip;
    if (get_interface_info(dev, my_mac, &my_ip) != 0) {
        fprintf(stderr, "Failed to get interface info for %s\n", dev);
        pcap_close(handle);
        return -1;
    }

    // 3) Raw socket 생성 (IP 헤더 포함)
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("socket(AF_INET, SOCK_RAW)");
        pcap_close(handle);
        return -1;
    }
    int on = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(raw_sock);
        pcap_close(handle);
        return -1;
    }

    printf(">>> Listening on interface %s, blocking pattern: \"%s\"\n", dev, pattern);

    // 4) 무한 루프: 패킷 캡처 및 처리
    while (1) {
        struct pcap_pkthdr *pkt_header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &pkt_header, &pkt_data);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex returned %d (%s)\n", res, pcap_geterr(handle));
            break;
        }

        // 캡처된 패킷 총 길이
        printf("%u bytes captured\n", pkt_header->caplen);

        // Ethernet 헤더 파싱
        if (pkt_header->caplen < sizeof(struct ether_header)) continue;
        struct ether_header *eth = (struct ether_header *)pkt_data;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;  // IPv4가 아니면 스킵

        // IP 헤더 파싱
        const u_char *ip_start = pkt_data + sizeof(struct ether_header);
        struct ip *ip_hdr = (struct ip *)ip_start;
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;  // TCP가 아니면 스킵

        // 전체 IP 패킷 길이 (바이트 단위)
        int total_ip_len = ntohs(ip_hdr->ip_len);
        if (total_ip_len < ip_hdr_len) continue;

        // TCP 헤더 파싱
        const u_char *tcp_start = ip_start + ip_hdr_len;
        if (pkt_header->caplen < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct tcphdr)) continue;
        struct tcphdr *tcp_hdr = (struct tcphdr *)tcp_start;
        int tcp_hdr_len = tcp_hdr->th_off * 4;

        // TCP 페이로드 길이 계산
        int tcp_data_len = total_ip_len - ip_hdr_len - tcp_hdr_len;
        if (tcp_data_len <= 0) continue;  // 페이로드가 없으면 스킵

        // 페이로드 포인터
        const char *payload = (const char *)(tcp_start + tcp_hdr_len);
        if (payload == NULL) continue;

        // 패턴 매칭: 페이로드 안에 pattern 문자열이 포함되었는지
        if (strstr(payload, pattern) == NULL) {
            continue;
        }

        {
            int fwd_hdr_len = sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;
            u_char *fwd_buf = (u_char *)malloc(fwd_hdr_len);
            if (!fwd_buf) {
                perror("malloc forward buffer");
                continue;
            }

            // 원본 패킷에서 Ethernet + IP + TCP 헤더만 복사
            memcpy(fwd_buf, pkt_data, fwd_hdr_len);

            // (1) Ethernet: 출발지 MAC 주소(my_mac)로 변경
            struct ether_header *fwd_eth = (struct ether_header *)fwd_buf;
            memcpy(fwd_eth->ether_shost, my_mac, 6);
            // 목적지 MAC(ether_dhost)은 원본대로 유지

            // (2) IP 헤더 수정
            struct ip *fwd_iph = (struct ip *)(fwd_buf + sizeof(struct ether_header));
            // IP 전체 길이: IP 헤더 + TCP 헤더, 페이로드는 0
            fwd_iph->ip_len = htons(ip_hdr_len + tcp_hdr_len);
            fwd_iph->ip_sum = 0;
            fwd_iph->ip_sum = CheckSum((uint16_t *)fwd_iph, ip_hdr_len);

            // (3) TCP 헤더 수정
            struct tcphdr *fwd_tcph = (struct tcphdr *)((u_char *)fwd_iph + ip_hdr_len);
            // Seq 번호: 원본 Seq + 페이로드 길이
            uint32_t orig_seq = ntohl(tcp_hdr->th_seq);
            fwd_tcph->th_seq = htonl(orig_seq + tcp_data_len);
            // RST + ACK 플래그 설정
            fwd_tcph->th_flags = TH_RST | TH_ACK;
            // 데이터 오프셋(th_off)은 이미 복사된 값 유지 (옵션이 있다면 그대로)
            // 윈도우 크기, 기타 필드도 복사 상태 유지
            fwd_tcph->th_sum = 0;

            // TCP 체크섬 계산 (Pseudo Header + TCP 헤더)
            PseudoHdr phdr;
            memset(&phdr, 0, sizeof(PseudoHdr));
            phdr.srcAddr = fwd_iph->ip_src.s_addr;
            phdr.dstAddr = fwd_iph->ip_dst.s_addr;
            phdr.reserved = 0;
            phdr.proto = IPPROTO_TCP;
            phdr.tcpLen = htons(tcp_hdr_len);

            // 체크섬: (PseudoHdr + TCP헤더) 합산
            int pseudo_pkt_len = sizeof(PseudoHdr) + tcp_hdr_len;
            u_char *cksum_buf = (u_char *)malloc(pseudo_pkt_len);
            if (!cksum_buf) {
                perror("malloc cksum buf");
                free(fwd_buf);
                continue;
            }
            memcpy(cksum_buf, &phdr, sizeof(PseudoHdr));
            memcpy(cksum_buf + sizeof(PseudoHdr), fwd_tcph, tcp_hdr_len);
            fwd_tcph->th_sum = CheckSum((uint16_t *)cksum_buf, pseudo_pkt_len);
            free(cksum_buf);

            // pcap을 통해 전송
            if (pcap_sendpacket(handle, fwd_buf, fwd_hdr_len) != 0) {
                fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
            }
            free(fwd_buf);
        }

        {
            int msg_len = (int)strlen(REDIRECT_MSG);
            int back_hdr_len = sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len + msg_len;
            u_char *back_buf = (u_char *)malloc(back_hdr_len);
            if (!back_buf) {
                perror("malloc backward buffer");
                continue;
            }

            // (1) Ethernet 헤더: 원본 패킷 복사 후 변경
            memcpy(back_buf, pkt_data, sizeof(struct ether_header));
            struct ether_header *back_eth = (struct ether_header *)back_buf;
            // 출발지 MAC = 내 MAC
            memcpy(back_eth->ether_shost, my_mac, 6);
            // 목적지 MAC = 원본 Ethernet 의 출발지 MAC
            memcpy(back_eth->ether_dhost, eth->ether_shost, 6);

            // (2) IP 헤더: 원본 IP 헤더 복사 후 수정
            u_char *back_ip_start = back_buf + sizeof(struct ether_header);
            memcpy(back_ip_start, ip_start, ip_hdr_len);
            struct ip *back_iph = (struct ip *)back_ip_start;

            // IP 전체 길이 = IP 헤더 + TCP 헤더 + redirect 메시지
            back_iph->ip_len = htons(ip_hdr_len + tcp_hdr_len + msg_len);
            // TTL: 임의로 64→128 로 설정 (원본에서 복사된 TTL 무시)
            back_iph->ip_ttl = 128;
            // 출발지 IP = 원본 목적지 IP (서버 IP)
            uint32_t orig_src_ip = ip_hdr->ip_src.s_addr;
            uint32_t orig_dst_ip = ip_hdr->ip_dst.s_addr;
            back_iph->ip_src.s_addr = orig_dst_ip;
            back_iph->ip_dst.s_addr = orig_src_ip;
            back_iph->ip_sum = 0;
            back_iph->ip_sum = CheckSum((uint16_t *)back_iph, ip_hdr_len);

            // (3) TCP 헤더: 원본 TCP 헤더 복사 후 수정
            u_char *back_tcp_start = back_ip_start + ip_hdr_len;
            memcpy(back_tcp_start, tcp_start, tcp_hdr_len);
            struct tcphdr *back_tcph = (struct tcphdr *)back_tcp_start;

            // 소스 포트 = 원본 목적지 포트 (서버 포트)
            back_tcph->th_sport = tcp_hdr->th_dport;
            // 목적지 포트 = 원본 출발지 포트 (클라이언트 포트)
            back_tcph->th_dport = tcp_hdr->th_sport;
            // ACK 번호 = 원본 Seq + 페이로드 길이
            back_tcph->th_ack = htonl(ntohl(tcp_hdr->th_seq) + tcp_data_len);
            // Seq 번호 = 원본 ACK 번호
            back_tcph->th_seq = tcp_hdr->th_ack;
            // ACK + FIN 플래그 설정
            back_tcph->th_flags = TH_ACK | TH_FIN;
            // 데이터 오프셋(th_off) = 그대로 복사된 값 유지 (옵션이 있을 경우)
            back_tcph->th_sum = 0;

            // (4) redirect 메시지 복사
            u_char *back_payload = back_tcp_start + tcp_hdr_len;
            memcpy(back_payload, REDIRECT_MSG, msg_len);

            // (5) TCP 체크섬 계산 (Pseudo Header + TCP 헤더 + 메시지)
            PseudoHdr phdr2;
            memset(&phdr2, 0, sizeof(PseudoHdr));
            phdr2.srcAddr = back_iph->ip_src.s_addr;
            phdr2.dstAddr = back_iph->ip_dst.s_addr;
            phdr2.reserved = 0;
            phdr2.proto = IPPROTO_TCP;
            phdr2.tcpLen = htons(tcp_hdr_len + msg_len);

            int pseudo_pkt2_len = sizeof(PseudoHdr) + tcp_hdr_len + msg_len;
            u_char *cksum_buf2 = (u_char *)malloc(pseudo_pkt2_len);
            if (!cksum_buf2) {
                perror("malloc cksum buf2");
                free(back_buf);
                continue;
            }
            memcpy(cksum_buf2, &phdr2, sizeof(PseudoHdr));
            memcpy(cksum_buf2 + sizeof(PseudoHdr), back_tcph, tcp_hdr_len);
            memcpy(cksum_buf2 + sizeof(PseudoHdr) + tcp_hdr_len, back_payload, msg_len);
            back_tcph->th_sum = CheckSum((uint16_t *)cksum_buf2, pseudo_pkt2_len);
            free(cksum_buf2);

            // (6) Raw socket 으로 IP 헤더부터 전송 (Ethernet 헤더는 무시)
            struct sockaddr_in dst_addr;
            dst_addr.sin_family = AF_INET;
            dst_addr.sin_port = back_tcph->th_dport;  // 네트워크 바이트 순서
            dst_addr.sin_addr.s_addr = back_iph->ip_dst.s_addr;

            // DumpHex(&back_buf, back_hdr_len);  // 디버깅용 헥사 덤프
            if (sendto(raw_sock,
                       back_iph,
                       ip_hdr_len + tcp_hdr_len + msg_len,
                       0,
                       (struct sockaddr *)&dst_addr,
                       sizeof(dst_addr)) < 0) {
                perror("sendto backward");
            }

            free(back_buf);
        }
    }

    close(raw_sock);
    pcap_close(handle);
    return 0;
}
