#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

// Ethernet Header
struct ethheader {
    unsigned char ether_dhost[6];  // Destination MAC address
    unsigned char ether_shost[6];  // Source MAC address
    unsigned short ether_type;     // EtherType
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
  };
  
// TCP Header
struct tcpheader {
    unsigned short tcp_sport;     // Source port
    unsigned short tcp_dport;     // Destination port
    unsigned int tcp_seq;         // Sequence number
    unsigned int tcp_ack;         // Acknowledgment number
    unsigned char tcp_lenres;     // Data offset & reserved
    unsigned char tcp_flags;      // TCP flags
    unsigned short tcp_win;       // Window size
    unsigned short tcp_checksum;  // Checksum
    unsigned short tcp_urgptr;    // Urgent pointer
};

// 패킷 처리 함수
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {

        
    struct ethheader *eth = (struct ethheader *)packet;
    // Ethernet Header 출력
    printf("****Ethernet Header****\n");
    printf("  src mac: ");
        for (int i = 0; i < 6; i++) {
            printf("%02x", eth->ether_shost[i]);
            if (i < 5) printf(":");
        }
        printf(" /");
        printf(" dst mac: ");
        for (int i = 0; i < 6; i++) {
            printf("%02x", eth->ether_dhost[i]);
            if (i < 5) printf(":");
        }
        printf("\n");
    // IP Header 추출
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *)
                               (packet + sizeof(struct ethheader)); 
        printf("****IP Header****\n");
        printf("    src ip : %s / ", inet_ntoa(ip->iph_sourceip));   
        printf("dst ip : %s\n", inet_ntoa(ip->iph_destip));    
    

        // IP 프로토콜이 TCP인 경우에만 TCP 헤더 출력
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
 
            // TCP Header 출력 (Source Port, Destination Port만)
            printf("****TCP Header****\n");
            printf("   src port: %d / ", ntohs(tcp->tcp_sport));
            printf(" dst port: %d\n", ntohs(tcp->tcp_dport));

            const unsigned char *message = packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + (tcp->tcp_lenres >> 4) * 4;

            int message_size = header->len - (message - packet);  // 패킷 크기에서 메시지 크기 계산
            if (message_size > 0) {
                printf("Message:\n");
                for (int i = 0; i < message_size && i < 128; i++) {  // 최대 128바이트까지 출력
                    if (message[i] >= 32 && message[i] <= 126) {  // printable ASCII characters
                        printf("%c", message[i]);  // 문자 그대로 출력
                    } else {
                        printf(".");  // 비 printable 문자일 경우 '.'로 대체
                    }
                }
                printf("\n");
            } else {
                printf("No Message\n");
                printf("\n");
            }
        
           }
    }
}  

    int main()
    {
      pcap_t *handle;
      char errbuf[PCAP_ERRBUF_SIZE];
      struct bpf_program fp;
      char filter_exp[] = "tcp port 80";
      bpf_u_int32 net;
    
      // Step 1: Open live pcap session on NIC with name enp0s3
      handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    
      // Step 2: Compile filter_exp into BPF psuedo-code
      pcap_compile(handle, &fp, filter_exp, 0, net);
      if (pcap_setfilter(handle, &fp) !=0) {
          pcap_perror(handle, "Error:");
          exit(EXIT_FAILURE);
      }
    
      // Step 3: Capture packets
      pcap_loop(handle, -1, got_packet, NULL);
    
      pcap_close(handle);   //Close the handle
      return 0;
    }