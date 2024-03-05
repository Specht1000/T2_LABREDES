#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> // ETH_P_ALL
#include <netinet/if_ether.h>

#define LOCAL_IPV4 "10.32.143.19" // Substitua pelo endereço IPv4 da máquina local
#define LOCAL_IPV6 "fe80::a61f:72ff:fef5:9050" // Substitua pelo endereço IPv6 da máquina local

#define LOCAL_BROAD "ff:ff:ff:ff:ff:ff"

int main() {
    int s;
    char buffer[65536];
    struct sockaddr_ll src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    int arp_req, arp_rep, icmp, icmp6, ip, ip6, udp, tcp, http, syn=0;

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        perror("Erro ao criar o socket");
        return 1;
    }

    while (1) {
        int packet_len = recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &src_addr_len);
        if (packet_len < 0) {
            perror("recvfrom falhou");
            break;
        }

        struct ethhdr *eth_header = (struct ethhdr*)buffer;

 // Verificação para pacotes ARP
        if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
            struct arphdr *arp_header = (struct arphdr*)(buffer + sizeof(struct ethhdr));
            printf("Pacote ARP detectado. Tipo: ");
            if (ntohs(arp_header->ar_op) == ARPOP_REQUEST){
                printf("ARP Request %d\n", arp_req);
                arp_req++;}
            else if (ntohs(arp_header->ar_op) == ARPOP_REPLY){
                printf("ARP Reply %d \n", arp_rep);
                arp_rep++;}
            else
                printf("Outro\n");
        }

       else if (ntohs(eth_header->h_proto) == ETH_P_IPV6) {
            // Processamento de pacotes IPv6
            struct ip6_hdr *ipv6_header = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
            char straddr[INET6_ADDRSTRLEN];

            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), straddr, INET6_ADDRSTRLEN);
            if (strcmp(straddr, LOCAL_IPV6) == 0) {
                printf("Pacote IPv6 destinado ao IP local. Next Header: ");
                switch (ipv6_header->ip6_nxt) {
                    case IPPROTO_TCP:
                        printf("TCP %d\n", tcp);
                        tcp++;
                        break;
                    case IPPROTO_UDP:
                        printf("UDP %d \n", udp);
                        udp++;
                        break;
                    case IPPROTO_ICMPV6:
                        printf("ICMPv6 %d \n", icmp6);
                        icmp6++;
                        break;
                    default:
                        printf("Outro\n");
                        break;
                }
                ip6++;
                printf("IP6: %d \n", ip6);
            }
        } else if (ntohs(eth_header->h_proto) == ETH_P_IP) {
            

            // IPVA4
            struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            struct in_addr dest_addr;
            dest_addr.s_addr = ip_header->daddr;
            if (strcmp(inet_ntoa(dest_addr), LOCAL_IPV4) == 0) {
                printf("Pacote IPv4 destinado ao IP local. Protocolo: ");
                switch (ip_header->protocol) {
                    case IPPROTO_TCP:
                        printf("TCP %d \n", tcp);
                        tcp++;

                        struct tcphdr *tcp_header = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip_header->ihl*4);


                         if (tcp_header->rst == 1) {
                            printf("TCP RST Flag detectada\n");
                         }
                         else if (tcp_header->syn == 1) {
                            printf("TCP SYN Flag detectada\n");
                            syn++;
                            printf("SYN: %d \n", syn);

                            if(syn>1500) printf(" ATAQUEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE SYNFLODDDDDD \n \n \n \n \n \n \n \n \n \n ATAQUEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE SYNFLODDDDDD \n");
                        }

                        /*else if (ntohs(tcp_header->dest) == 443 || ntohs(tcp_header->source) == 443) {
                        printf("Potencial tráfego HTTPS detectado\n");
                        }*/
                          else if (ntohs(tcp_header->dest) == 80 || ntohs(tcp_header->source) == 80) {
                            printf("HTTP: %d \n", http);
                            http++;

                            if(http>1500) printf("ATAQUEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE SLOWLORIS \n \n \n \n \n AATATATTATATATTTTTAAAAAQUUUEEEE SLOWLORIS  \n \n \n");

                        }
                        break;
                    case IPPROTO_UDP:
                        printf("UDP %d \n", udp);
                        udp++;
                        break;
                    case IPPROTO_ICMP:
                        printf("ICMP %d \n", icmp);
                        icmp++;
                        break;
                    default:
                        printf("Outro\n");
                        break;
                }
                ip++;
                printf("IP: %d \n", ip);
            }
        }
    }

    close(s);
    return 0;
}
