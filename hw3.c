#include<stdio.h>
#include<pcap.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<time.h>

#define SIZE_ETHERNET 14 //header 14 bytes
#define ETHER_ADDR_LEN 6 //address 6 bytes

//UDP header
typedef struct uheader {
	uint16_t uh_sport;					//source port
	uint16_t uh_dport;					//destination port
	uint16_t uh_length;
	uint16_t uh_sum;				//checksum
}UDP;

//Ethernet header
typedef struct eheader {
	u_char ether_dhost[ETHER_ADDR_LEN];	//destination host address
	u_char ether_shost[ETHER_ADDR_LEN];	//source host address
	u_short ether_type;					//IP? ARP? RARP? etc
}Ethernet;

//IP header
typedef struct iheader {
	u_char  ip_vhl;					//version << 4 | header length >> 2
	u_char  ip_tos;					//type of service
	u_short ip_len;					//total length
	u_short ip_id;					//identification
	u_short ip_off;					//fragment offset field
#define IP_RF 0x8000				//reserved fragment flag
#define IP_DF 0x4000				//dont fragment flag
#define IP_MF 0x2000				//more fragments flag
#define IP_OFFMASK 0x1fff			//mask for fragmenting bits
	u_char  ip_ttl;					//time to live
	u_char  ip_p;					//protocol
	u_short ip_sum;					//checksum
	struct  in_addr ip_src, ip_dst;	//source and dest address
}IP;
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

//TCP header
typedef u_int tcp_seq;

typedef struct theader {
	u_short th_sport;				//source port
	u_short th_dport;				//destination port
	tcp_seq th_seq;					//sequence number
	tcp_seq th_ack;					//acknowledgement number
	u_char  th_offx2;				//data offset, rsvd
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;					//window
	u_short th_sum;					//checksum
	u_short th_urp;					//urgent pointer
}TCP;

void packet_reader(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	static int count = 0;		//packet counter

	//declare pointers to packet headers
	const Ethernet *ethernet;	//The Ethernet header
	const IP *ip;				//The IP header
	const TCP *tcp;				//The TCP header
	const UDP *udp;				//The UDP header
	const char *payload;		//Packet payload
	//time format
	struct tm *lt;
	char timestr[80];
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	lt = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%b %d %Y, %X", lt);

	ethernet = (Ethernet*)(packet);
    count++;
    printf("=======================================\nPacket number %d:\n", count);
    printf("       Time: %s\n", timestr);
    printf("    Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
    printf("    Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
    printf("   Ethernet: 0x%04x\n", ntohs(ethernet->ether_type));

    if(ntohs(ethernet->ether_type) == 0x0800){ //IP
        int size_ip;
        ip = (IP*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;

        if(ip->ip_p == 0x06){ //TCP/IP
            printf("   Protocol: TCP/IP\n");
            tcp = (TCP*)(packet + SIZE_ETHERNET + size_ip);
            printf("       From: %s:%d\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("         To: %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
        }
        else if(ip->ip_p == 0x11){ //UDP/IP
            printf("   Protocol: UDP/IP\n");
            udp = (UDP*)(packet + SIZE_ETHERNET + size_ip);
            printf("       From: %s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
            printf("         To: %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
        }
        else{ //IP
            printf("   Protocol: IP\n");
            printf("       From: %s\n", inet_ntoa(ip->ip_src));
            printf("         To: %s\n", inet_ntoa(ip->ip_dst));
        }
    }
}

int main(int argc, char **argv){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(argc!=2){
		fprintf(stderr,"usage: %s [-filename]\n", argv[0]);
		return -1;
	}
	/* Open the file */
	if((fp = pcap_open_offline(argv[1],errbuf))==NULL){
		fprintf(stderr,"Unable to open the file %s\n", argv[1]);
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, packet_reader, NULL);

	pcap_close(fp);
	return 0;
}
