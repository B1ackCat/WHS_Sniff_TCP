#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>
#include<arpa/inet.h>

#include "myheader.h"

void Ether(struct ethheader *eth){
	printf("========================= MAC Address =========================\n");
	printf("==      Source            ->      Destination\n");
	printf("== ");
	
	/* print Src MAC -> Dst MAC */
	for(int i=0;i<5;i++){
		printf("%02X:", eth->ether_shost[i]);
	}
	printf("%02X -> ", eth->ether_shost[5]);
	for(int i=0;i<5;i++){
		printf("%02X:", eth->ether_dhost[i]);
	}
	printf("%02X\n", eth->ether_dhost[5]);
}

void IPHeader(struct ipheader *ip){
	printf("========================= IP Address ==========================\n");
	printf("==      Source         ->         Destination\n");
	printf("== %s -> ", inet_ntoa(ip->iph_sourceip));
	printf("%s\n", inet_ntoa(ip->iph_destip));
}

void TCPHeader(struct tcpheader *tcp){
	printf("========================= TCP Port ============================\n");
	printf("== Source Port         ->     Destination Port\n");
	printf("== %hu -> %hu\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));
}

void PrintData(const u_char* packet, struct ipheader *ip, struct tcpheader *tcp){
	u_char* data;
	u_char ip_header_len = ip->iph_ihl*4;
	u_char tcp_header_len = (tcp->tcp_offx2>>4)*4;
	u_short ip_len = ntohs(ip->iph_len);
	u_short len = ip_len - ip_header_len - tcp_header_len;

	if(len > 0){
#define COLUMN_NUM 16
		data = (u_char*)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
		printf("=========================== Data ==============================\n");
		for(int i=0; i < len + ((len % COLUMN_NUM) ? (COLUMN_NUM - len % COLUMN_NUM) : 0); i++){	
			if((i % COLUMN_NUM) == 0) printf("%04X: ",i);
			if(data[i]){
				printf("%02X ", data[i]);
			}
			else{
				printf("00 ");
			}

			if((i%COLUMN_NUM) == (COLUMN_NUM-1)){
				for(int j=i-(COLUMN_NUM-1); j<=i; j++){
					char c=data[j];
					if((c >= ' ') && (c <= '~')){
						putchar(c);
					}
					else{
						putchar('.');
					}
				}
				putchar('\n');
			}
		}
	}
	putchar('\n');
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	Ether(eth);

	if(ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
		struct ipheader *ip = (struct ipheader*)(packet+sizeof(struct ethheader));
		IPHeader(ip);
		if(ip->iph_protocol == IPPROTO_TCP){
			struct tcpheader *tcp = (struct tcpheader*)(packet+sizeof(struct ethheader)+ip->iph_ihl*4);
			TCPHeader(tcp);
			PrintData(packet, ip, tcp);	
		}
	}
}

int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net;

	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	if(pcap_setfilter(handle, &fp) != 0) {
		pcap_perror(handle, "Error:");
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
}
