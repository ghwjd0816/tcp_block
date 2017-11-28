#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<libnet.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/socket.h>

#define AF_LINK AF_PACKET
#define SIZE_OF_ETHERNET 14
#define SIZE_OF_ARP 8
#define SIZE_OF_IPV4 20
#define SIZE_OF_TCP 20
#define PACKET_SIZE 42

struct ip_address{
	u_char ar_sha[6];
	u_char ar_spa[4];
	u_char ar_tha[6];
	u_char ar_tpa[4];
};

void usage()
{
	printf("[*]usage  : sudo ./tcp_block\n");
}

void print_mac(uint8_t*mac)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void dump(u_char* packet, int len)
{
	for(int i=0;i<len;i++)
	{
		if(i>0&&i%16==0)puts("");
		printf("%02X ",packet[i]);
	}
	puts("");
}

int main(int argc, char **argv)
{
	printf("[+]TCP_BLOCK\n");
	char *dev,errbuf[PCAP_ERRBUF_SIZE],my_ip[20];
	if(argc != 1)
	{
		usage();
		return -1;
	}

	strncmp(argv[1], my_ip, 20);
	
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		printf("[-]Failed to find network device.\n");
		return -1;
	}
	printf("[*]Device Name : %s\n",dev);
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		printf("[-]Failed to open devie %s : %s\n",dev,errbuf);
		return -1;
	}

	while(true)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		u_char* rst_packet;
		int len;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0)continue;
		if(res == -1 || res == -2)break;

		struct libnet_ethernet_hdr *ethernet, *rst_ethernet;
		struct libnet_ipv4_hdr *ip, *rst_ip;
		struct libnet_tcp_hdr *tcp, *rst_tcp;

		ethernet = (struct libnet_ethernet_hdr*)packet;
		if(ntohs(ethernet->ether_type) != ETHERTYPE_IP)continue;
		ip = (struct libnet_ipv4_hdr*)(packet + SIZE_OF_ETHERNET);
		if(ip->ip_p != 0x06)continue;
		tcp = (struct libnet_tcp_hdr*)(ip + SIZE_OF_IPV4);
		int size_of_tcp = tcp->th_off>>4;
						
		len = size_of_tcp + SIZE_OF_IPV4 + SIZE_OF_ETHERNET;
		len = header->len - len;
		printf("[*]Send Forward RST\n");		
//Forward RST
		tcp->th_flags = TH_RST;
		int th_seq = tcp->th_seq;
		tcp->th_seq += len>0?len:1;
		if(pcap_sendpacket(handle, packet, header->len)==-1)
		{
			printf("[-]Failed to send forward rst packet\n");
			return -1;
		}
		tcp->th_seq = th_seq;

		printf("[*]Send Backward RST\n");
		rst_ethernet = (struct libnet_ethernet_hdr*)malloc(SIZE_OF_ETHERNET);
		rst_ip = (struct libnet_ipv4_hdr*)malloc(SIZE_OF_IPV4);
		rst_tcp = (struct libnet_tcp_hdr*)malloc(size_of_tcp);
//Backward RST
		printf("[*]ETHERNET\n");
		memcpy(rst_ethernet->ether_dhost, ethernet->ether_shost,sizeof(ethernet->ether_shost));
		memcpy(rst_ethernet->ether_shost, ethernet->ether_dhost,sizeof(ethernet->ether_dhost));
		rst_ethernet->ether_type = ethernet->ether_type;

		printf("[*]IPV4\n");
		memcpy(rst_ip, ip, SIZE_OF_IPV4);
		rst_ip->ip_src = ip->ip_dst;
		rst_ip->ip_dst = ip->ip_src;

		printf("[*]TCP\n");
		memcpy(rst_tcp, tcp, size_of_tcp);
		rst_tcp->th_sport = tcp->th_dport;
		rst_tcp->th_dport = tcp->th_sport;
		rst_tcp->th_seq = tcp->th_ack;
		rst_tcp->th_ack = tcp->th_seq + (len>0?len:1);

		printf("[*]RST_PACKET\n");
		memcpy(rst_packet, rst_ethernet, SIZE_OF_ETHERNET);
		memcpy(rst_packet+SIZE_OF_ETHERNET, rst_ip, SIZE_OF_IPV4);
		memcpy(rst_packet+SIZE_OF_ETHERNET+SIZE_OF_IPV4, rst_tcp, size_of_tcp);
		
		if(pcap_sendpacket(handle, rst_packet, header->len)==-1)
		{
			printf("[-]Failed to send backward rst packet\n");
			return -1;
		}
		free(rst_ethernet);
		free(rst_ip);
		free(rst_tcp);
		//free(rst_packet);
	}


	pcap_close(handle);
}


