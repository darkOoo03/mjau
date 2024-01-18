// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"



int arpCount = 0;
char copy[10000];

char key[] = "QVIDE";//Ceaser cypher of word "MREZA" using step 4

//reference to the dump file
pcap_dumper_t* file_dumper;


char* encrypt_data(char* message, char* key);

void dispatcher_handler(unsigned char* fd, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);



int main() {
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("example.pcap",error_buffer)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}
	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	pcap_dumper_t* file_dumper = pcap_dump_open(device_handle, "encrypted_packets.pcap");
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}
	char filter_exp[] = "ip or arp";
	struct bpf_program fcode;
	
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, 0xffffff) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}
	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}


	// Read and dispatch packets until EOF is reached
	pcap_loop(device_handle, 0, dispatcher_handler, (unsigned char*)file_dumper);

	// Close the file associated with device_handle and deallocates resources
	pcap_close(device_handle);

	printf("\nARP packets: %d\n",arpCount);

	return 0;
}

void dispatcher_handler(unsigned char* fd, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data) {
	memset(copy, 0, sizeof(copy));

	if (packet_header == NULL) return; //weird magic null packet_header - probably a faulty packet, leave just in case

	printf("Packet length: %ld byte(s)\n", packet_header->len);

	ethernet_header* eh = (ethernet_header*)packet_data;
	memcpy(copy, eh, sizeof(ethernet_header));

	printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eh->dest_address[0], eh->dest_address[1], eh->dest_address[2],
		eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);

	if (ntohs(eh->type) == 0x0800) {
		ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));
		memcpy(copy + sizeof(ethernet_header), ih, ih->header_length * 4);

		printf("Src: %d.%d.%d.%d\nDst: %d.%d.%d.%d\n",
			ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3],
			ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

		if (ih->next_protocol == 0x6) { // TCP
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);

			printf("Dest port: %u\n", ntohs(th->dest_port));
			printf("Window size: %u\n", ntohs(th->windows_size));

			if (th->flags == 16 && th->sequence_num == 0) {
				printf("ACK flag detected and seq num=0;\n");
				printf("Source port: %u\n", ntohs(th->src_port));
			}

			if (ntohs(th->src_port) == 80 || ntohs(th->dest_port) == 80) {
				printf("HTTP protocol, data: \n");

				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				for (int i = 0; i < 16; i++) {
					printf("%c", app_data[i]);
				}
				printf("\n");
			}
		}
		else if (ih->next_protocol == 0x11) { // UDP
			udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);
			memcpy(copy + sizeof(ethernet_header) + ih->header_length * 4, uh, sizeof(udp_header));

			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			printf("UDP: Packet size: %u\n", ntohs(uh->datagram_length));

			char* coded = encrypt_data(app_data, key);
			memcpy(copy + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header), coded, strlen(coded));

			pcap_dump((unsigned char*)fd, packet_header, (const unsigned char*)copy);
		}
	}
	else if (ntohs(eh->type) == 0x0806) {
		printf("ARP packet read...\n\n");
		arpCount++;
		return;
	}

	printf("\n");
}



char* encrypt_data(char* message, char* key) {
	// Vigenere algorithm
	size_t messageLen = strlen(message);
	size_t keyLen = strlen(key);

	if (messageLen == 0 || keyLen == 0) {
		return NULL;
	}

	for (size_t i = 0; i < messageLen; ++i) {
		if (message[i] >= 'A' && message[i] <= 'Z') {
			message[i] = 'A' + (message[i] - 'A' + key[i % keyLen] - 'A') % 26;
		}
		else if (message[i] >= 'a' && message[i] <= 'z') {
			message[i] = 'a' + (message[i] - 'a' + key[i % keyLen] - 'a') % 26;
		}
	}

	return message;
}
