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



// Vigenere key
char* key = "FILKO";

int tlsBrojac = 0;

//reference to the dump file
pcap_dumper_t* file_dumper;


char* vigenere(char* message, char* key);

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{

	char copy[10000];
	memset(copy, 0, packet_header->len * sizeof(char));

	printf("\n\nPacket length: %ld bytes", packet_header->len);

	ethernet_header* eh = (ethernet_header*)packet_data;
	memcpy(copy, eh, sizeof(ethernet_header) * sizeof(char));

	printf("\nSource MAC: %x\nDestination MAC: %x\n", eh->src_address, eh->dest_address);


	if (ntohs(eh->type) == 0x0800) //IPv4
	{
		ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));
		memcpy(copy + sizeof(ethernet_header), ih, (ih->header_length * 4) * sizeof(char));

		printf("Source IP Address: %d.%d.%d.%d \n", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
		printf("TTL: %d\n", ih->ttl);
		printf("Header size: %d\n", ih->header_length * 4);

		switch (ih->next_protocol) {
		case 6: /*TCP*/ {
			printf("\nType:TCP");

			tcp_header* th = (tcp_header*)(packet_data + sizeof(ethernet_header) + ih->header_length * 4);
			printf("\nSrc port: %u\nDest port: %u\n", th->src_port, th->dest_port);

			printf("ACK number: %d", th->ack_num);

			if (th->dest_port == 443 || th->src_port == 443) { //TLS/SSL on 443 
				printf("TCP segment has TLS protocol.");
				tlsBrojac++;
				/*PLACE TO SEARCH FOR CONTENT TYPE INSIDE HEADER*/
			}
			break;
		}
		case 17:/*UDP*/ {
			printf("\nType:UDP");
			udp_header* uh = (udp_header*)(packet_data + sizeof(ethernet_header) + ih->header_length * 4);
			printf("\nSrc port: %u\nDest port: %u\n", uh->src_port, uh->dest_port);

			memcpy(copy + sizeof(ethernet_header) + ih->header_length * 4, uh, sizeof(udp_header));

			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);

			printf("Data: ");
			for (int i = 0; i < app_length; i++)
			{
				printf("%x ", app_data[i]);
				if ((i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");

			app_data[app_length] = '\0';
			char* encrypted = vigenere(app_data, key);
			printf("\nEncoded: %s\n", encrypted);

			memcpy(copy + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header), encrypted, strlen(encrypted));
			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)copy);

			break;
		}
		default:break;
		}


	}
	else {
		return;
	}
}




int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("example.pcap", // Name of the device
		error_buffer)) == NULL) // Error buffer
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}

	file_dumper = pcap_dump_open(device_handle, "encrypted_packets.pcap");
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity. 
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	// Read and dispatch packets until EOF is reached 
	pcap_loop(device_handle, 0, dispatcher_handler, NULL);

	printf("\n\nBroj TLS paketa: %d\n", tlsBrojac);

	// Close the file associated with device_handle and deallocates resources 
	pcap_close(device_handle);

	getchar();
}



char* vigenere(char* message, char* key) {
	int messageLen = strlen(message);
	int keyLen = strlen(key);

	// Ensure key is not empty
	if (keyLen == 0) {
		return "Error: Key should not be empty";
	}

	// Extend the key if it's shorter than the message
	for (int i = 0; i < messageLen; ++i) {
		if (key[i % keyLen] == '\0') {
			key[i % keyLen] = key[i % keyLen - keyLen];
		}
	}

	// Vigenere
	for (int i = 0; i < messageLen; ++i) {
		if (message[i] >= 'A' && message[i] <= 'Z') {
			message[i] = 'A' + (message[i] - 'A' + key[i % keyLen] - 'A') % 26;
		}
		else if (message[i] >= 'a' && message[i] <= 'z') {
			message[i] = 'a' + (message[i] - 'a' + key[i % keyLen] - 'a') % 26;
		}
	}
	message[messageLen] = '\0';

	return message;
}
