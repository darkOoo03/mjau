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

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("packetsv12.pcap", // Name of the device
		error_buffer // Error buffer
	)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "packetsv12.pcap");
		return -1;
	}
	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	pcap_dumper_t* file_dumper = pcap_dump_open(device_handle, "encrypted_packets .pcap");
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	unsigned int netmask;
	char filter_exp[] = "tcp";
	struct bpf_program fcode;

	if (pcap_compile(device_handle, &fcode, filter_exp, 1, 0xFFFFFF) < 0)
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
	pcap_loop(device_handle, 10, dispatcher_handler, NULL);
	// Close the file associated with device_handle and deallocates resources
	pcap_close(device_handle);
	return 0;
}
int j = 0;
int k = 0;
void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	time_t timestamp;
	struct tm* local_time;
	char time_string[16];
	timestamp = packet_header->ts.tv_sec;
	local_time = localtime(&timestamp);

	strftime(time_string, sizeof time_string, "%H:%M:%S", local_time);
	printf("%d Packet: %s\n", ++j, time_string);

	ethernet_header* eh = (ethernet_header*)packet_data;
	ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));

	if(ntohs(eh->type) == 0x0800){
		printf("Logicka adresa posiljaoca: %d.%d.%d.%d\n",ih->src_addr[0],ih->src_addr[1],ih->src_addr[2],ih->src_addr[3]);
		printf("Time to live vrednost: %d\n", ih->ttl);

		int ip_len = ih->header_length * 4;
		icmp_header* icmp = (icmp_header*)(packet_data + sizeof(ethernet_header));

		if (ih->next_protocol == 1) {
			printf("\nICMP Protokol:\n");
			printf("SADRZAJ: %s\n", icmp->data);
			printf("TIP: %d\n", icmp->type);
		}
		else if (ih->next_protocol == 6) {
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ip_len);
			printf("\nTCP PROTOKOL: \n");
			if (th->ack_num!=0) {
				printf("Port posiljaoca: %u\n",ntohs(th->src_port));
				printf("Broj potvrde: %d\n",th->ack_num);
			}
			if (ntohs(th->src_port) == 80 || ntohs(th->dest_port) == 80) {
				k++;
				printf("\nHTTP SADRZAJ: \n");
				unsigned char* app_data = (unsigned char*)((unsigned char*)th + th->header_length * 4);
				printf("%s\n", app_data);
			}
			printf("\n\nHTTP UDEO: %f\n\n",(k/j)*100);
		}
		else if (ih->next_protocol == 17) {
			udp_header* uh = (udp_header*)((unsigned char*)ih + ip_len);
			printf("\nUDP PROTOKOL: \n");
			printf("Ukupna duzina podataka: %d\n",uh->datagram_length);
			printf("Kontrolna suma: %d\n", uh->checksum);
		}

	}

}
