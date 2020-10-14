#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 8192

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = NULL;
	
	handle = pcap_open_live("ens33", MAX_PACKET_SIZE, 0, 512, errbuf);
	if(handle == NULL) {
		printf("couldn't open device ens33\n");
		return -1;
	}
	printf("ens33 opened\n");
	
	struct pcap_pkthdr *header;
	const uint8_t *packet;
	int res;

	while((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
		if(res == 0)
			continue;
		printf("%02x:%02x:%02x:%02x:%02x:%02x\t", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
		printf("-->\t");
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
	}
	

	return 0;
}

