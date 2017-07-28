//BoB 6th BadSpell(KJS)
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#define ARP_REQUEST		1
#define ARP_REPLY			2

typedef enum _ARP_OPCODE
{
	ARP_Request = 1,
	ARP_Reply = 2,
} ARP_OPCODE;

typedef struct _ETHER_HEADER
{
	uint8_t destHA[6];
	uint8_t sourceHA[6];
	uint16_t type;
} __attribute__((packed)) ETHER_HEADER, *LPETHER_HEADER;

typedef struct _ARP_HEADER
{
    u_int16_t hardwareType;
    u_int16_t protocolType;
    u_char hardwareAddressLength;
    u_char protocolAddressLength;
    u_int16_t operationCode;
    u_char senderHA[6];
    u_char senderIP[4];
    u_char targetHA[6];
    u_char targetIP[4];
} __attribute__((packed)) ARP_HEADER, *LPARP_HEADER;

char *getMac(uint8_t *mac)
{
	static char macAddress[32];
	sprintf(macAddress, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1],  mac[2],  mac[3],  mac[4], mac[5]);
	return macAddress;
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev, *sender_ip, *target_ip;
	pcap_t *handle;
	u_char packet[1500];
	struct ifreq if_mac, if_ip;
	uint8_t localMacAddress[6];
	uint32_t localIPAddress;
	int sockfd;

	if (argc != 4)
	{
		printf("Usage: %s [interface] [sender ip] [target ip]\n", argv[0]);
		return 2;
	}
	dev = argv[1];
	sender_ip = argv[2];
	target_ip = argv[3];

	handle = pcap_open_live(dev, BUFSIZ, 1, 300, errbuf);
	if (handle == NULL)
	{
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printf("Open Raw socket error.\n");
		return 2;
	}
	
	// Get local MAC Address and IP
	strncpy(if_mac.ifr_name, dev, IFNAMSIZ - 1);
	strncpy(if_ip.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(sockfd, SIOCGIFHWADDR, &if_mac);
	ioctl(sockfd, SIOCGIFADDR, &if_ip);
	memcpy(localMacAddress, if_mac.ifr_hwaddr.sa_data, 6);
	localIPAddress = ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr;

	// Make ARP packet !!
	LPETHER_HEADER etherHeader = (LPETHER_HEADER)packet;
	uint32_t utarget_ip;

	memcpy(etherHeader->destHA, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	memcpy(etherHeader->sourceHA, localMacAddress, 6);
	etherHeader->type = ntohs(ETHERTYPE_ARP);

	LPARP_HEADER ipHeader = (LPARP_HEADER)(packet + sizeof(ETHER_HEADER));
	ipHeader->hardwareType = ntohs(1);
	ipHeader->protocolType = ntohs(ETHERTYPE_IP);
	ipHeader->hardwareAddressLength = 6;
	ipHeader->protocolAddressLength = 4;
	ipHeader->operationCode = ntohs(ARP_REQUEST);
	memcpy(ipHeader->senderHA, localMacAddress, 6);
	memcpy(ipHeader->senderIP, &localIPAddress, 4);
	memcpy(ipHeader->targetHA, "\x00\x00\x00\x00\x00\x00", 6);
	utarget_ip = inet_addr(sender_ip);
	memcpy(ipHeader->targetIP, &utarget_ip, 4);

	printf("Send ARP broadcast for get victim's MAC Address...\n");
	pcap_sendpacket(handle, packet, sizeof(ETHER_HEADER) + sizeof(ARP_HEADER));

	const u_char *captured_packet;
	struct pcap_pkthdr *header;
	uint8_t victimHA[6];

	while (pcap_next_ex(handle, &header, &captured_packet) >= 0)
	{
		if (!captured_packet) // Null packet check
			continue;

		LPETHER_HEADER etherHeader = (LPETHER_HEADER)captured_packet;
		if (ntohs(etherHeader->type) != ETHERTYPE_ARP)
			continue;

		LPARP_HEADER ipHeader = (LPARP_HEADER)(captured_packet + sizeof(ETHER_HEADER));
		if (ntohs(ipHeader->protocolType) == ETHERTYPE_IP && ntohs(ipHeader->operationCode) == ARP_REPLY)
		{
			printf("Received ARP from %s\n", sender_ip);
			printf("%s Mac Address -> %s\n", sender_ip, getMac(ipHeader->senderHA));

			memcpy(victimHA, ipHeader->senderHA, 6);
			break;
		}
	}
	pcap_close(handle);
	return 0;
}