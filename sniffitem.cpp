#include "sniffitem.h"
#include "string.h"

sniffitem::sniffitem()
{
	header = NULL;
	packet = NULL;

}
sniffitem::sniffitem(const pcap_pkthdr *p_header,const u_char *p_packet) {
	header = new pcap_pkthdr;
	memcpy(header, p_header, sizeof(pcap_pkthdr));
	packet = new unsigned char[header->caplen];
	memcpy(packet, p_packet, header->caplen);

}

sniffitem::~sniffitem() {
	if (header != NULL)
	{
		delete header;
		header=NULL;
	}
	if (packet != NULL)
	{
		 delete[] packet;
		 packet=NULL;
	}
}

sniffitem::sniffitem( const sniffitem& other )
{
	header = NULL;
	packet = NULL;

     (*this)=other;
}

sniffitem& sniffitem::operator=( const sniffitem& other )
{

	if (header != NULL)
		{
			delete header;
			header=NULL;
		}
		if (packet != NULL)
		{
			 delete[] packet;
			 packet=NULL;
		}

	header = new pcap_pkthdr;
	TRACE("size of packet structure %d\n",sizeof(pcap_pkthdr));
	memcpy(header, other.header, sizeof(pcap_pkthdr));
	packet = new unsigned char(header->caplen);
	memcpy(packet, other.packet, header->caplen);
    return *this;
}
