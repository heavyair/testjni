#include "netheader.h"


class sniffitem
{
public:
	sniffitem();
	sniffitem(const pcap_pkthdr *p_header,const u_char *p_packet);
	~sniffitem();
	sniffitem( const sniffitem& other);
	sniffitem& operator=( const sniffitem& other );

public:
	pcap_pkthdr *header;
	u_char *packet;

};

typedef sniffitem* pSniffitem;
