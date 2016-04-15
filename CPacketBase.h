/*
 * CPacketBase.h
 *
 *  Created on: Mar 10, 2015
 *      Author: root
 */

#ifndef CPACKETBASE_H_
#define CPACKETBASE_H_
#include "netheader.h"


#include <tins/tins.h>

#define PACKET_TYPE_ARP 1
#define PACKET_TYPE_IP  2
#define PACKET_TYPE_UDP 3
#define PACKET_TYPE_TCP 4

using namespace Tins;

class CPacketBase {
public:
	 enum PacketTYPE {
	            ARP = 0x0001,
	            IP=0x0002,
	            UDP   = 0x0003,
	            TCP = 0x0004,
	        };

	CPacketBase();
	virtual ~CPacketBase();

    bool IniMembers(const u_char * p_sBuf,unsigned int p_nSize);

public:
    PacketTYPE m_nType;  //ARP, UDP
    const u_char * m_sBuf;
    unsigned int m_nBufSize;

    MACADDR m_EtherSrc;
    MACADDR m_EtherDST;
    int m_nARPOP;
    DWORD m_nARPSrcIP;
    DWORD m_nARPDstIP;
    MACADDR m_ARPDstMac;
    MACADDR m_ARPSrcMac;
    DWORD m_nIPSrc;
    DWORD m_nIPDst;
    int m_nUDPSrcPort;
    int m_nUDPDstPort;
    int m_nTCPSrcPort;
    int m_nTCPDstPort;
    DWORD m_nTCPSEQ;
    DWORD m_nTCPACK;

    struct sniff_ethernet *m_pEthernet; /* The ethernet header [1] */
   	EtherARP * m_pARP;
	struct sniff_ip * m_pIP; /* The IP header */
	struct libnet_udp_hdr *m_pUDP;
	struct libnet_tcp_hdr * m_pTCP;
	char * m_sPayload;
	unsigned int m_nPayloadSize;

private:
	const PDU * m_pPDU;

};

#endif /* CPACKETBASE_H_ */
