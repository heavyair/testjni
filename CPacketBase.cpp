/*
 * CPacketBase.cpp
 *
 *  Created on: Mar 10, 2015
 *      Author: root
 */

#include "CPacketBase.h"
#include "CAddressHelper.h"
CPacketBase::CPacketBase() {
	// TODO Auto-generated constructor stub
	m_sBuf = NULL;
}

CPacketBase::~CPacketBase() {
	// TODO Auto-generated destructor stub
	/*if (m_sBuf != NULL) {
		delete []m_sBuf;
		m_sBuf = NULL;
	}
	*/

}

bool CPacketBase::IniMembers(const u_char * p_sBuf,unsigned int p_nSize) {
	/*if (m_sBuf != NULL)
		delete []m_sBuf;

	m_nPayloadSize=0;
	this->m_sBuf = new unsigned char[p_nSize];
	memcpy(m_sBuf, p_sBuf, p_nSize);
	this->m_nBufSize = p_nSize;
*/
	DWORD n=*p_sBuf;
	m_sBuf=p_sBuf;
	m_nBufSize=p_nSize;

	int size_ip;

	m_pEthernet = (struct sniff_ethernet*) (m_sBuf);

	this->m_EtherSrc = CAddressHelper::MacBuffer2Array(
			m_pEthernet->ether_shost);
	this->m_EtherDST = CAddressHelper::MacBuffer2Array(
			m_pEthernet->ether_dhost);

	switch (ntohs(m_pEthernet->ether_type)) {
	case ETHERNET_TYPE_IP: {
		m_pIP = (struct sniff_ip*) (m_sBuf + SIZE_ETHERNET);
		size_ip = IP_HL(m_pIP) * 4;
		if (size_ip < 20) {
			return false;
		}
		this->m_nType = this->PacketTYPE::IP;
		this->m_nIPDst = m_pIP->ip_dst.s_addr;
		this->m_nIPSrc = m_pIP->ip_src.s_addr;
		switch (m_pIP->ip_p) {
		case IPPROTO_TCP:
		{
			m_pTCP = (libnet_tcp_hdr *) ((u_char*) m_pIP + size_ip);
			if (p_nSize < (SIZE_ETHERNET + size_ip + sizeof(libnet_tcp_hdr)))
							return false;
			  this->m_nType = this->PacketTYPE::TCP;
			  m_nTCPSrcPort=ntohs(m_pTCP->th_sport);
			  m_nTCPDstPort=ntohs(m_pTCP->th_dport);
			  m_nTCPSEQ=ntohl(m_pTCP->th_seq);
			  m_nTCPACK=ntohl(m_pTCP->th_ack);

			break;
		}
		case IPPROTO_UDP:
			//	TRACE("   Protocol: UDP\n");

			m_pUDP = (libnet_udp_hdr *) ((u_char*) m_pIP + size_ip);
			if (p_nSize < (SIZE_ETHERNET + size_ip + sizeof(libnet_udp_hdr)))
				return false;
			this->m_nType = this->PacketTYPE::UDP;
			this->m_nUDPDstPort = ntohs(m_pUDP->uh_dport);
			this->m_nUDPSrcPort = ntohs(m_pUDP->uh_sport);

			this->m_nPayloadSize = ntohs(m_pIP->ip_len) - size_ip - sizeof(libnet_udp_hdr);

		    this->m_sPayload = (char *) ((char  *) m_pUDP + sizeof(libnet_udp_hdr));

			break;
		case IPPROTO_ICMP:

			break;
		case IPPROTO_IP:

			break;
		default:

			break;
		}
		break;
	}

	case ETHERNET_TYPE_ARP:
	case ETHERNET_TYPE_REVARP: {
		if ((p_nSize - ETHERNET_HEADER_LEN) < sizeof(EtherARP))
			return false;
		this->m_nType = this->PacketTYPE::ARP;
		m_pARP = (EtherARP *) (m_sBuf + ETHERNET_HEADER_LEN);
		this->m_nARPOP = ntohs(m_pARP->ea_hdr.ar_op);
		this->m_ARPDstMac = CAddressHelper::MacBuffer2Array(m_pARP->arp_tha);
		this->m_ARPSrcMac = CAddressHelper::MacBuffer2Array(m_pARP->arp_sha);
		this->m_nARPDstIP = CAddressHelper::BufferIP2Int(
				(u_char *) m_pARP->arp_tpa);
		this->m_nARPSrcIP = CAddressHelper::BufferIP2Int(
				(u_char *) m_pARP->arp_spa);

		break;
	}
	default:
		return false;
		break;
	}
	return true;
}
