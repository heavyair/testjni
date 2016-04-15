/*
 * CPacketSender.cpp
 *
 *  Created on: Dec 21, 2015
 *      Author: victor
 */

#include <CPacketSender.h>
#include <CNetcutTool.h>

#include "CAddressHelper.h"
using namespace std;
namespace NETCUT_CORE_FUNCTION {

CPacketSender::CPacketSender() {
	// TODO Auto-generated constructor stub

}

CPacketSender::~CPacketSender() {
	// TODO Auto-generated destructor stub
	//TRACE("Packet sender finish\n");
}

libnet_t * CPacketSender::InitSendAdapter() {

	libnet_t * handle = NULL;
	char sErrbuf[256];

//	TRACE("libnet_start \n");
	handle = libnet_init(LIBNET_LINK_ADV, this->m_sDevName.c_str(), sErrbuf);
	if (handle == NULL) {
		TRACE("libnet_init err!: %s\n", sErrbuf);

	}
	return handle;
}

bool CPacketSender::sendTCP(const u_char * p_sEtherSrcMac, const u_char *p_sEtherDstMac,u_int p_nSaddr, u_int p_nDaddr,unsigned short int p_nSport,unsigned short int p_nDport,unsigned int p_nSeq,unsigned int p_nAck,u_int8_t p_nConBits,unsigned char * p_Data, unsigned int p_nDataSize)
{

//TRACE("sending packet src %s dst %s seq %u ack %u\n",CAddressHelper::IntIP2str(p_nSaddr).c_str(),CAddressHelper::IntIP2str(p_nDaddr).c_str(),p_nSeq,p_nAck);

	bool bRet = false;
	libnet_t * LibnetHandle = this->InitSendAdapter();
	do {

		if (LibnetHandle == NULL) {
	//		TRACE("Libnet Init error\n");
			break;

		}

	 int tcp = libnet_build_tcp(p_nSport, // source port
			 p_nDport,  // destination port
			 p_nSeq,               // sequence number
			 p_nAck,              // acknowledgement number
			 p_nConBits,                  // control bits
			 TCP_WINDOW_SIGN_ID,                   // Advertised window size
	 0,                       // checksum
	 0,                       // urgent pointer
	 LIBNET_TCP_H+p_nDataSize,       // length ofprotocol header
	 p_Data,           // data
	 p_nDataSize,         // payload length
	 LibnetHandle, 0);

	 if (tcp == -1) {
	 TRACE("Unable to build TCP header.\n");
	 break;
	 }


	 int ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H + p_nDataSize, // length
	 0x10,        // TOS
	 libnet_get_prand(LIBNET_PRu16),   // IP ID
	 0,   // IP Frag
	 128,  // TTL
	 IPPROTO_TCP, // protocol
	 0,   // checksum
	 p_nSaddr,        // src ip
	 p_nDaddr,        // destination ip
	 NULL,        // payload
	 0,   // payload size
	 LibnetHandle,    // libnet handle
	 0);  // libnet id

	 if (ip == -1) {
	 TRACE("Unable to build IP header.\n");
	 break;
	 }

	 int t = libnet_build_ethernet((uint8_t *) p_sEtherDstMac,
					(uint8_t *) p_sEtherSrcMac, ETHERTYPE_IP, NULL, 0, LibnetHandle, 0);

	 if (t == -1) {
	 TRACE("libnet_build_ethernet err!\n");
	 break;

	 }

	 int c = libnet_write(LibnetHandle);
	 if (c == -1) {
	 TRACE("Unable to Write \n");
	 break;
	 }
	 bRet=true;
	}
	while(false);

	ClearSendAdapter(LibnetHandle);
	return bRet;

}
bool CPacketSender::SendNetbiosQuery(const MACADDR  p_TargetMac, DWORD p_nsIP,
		DWORD p_ndIP,unsigned short int p_nSeq) {


	libnet_t * LibnetHandle = this->InitSendAdapter();


	if (LibnetHandle == NULL) {
			return false;

	}


	bool bRet = true;

	do {
		//	u_char enet_dst[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


		struct NMBpacket buff;
		int sendlen;

		CNbtQuery::fill_namerequest(&buff, &sendlen, p_nSeq);

		// wrap it
		int udp = libnet_build_udp(1024,  // source port
				137,  // destination port
				LIBNET_UDP_H + sendlen,     // packet size
				0,   // checksum
				(u_char *) &buff,        // payload
				sendlen,   // payload size
				LibnetHandle,    // libnet handle
				0);  // libnet id

		if (udp == -1) {
			//	TRACE("libnet_build err!\n");

			bRet = false;
			break;

		}
		// hook me up with some ipv4
		int ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + sendlen, // length
		0x10,        // TOS
				0,   // IP ID
				0,   // IP Frag
				16,  // TTL
				IPPROTO_UDP, // protocol
				0,   // checksum
				p_nsIP,        // src ip
				p_ndIP,        // destination ip
				NULL,        // payload
				0,   // payload size
				LibnetHandle,    // libnet handle
				0);  // libnet id

		if (ip == -1) {
			//	TRACE("libnet_build err!\n");

			bRet = false;
			break;

		}
		// we can just autobuild since we arent doing anything tricky
		int t = libnet_autobuild_ethernet(p_TargetMac.data(), // ethernet destination
				ETHERTYPE_IP, // protocol type
				LibnetHandle);        // libnet handle

		if (t == -1) {
			TRACE("libnet_build_ethernet err!\n");

			bRet = false;
			break;

		}
		/*********send packets*******************************/

		int res = libnet_write(LibnetHandle);

		if (res == -1) {

			TRACE("Libnet Write err!\n");
			bRet = false;
			break;

		}

	} while (false);

	ClearSendAdapter(LibnetHandle);


	return bRet;

}


bool CPacketSender::SendMDNSQuery(std::string p_sQuery, int p_nType,DWORD p_nMyIP) {



	bool bRet = true;
	libnet_t * LibnetHandle = this->InitSendAdapter();


	if (LibnetHandle == NULL) {
			return false;

	}

	u_short type = LIBNET_UDP_DNSV4_H;

	do {

		char payload[1024];
		//string sQuery = "_device-info._tcp.local";
		//string sQuery="_services._dns-sd._udp.local";

		//string sQuery=CAddressHelper::GetDNS_inaddr(p_ndIP);
		u_short payload_s = snprintf(payload, sizeof payload, "%c%s%c%c%c%c%c",
				(char) (p_sQuery.size() & 0xff), p_sQuery.c_str(), 0x00, 0x00,
				0x01, 0x00, 0x01);
		QUESTION *querytype = (QUESTION*) (payload + 1 + p_sQuery.size() + 1);
		querytype->qclass = htons(1);
		querytype->qtype = htons(p_nType);
		/*
		 u_short payload_s = snprintf(payload, sizeof payload, "%s%c%c%c%c%c",
		 sQuery.c_str(), 0x00, 0x00, 0x01, 0x00, 0x01);

		 QUESTION *querytype=(QUESTION*)(payload+sQuery.size()+1);
		 querytype->qclass=htons(1);
		 querytype->qtype=htons(T_TXT);

		 */


		int dns = libnet_build_dnsv4(LIBNET_UDP_DNSV4_H, /* TCP or UDP */
		0x0000, /* id */
		0x0100, /* request */
		1, /* num_q */
		0, /* num_anws_rr */
		0, /* num_auth_rr */
		0, /* num_addi_rr */
		(uint8_t *) payload, payload_s, LibnetHandle, 0);
		if (dns == -1) {
			//	TRACE("Can't build DNS packet: %s\n",	libnet_geterror(LibnetHandle));
			bRet = false;
			break;
		}

		// wrap it
		int udp = libnet_build_udp(5353,  // source port
				5353,  // destination port
				LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + payload_s,    // packet size
				0,   // checksum
				NULL,        // payload
				0,   // payload size
				LibnetHandle,    // libnet handle
				0);  // libnet id

		if (udp == -1) {
			//	TRACE("libnet_build err!\n");

			bRet = false;
			break;

		}

		// hook me up with some ipv4
		int ip = libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_UDP_H + type + payload_s,/* length */
				0, /* TOS */
				242, /* IP ID */
				0, /* IP Frag */
				64, /* TTL */
				IPPROTO_UDP, /* protocol */
				0, /* checksum */
				p_nMyIP, /* source IP */
				CAddressHelper::StrIP2Int("224.0.0.251"), /* destination IP */
				NULL, /* payload */
				0, /* payload size */
				LibnetHandle, /* libnet handle */
				0); /* libnet id */

		if (ip == -1) {
			//	TRACE("libnet_build err!\n");

			bRet = false;
			break;

		}
		u_char buf[6];
		CAddressHelper::GetMCastMac(CAddressHelper::StrIP2Int("224.0.0.251"),
				buf);
		// we can just autobuild since we arent doing anything tricky
		int t = libnet_autobuild_ethernet(buf,     // ethernet destination
				ETHERTYPE_IP, // protocol type
				LibnetHandle);        // libnet handle

		if (t == -1) {
			TRACE("libnet_build_ethernet err!\n");

			bRet = false;
			break;

		}
		/*********send packets*******************************/

		int res = libnet_write(LibnetHandle);

		if (res == -1) {

			TRACE("Libnet Write err!\n");
			bRet = false;
			break;

		}

	} while (false);

	ClearSendAdapter(LibnetHandle);


	return bRet;

}

void CPacketSender::ClearSendAdapter(libnet_t * p_LibnetHandle) {

	if (p_LibnetHandle != NULL) {

		libnet_clear_packet(p_LibnetHandle);

		libnet_destroy(p_LibnetHandle);

	}

}

bool CPacketSender::sendArp(const DWORD &p_DstIP, const DWORD &p_SrcIp,
		const u_char *p_sDstMac, const u_char *p_sSrcMac,
		const u_char *p_sEtherDstMac, const u_char * p_sEtherSrcMac,
		const uint16_t p_nRequesttype) {


	bool bRet = true;
	libnet_t * LibnetHandle = this->InitSendAdapter();
	do {

		if (LibnetHandle == NULL) {
	//		TRACE("Libnet Init error\n");
			bRet = false;
			break;

		}



		const u_char *EtherDsc = p_sEtherDstMac;
		const u_char *EtherSrc = p_sEtherSrcMac;
		const u_char *ArpDstMac = p_sDstMac;
		const u_char *ArpSrcMac = p_sSrcMac;

		libnet_ptag_t p_tag;

		p_tag = libnet_autobuild_arp(p_nRequesttype, (uint8_t *) ArpSrcMac,
				(uint8_t *) &p_SrcIp, (uint8_t *) ArpDstMac,
				(uint8_t*) &p_DstIP, LibnetHandle);

		if (p_tag == -1) {
			TRACE("libnet_build_arp err!\n");

			bRet = false;
			break;

		}

		//libnet_build_ethernet(const uint8_t *dst, const uint8_t *src, uint16_t type,  const uint8_t* payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

		/***********build ethernet packet header*************/
		p_tag = libnet_build_ethernet((uint8_t *) EtherDsc,
				(uint8_t *) EtherSrc, ETHERTYPE_ARP, NULL, 0, LibnetHandle, 0);
		if (p_tag == -1) {
			TRACE("libnet_build_ethernet err!\n");

			bRet = false;
			break;

		}
		/*********send packets*******************************/

		int res = libnet_write(LibnetHandle);

		if (res == -1) {

			TRACE("Libnet Write err!\n");
			bRet = false;
			break;

		}

	} while (false);

	if (LibnetHandle != NULL) {
		libnet_clear_packet(LibnetHandle);

		libnet_destroy(LibnetHandle);
	}

	return bRet;

	/*********over and destroy**************************/

}
} /* namespace NETCUT_CORE_FUNCTION */
