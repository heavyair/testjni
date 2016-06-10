/*
 * CPacketReader.cpp
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#include "CPacketReader.h"
#include "CThreadWorker.h"

namespace NETCUT_CORE_FUNCTION {

CPacketReader::CPacketReader(){
	// TODO Auto-generated constructor stub

	m_PcapHandle = NULL;

}

CPacketReader::~CPacketReader() {
	// TODO Auto-generated destructor stub
	StopSniff();
	//TRACE("STOP SNIFF DONE\n");
	m_ThreadSniff.WaitThreadExit();
	//TRACE("SNIFF thread DONE\n");
}

void CPacketReader::StartSniff() {

	m_EventStop.ResetEvent();
	m_ThreadSniff.StartThread(threadSniffer,this);
	//m_ThreadPacketWorker.StartThread(threadPacketWorker,this);

}

void CPacketReader::StopSniff() {

	m_EventStop.SetEvent();

	if (m_PcapHandle != NULL)
	{
      pcap_breakloop(m_PcapHandle);

      TRACE("Stopping sniffer\n");

	}


}
/*
bool CPacketReader::IsWorking() {

	return m_EventStop.WaitForEvent(1);
}
*/

void* CPacketReader::threadSniffer(void *para) {
	CPacketReader * ptr = (CPacketReader *) para;
	while(!ptr->m_EventStop.WaitForEvent(1))
	{
	ptr->threadSnifferRun();  //use tins sniffer
	}
	//ptr->threadTinsSnifferRun();  //use tins sniffer
	return NULL;
}

/*
void CPacketReader::threadTinsSnifferRun() {

		SnifferConfiguration config;
		config.set_filter("ip or arp or rarp");
		config.set_buffer_size(SNIFF_BUFFER_SIZE);
		config.set_snap_len(SNAP_LEN);
		m_PSnifferPointer =new Sniffer(m_sDevName, config);
		//Sniffer sniffer(m_sDevName, config);
		pcap_setdirection(m_PSnifferPointer->get_pcap_handle(), PCAP_D_IN);
		//m_PcapHandle=sniffer.get_pcap_handle();
		TRACE("Sniff loop started\n");
		m_EventStop.ResetEvent();
		m_PSnifferPointer->sniff_loop(
				std::bind(&CPacketReader::CallbackGotPdu, this,
						std::placeholders::_1));
		TRACE("Sniff loop finished now\n");

}
*/
void CPacketReader::threadSnifferRun() {



	struct bpf_program filter;



		//bpf_u_int32 netaddr = 0,
		bpf_u_int32 mask = 0;
		bpf_u_int32 net=0;			/* ip */

		m_PcapHandle = pcap_open_live(m_sDevName.c_str(), MAXPACKET_LEN, true,
				1000, this->m_sErrbuf);
		//	m_PcapHandle = pcap_create(this->m_sDevName.c_str(), m_sErrbuf);
		if (m_PcapHandle == NULL) {
			TRACE("Couldn't open device %s: %s\n", m_sDevName.c_str(),
					m_sErrbuf);
		return;
		}

	/*	if (pcap_lookupnet(m_sDevName.c_str(), &net, &mask, m_sErrbuf) == -1) {
			TRACE("Couldn't get netmask for device %s: %s\n",
					m_sDevName.c_str(), m_sErrbuf);
				net = 0;
				mask = 0;
			}
*/
		if (pcap_compile(m_PcapHandle, &filter, "ip or arp or rarp", 1, net)
				== -1) {
			TRACE("ERROR: %s\n", pcap_geterr(m_PcapHandle));
			return;

		}


		if (pcap_setfilter(m_PcapHandle, &filter) == -1) {
			TRACE("ERROR: %s\n", pcap_geterr(m_PcapHandle));
			return;
		}

		pcap_freecode(&filter);
		pcap_setdirection(m_PcapHandle, PCAP_D_IN);
		//	TRACE("Sniff started on %s\n", this->getDevName().c_str());

		//TRACE("\nSniffer started on %s \n",m_sDevName.c_str());
		//m_EventStop.ResetEvent();
		if (pcap_loop(m_PcapHandle, 0, CPacketReader::Got_packet,
				(u_char *) this) < 1) {


			 pcap_close(m_PcapHandle);
			 m_PcapHandle=NULL;

		}




	TRACE("Thread Sniff Close.\n");

}

void CPacketReader::Got_packet(u_char *args,
		const struct pcap_pkthdr *header, const u_char *packet) {

	//TRACE("Having packet \n");

	if (args == NULL)
	{




		return;
	}
	CPacketReader *parent = (CPacketReader *) args;

	parent->Got_packetRun(header, packet);

	return;
}


void CPacketReader::Got_packetRun(const struct pcap_pkthdr *header,
		const u_char *packet) {



		CPacketBase PacketInfo;
		if (PacketInfo.IniMembers(packet, header->caplen))
		{
	//		TRACE("Got packet run \n");

			OnPacket(PacketInfo);
		}

}


/*
bool CPacketReader::CallbackGotPdu(const PDU &pdu) {

	OnPDU(pdu);

	return true;

}

*/




} /* namespace NETCUT_CORE_FUNCTION */
