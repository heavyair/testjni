/*
 * CSniffer.cpp
 *
 *  Created on: Dec 14, 2015
 *      Author: victor
 */

#include "CSniffer.h"

namespace NETCUT_CORE_FUNCTION {

CSniffer::CSniffer() {
	// TODO Auto-generated constructor stub

	this->m_sDevName="";
}

CSniffer::~CSniffer() {
	// TODO Auto-generated destructor stub

}

 void CSniffer::OnArpPacket(const CPacketBase & packet)
 {

 	}
	 void CSniffer::OnDHCPPacket(const CPacketBase & packet)
	 {

	 	}
	 void CSniffer::OnNetBiosPacket(const CPacketBase & packet)
	 {

	 	}
	 void CSniffer::OnMDNSPacket(const CPacketBase & packet)
	 {

	 	}

	 void CSniffer::OnTCPPacket(const CPacketBase & packet)
	 {

	 	}
	 void CSniffer::OnIPPacket(const CPacketBase & packet)
	{

	}
void CSniffer::OnPacket(const CPacketBase & PacketInfo) {

	//TRACE("GOT Packet \n");
			switch (PacketInfo.m_nType) {
			case PACKET_TYPE_IP:
			case PACKET_TYPE_UDP:
			case PACKET_TYPE_TCP: {
				OnIPPacket(PacketInfo);
				if (PacketInfo.PacketTYPE::UDP == PacketInfo.m_nType) {
					if (PacketInfo.m_nUDPDstPort == 67
							|| PacketInfo.m_nUDPSrcPort == 67)
						OnDHCPPacket(PacketInfo);
					if (PacketInfo.m_nUDPSrcPort == 137)
						OnNetBiosPacket(PacketInfo);
					if (PacketInfo.m_nUDPSrcPort == 5353)
						this->OnMDNSPacket(PacketInfo);

				}
				if (PacketInfo.PacketTYPE::TCP == PacketInfo.m_nType) {
					OnTCPPacket(PacketInfo);
				}

				break;
			}
			case PACKET_TYPE_ARP: {
				OnArpPacket(PacketInfo);

				break;
			}
			default:
				break;
			}
}

void  CSniffer::SetDeviceName(string p_sName) {
	// TODO Auto-generated constructor stub

	this->m_sDevName=p_sName;
}
/*
void CSniffer::OnPDU(const PDU &pdu)
{
if(pdu.find_pdu<IP>()!=NULL)
	{
		TRACE("New IP packet\n");
	}
	if(pdu.find_pdu<ARP>()!=NULL)
		{
			TRACE("New ARP packet\n");
			OnARP(pdu);
		}
	if(pdu.find_pdu<BootP>()!=NULL)
			{
				TRACE("New BOOTP packet\n");
			}
	if(pdu.find_pdu<DHCP>()!=NULL)
				{
					TRACE("New DHCP packet\n");
				}

}

*/
 /* namespace NETCUT_CORE_FUNCTION */

}

