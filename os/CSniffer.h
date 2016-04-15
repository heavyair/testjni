/*
 * CSniffer.h
 *
 *  Created on: Dec 14, 2015
 *      Author: victor
 */

#ifndef CSNIFFER_H_
#define CSNIFFER_H_

#include "CPacketBase.h"

namespace NETCUT_CORE_FUNCTION {
using namespace std;

class CSniffer {
public:
	CSniffer();
	virtual ~CSniffer();
	void SetDeviceName(string p_sName);
	virtual void StartSniff()=0;
	virtual void StopSniff()=0;
	virtual void OnPacket(const CPacketBase & packet);
	virtual void OnArpPacket(const CPacketBase & packet);
	virtual void OnDHCPPacket(const CPacketBase & packet);
	virtual void OnNetBiosPacket(const CPacketBase & packet);
	virtual void OnMDNSPacket(const CPacketBase & packet);

	virtual void OnTCPPacket(const CPacketBase & packet);
	virtual void OnIPPacket(const CPacketBase & packet);
	// virtual void OnPDU(const PDU &pdu);
	//virtual void OnARP(const PDU &arp)=0;

protected:
	string m_sDevName;

};
/* namespace NETCUT_CORE_FUNCTION */
}

#endif /* CSNIFFER_H_ */
