/*
 * CPacketSender.h
 *
 *  Created on: Dec 21, 2015
 *      Author: victor
 */

#ifndef OS_LINUX_CPACKETSENDER_H_
#define OS_LINUX_CPACKETSENDER_H_

#include <CPacketSenderBase.h>

#include "netheader.h"
#define TCP_WINDOW_SIGN_ID 29381
namespace NETCUT_CORE_FUNCTION {

class CPacketSender: public CPacketSenderBase {
public:
	CPacketSender();
	virtual ~CPacketSender();

	virtual bool sendArp(const DWORD &p_DstIP, const DWORD &p_SrcIp,
			const u_char *p_sDstMac, const u_char *p_sSrcMac,
			const u_char *p_sEtherDstMac, const u_char * p_sEtherSrcMac,
			const uint16_t p_nRequesttype);

	virtual bool sendTCP(const u_char * p_sEtherSrcMac, const u_char *p_sEtherDstMac,u_int p_nSaddr, u_int p_nDaddr,unsigned short int p_nSport,unsigned short int p_nDport,unsigned int p_nSeq,unsigned int p_nAck,u_int8_t p_nConBits,unsigned char * p_Data, unsigned int p_nDataSize);

	virtual bool SendNetbiosQuery(const MACADDR  p_TargetMac, DWORD p_nsIP,
			DWORD p_ndIP,unsigned short int p_nSeq);

	bool SendMDNSQuery(std::string p_sQuery, int p_nType,DWORD  p_nMyIP);


protected:
	libnet_t * InitSendAdapter();
	void ClearSendAdapter(libnet_t * p_LibnetHandle);

};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_CPACKETSENDER_H_ */
