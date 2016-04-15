/*
 * CIPCMessagePCInfo.h
 *
 *  Created on: Jan 25, 2016
 *      Author: root
 */

#ifndef CIPCMESSAGEPCINFO_H_
#define CIPCMESSAGEPCINFO_H_

#include <CIPCMessage.h>
#include <CIPCBaseTemplate.h>
#include "netheader.h"

namespace NETCUT_CORE_FUNCTION {

struct message_pcinfo {
		int32_t nSize;
		int32_t nType;
		bool bOff;
		bool bDefender;
		bool bAttacker;
		bool bIsGateWay;
		bool bIsMydevivce;

		unsigned char MacBuff[6];
		char sMacStr[EVENT_FIX_MACSTR];
		char sIPs[EVENT_MAX_IPADDRESS];
		int nIPSize;
		char sBrandName[EVENT_MAX_BRANDNAME];
		int nBrandSize;
		char sHostname[EVENT_MAX_HOSTNAME];
		int nHostNameSize;
		int nSpeedLimit;
		DWORD nIPs[12];
		int32_t nIPCount;

	}__attribute__((packed));


class CIPCMessagePCInfo: public CIPCBaseTemplate <CIPCMessagePCInfo,message_pcinfo,IPCMESSAGE_ID_PCINFO>  {
public:
	CIPCMessagePCInfo();
	virtual ~CIPCMessagePCInfo();

	void SetIPs(std::string  p_sIPs);
	void SetBrand(std::string  p_s);
	void SetHostname(std::string  p_s);
	void SetMac(const unsigned char * p_Buf);





};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCMESSAGEPCINFO_H_ */
