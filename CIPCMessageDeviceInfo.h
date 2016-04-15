/*
 * CIPCMessageDeviceInfo.h
 *
 *  Created on: Jan 13, 2016
 *      Author: root
 */

#ifndef CIPCMESSAGEDEVICEINFO_H_
#define CIPCMESSAGEDEVICEINFO_H_

#include <CIPCMessage.h>
#include <CIPCBaseTemplate.h>

namespace NETCUT_CORE_FUNCTION {

struct message_deviceinfo {
			int32_t nSize;
	  	  	int32_t nType;
            char sDevname[IF_NAMESIZE];
            int32_t nDevNameSize;
            unsigned char MacBuff[6];
            char sDevMacStr[EVENT_FIX_MACSTR];
            int32_t  nIPCount;
            int32_t nIPs[32];
            char sIPs[EVENT_MAX_IPADDRESS];
            int32_t nIPSize;
            int32_t nGateIP;
            int32_t nMask;
            bool bUp;
            bool bMonitorOn;
        } __attribute__((packed));

class CIPCMessageDeviceInfo:  public CIPCBaseTemplate <CIPCMessageDeviceInfo,message_deviceinfo,IPCMESSAGE_ID_DEVICINFO>{

public:

	CIPCMessageDeviceInfo();
	virtual ~CIPCMessageDeviceInfo();





	//virtual int32_t TypeID();
	void SetRoute(int32_t p_nGateIP);
	void SetMac(unsigned char * p_sBuf);
    void AddIP(int32_t p_nIP);
    void SetMask(int32_t p_nMask);
    void ResetIP();
    void SetDevName(std::string p_sDevName);
    void SetMonitor(bool p_bOn);
    void SetUpFlag(bool p_bUp);
	std::string GetDevName();

public:
 //     std::string m_sDevName;


	   	 std::map<int32_t,int32_t> m_IPMap;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCMESSAGEDEVICEINFO_H_ */
