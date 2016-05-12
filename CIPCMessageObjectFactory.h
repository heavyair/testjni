/*
 * CIPCMessageObjectFactory.h
 *
 *  Created on: Jan 13, 2016
 *      Author: root
 */

#ifndef CIPCMESSAGEOBJECTFACTORY_H_
#define CIPCMESSAGEOBJECTFACTORY_H_

#include <CIPCMessage.h>
#include <vector>
#include <map>
#include <CIPCMessageDeviceInfo.h>
#include <CIPCMessageSniffRequest.h>
#include <CIPCMessagePCInfo.h>
#include <CIPCMessageMessage.h>
#include <CGrounded.h>
#include <CMyLock.h>


namespace NETCUT_CORE_FUNCTION {


/*

struct message_setspeed {
							int32_t nSize;
							int32_t nType;
							unsigned char MacBuff[6];
						    int32_t  nSpeedLimit;
						    DWORD nIPs[12];
						    int32_t nIPCount;
				           } __attribute__((packed));


class CIPCMessageSetSpeed: public CIPCBaseTemplate <CIPCMessageSetSpeed,message_setspeed,IPCMESSAGE_ID_SETSPEED> {};

*/

struct message_id_value {
	int32_t nSize;
	int32_t nType;
	int32_t nID;
	int32_t nIDValue;
   } __attribute__((packed));


class CIPCMessageIDValue: public CIPCBaseTemplate <CIPCMessageIDValue,message_id_value,IPCMESSAGE_ID_IDVALUE>{};


struct message_groundsetting {
						int32_t nSize;
		    	  	  	int32_t nType;
			            unsigned char MacBuff[6];
			            char sMacStr[EVENT_FIX_MACSTR];
			         //   bool bIsGrounded;
			            GroundUnit gDaily;
			            GroundUnit gOneTime;
			            int32_t    nLeftSeconds;
			        } __attribute__((packed));


class CIPCMessageGroundSetting: public CIPCBaseTemplate <CIPCMessageGroundSetting,message_groundsetting,IPCMESSAGE_ID_GROUNDSETTING>{};





/*
struct message_CutOffMethod {
	int32_t nSize;
	int32_t nType;
    int32_t nCutoffMethod;  //0, cut to both end, 1, cut to target pc, 2, cut to gateway
   } __attribute__((packed));


class CIPCMessageCutOffMethod: public CIPCBaseTemplate <CIPCMessageCutOffMethod,message_CutOffMethod,IPCMESSAGE_ID_CUTOFFMETHOD> {};
*/

struct message_onoff {
							int32_t nSize;
							int32_t nType;
							int32_t nMacOnoffType;
							unsigned char MacBuff[6];
							bool bOff;   //1 off, 0 Online
				           } __attribute__((packed));

class CIPCMacOnOff: public CIPCBaseTemplate <CIPCMacOnOff,message_onoff,IPCMESSAGE_ID_MAC_ONOFF> {};



struct message_MAC_INT_Value {
							int32_t nSize;
							int32_t nType;
							int32_t nMac_INT_Type;
							unsigned char MacBuff[6];
							int32_t nMac_INT_Value;   //1 off, 0 Online
				           } __attribute__((packed));

class CIPCMessageMac_INT_Value: public CIPCBaseTemplate <CIPCMessageMac_INT_Value,message_MAC_INT_Value,IPCMESSAGE_ID_MAC_INT_VALUE> {};


struct message_gatewayset {
							int32_t nSize;
							int32_t nType;
							unsigned char MacBuff[6];
							bool bSet;   //1 be gateway, 0, remove as gateway
				           } __attribute__((packed));


class CIPCGatewayOnOff: public CIPCBaseTemplate <CIPCGatewayOnOff,message_gatewayset,IPCMESSAGE_ID_SETGATEWAY> {};



struct message_setname {
							int32_t nSize;
							int32_t nType;
							unsigned char MacBuff[6];
						    char sName[255];
						    int32_t nSNameSize;
				           } __attribute__((packed));


class CIPCMessageSetName: public CIPCBaseTemplate <CIPCMessageSetName,message_setname,IPCMESSAGE_ID_SETNAME> {};


//typedef  CIPCMessageIDValue CIPCMessageIntValue;

class CIPCMessageObjectFactory {
public:

	CIPCMessageObjectFactory();
	virtual ~CIPCMessageObjectFactory();

	static CIPCMessageObjectFactory * GetInstance();
	static CIPCMessage * GetMessage(int sock);
	static CIPCMessage * Get(int32_t p_nTypeID);
	static void Free(CIPCMessage * p_IPCMessage);
	static void RegisterMessagesType();

	static std::map<int32_t,CIPCMessage *> m_MessageType;
	static std::map<int32_t,std::vector<CIPCMessage *>> m_MessageStorage;
protected:
	static CMyLock m_lock; /* lock */

};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCMESSAGEOBJECTFACTORY_H_ */
