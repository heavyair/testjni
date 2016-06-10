/*
 * CIPCMessage.h
 *
 *  Created on: Jan 12, 2016
 *      Author: root
 */

#ifndef CIPCMESSAGE_H_
#define CIPCMESSAGE_H_


#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <string>
#include "CAddressHelper.h"
#include "sys/socket.h"

#include <net/if.h>

namespace NETCUT_CORE_FUNCTION {


#define IPCMESSAGE_ID_PCINFO 1
#define IPCMESSAGE_ID_SNIFFREQUEST 2
//#define IPCMESSAGE_ID_CUTOFFMETHOD 3
#define IPCMESSAGE_ID_DEVICINFO 4
#define IPCMESSAGE_ID_MESSAGE 5
#define IPCMESSAGE_ID_IDVALUE 6  //all on off , int value can pass through this
#define IPCMESSAGE_ID_GROUNDSETTING 7
#define IPCMESSAGE_ID_MAC_ONOFF 8
#define IPCMESSAGE_ID_SETGATEWAY 9
#define IPCMESSAGE_ID_SETNAME 10
#define IPCMESSAGE_ID_STATUS 11
//#define IPCMESSAGE_ID_SETSPEED 12
#define IPCMESSAGE_ID_MAC_INT_VALUE 12
#define IPCMESSAGE_ID_MESSAGE_TYPE_VALUE 13
#define IPCMESSAGE_ID_PRO_ACCOUNT 14
#define IPCMESSAGE_ID_PRO_ACCOUNT_LOGIN 15

#define IPCMESSAGE_ID_MESSAGE_TYPE_SEARCHNAME 1

#define IPCMESSAGE_MAC_ONOFF_PC 1
#define IPCMESSAGE_MAC_ONOFF_GATEWAY 2

#define IPCMESSAGE_ID_MAC_INT_SETSPEED 1
#define IPCMESSAGE_ID_MAC_INT_OFFLINE 2
#define IPCMESSAGE_ID_MAC_INT_CUTOFF 3

#define IPCMESSAGE_ID_INT_SETDEFENDER 1
#define IPCMESSAGE_ID_INT_SCANNETWORK 2
#define IPCMESSAGE_ID_INT_PID 3
#define IPCMESSAGE_ID_INT_NETWORKDOWN 4
#define IPCMESSAGE_ID_INT_CUTOFFMETHOD 5
#define IPCMESSAGE_ID_INT_FAKEMAC 6
#define IPCMESSAGE_ID_INT_REGREQUIREMENT 7
#define IPCMESSAGE_ID_INT_SLOWSCAN 8
#define IPCMESSAGE_ID_INT_RESETNETWORKNODES 9
#define IPCMESSAGE_ID_INT_PROUSERFLAG 10
#define IPCMESSAGE_ID_INT_ISROOT 11
#define IPCMESSAGE_ID_INT_HASNETCARD 12
#define IPCMESSAGE_ID_INT_SPEEDLIMIT_ALL 13
#define IPCMESSAGE_ID_INT_ISPROACCOUNT 14
#define IPCMESSAGE_ID_INT_LOGINFAILED 15
#define IPCMESSAGE_ID_INT_RELOGIN 16
#define IPCMESSAGE_ID_INT_SCLIENTSCAN 17


#define NETCUTTYPE_CUTOFFMETHOD_BOTH 0
#define NETCUTTYPE_CUTOFFMETHOD_GATE 1
#define NETCUTTYPE_CUTOFFMETHOD_PC 2



/*
 *  Each message have a member , start with type ID, then length, then members.
 *  Writer will write all structure into network
 *  Read will read the length, then try to read the packet according to length, if read length < defined length, if defined length != known length return false
 *
 */
class CIPCMessage {
public:
	CIPCMessage();
	virtual ~CIPCMessage();
	virtual bool Read(int s);
	virtual bool write(int s);
	virtual CIPCMessage * Create();
	const	virtual int32_t TypeID() const;
	virtual void Reset()=0;

	char * m_pBufferMessage;
    int32_t m_nMessageType;
	int32_t m_nMessageSize;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCMESSAGE_H_ */
