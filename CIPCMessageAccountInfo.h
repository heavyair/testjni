/*
 * CIPCMessageAccountInfo.h
 *
 *  Created on: May 27, 2016
 *      Author: root
 */

#ifndef CIPCMESSAGEACCOUNTINFO_H_
#define CIPCMESSAGEACCOUNTINFO_H_
#include "netheader.h"
#include <CIPCMessage.h>
#include <CIPCBaseTemplate.h>
namespace NETCUT_CORE_FUNCTION {

/*NETCUTPROACFILE


ResetDefault value

Read NETCUTPROACFILE ,
if not file, do nothing.
if file and with correct mac, do nothing
if good file,  start thread to update, the thread should update current data after update,
*/
struct message_acinfo {
	    int32_t nSize;
		int32_t nType;
		bool bHasAC;
		char sACName[255];
		int nACNameSize;
		bool bExpired;
		int32_t nExpireTime;//seconds since 1970
		char sMacStr[EVENT_FIX_MACSTR];
	}__attribute__((packed));

class CIPCMessageAccountInfo: public CIPCBaseTemplate <CIPCMessageAccountInfo,message_acinfo,IPCMESSAGE_ID_PRO_ACCOUNT> {
public:
	CIPCMessageAccountInfo();
	virtual ~CIPCMessageAccountInfo();
	void SetValue(bool p_bHasAC,std::string p_sACName,bool p_bExpired,int32_t p_nExpireTime,std::string p_sMACStr);
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCMESSAGEACCOUNTINFO_H_ */
