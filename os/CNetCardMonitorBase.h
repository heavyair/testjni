/*
 * CNetCardMonitorBase.h
 *
 *  Created on: Jan 4, 2016
 *      Author: root
 */

#ifndef OS_CNETCARDMONITORBASE_H_
#define OS_CNETCARDMONITORBASE_H_
#include <string>
#include <CIPCMessageDeviceInfo.h>
#include <map>
namespace NETCUT_CORE_FUNCTION {

class CNetCardMonitorBase {
public:
	CNetCardMonitorBase();
	virtual ~CNetCardMonitorBase();

	virtual void OnNetCardNewAdd(std::string p_sNetcardName,u_int p_nIP,u_int p_nMask)=0;
	virtual void OnNetCardNewGate(std::string p_sNetcardName,u_int p_nGate)=0;
	virtual void OnNetCardNewLink(bool p_bUp, std::string p_sNetcardName,u_char *p_pMac)=0;

};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_CNETCARDMONITORBASE_H_ */
