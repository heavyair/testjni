/*
 * CIPCMessageSniffRequest.h
 *
 *  Created on: Jan 25, 2016
 *      Author: root
 */

#ifndef CIPCMESSAGESNIFFREQUEST_H_
#define CIPCMESSAGESNIFFREQUEST_H_

#include <CIPCMessage.h>
#include <CIPCBaseTemplate.h>

namespace NETCUT_CORE_FUNCTION {
struct message_sniffrequest {
					int32_t nSize;
					int32_t nType;
		            char sDevname[IF_NAMESIZE];
		            int32_t nDevNameSize;
		           } __attribute__((packed));

class CIPCMessageSniffRequest: public CIPCBaseTemplate <CIPCMessageSniffRequest,message_sniffrequest,IPCMESSAGE_ID_SNIFFREQUEST>{
public:
	CIPCMessageSniffRequest();
	virtual ~CIPCMessageSniffRequest();
	std::string GetDevName();


};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCMESSAGESNIFFREQUEST_H_ */
