/*
 * CIPCMessageMessage.h
 *
 *  Created on: Jan 26, 2016
 *      Author: root
 */

#ifndef CIPCMESSAGEMESSAGE_H_
#define CIPCMESSAGEMESSAGE_H_

#include <CIPCMessage.h>
#include <CIPCBaseTemplate.h>

namespace NETCUT_CORE_FUNCTION {

struct message_message {
					int32_t nSize;
	    	  	  	int32_t nType;
	    	  	  	int32_t nMessageSize;
		            char sMessage[EVENT_MAX_MESSAGESIZE];

		        } __attribute__((packed));


class CIPCMessageMessage: public CIPCBaseTemplate <CIPCMessageMessage,message_message,IPCMESSAGE_ID_MESSAGE> {
public:
	CIPCMessageMessage();
	virtual ~CIPCMessageMessage();
	void SetMessage(std::string p_sMessage);
};


struct message_Type_message {
					int32_t nSize;
	    	  	  	int32_t nType;
	    	  	  	int32_t nMessageType;
	    	  	  	int32_t nMessageSize;
		            char sMessage[EVENT_MAX_MESSAGESIZE];

		        } __attribute__((packed));


class CIPCMessageTypeMessage: public CIPCBaseTemplate <CIPCMessageTypeMessage,message_Type_message,IPCMESSAGE_ID_MESSAGE_TYPE_VALUE> {
public:

	void SetMessage(int p_nType,std::string p_sMessage);
};





class CIPCMessageStatus: public CIPCBaseTemplate <CIPCMessageStatus,message_message,IPCMESSAGE_ID_STATUS> {
public:

	void SetMessage(std::string p_sMessage);
};


} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCMESSAGEMESSAGE_H_ */
