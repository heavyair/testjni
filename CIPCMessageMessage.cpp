/*
 * CIPCMessageMessage.cpp
 *
 *  Created on: Jan 26, 2016
 *      Author: root
 */

#include <CIPCMessageMessage.h>

namespace NETCUT_CORE_FUNCTION {

CIPCMessageMessage::CIPCMessageMessage() {
	// TODO Auto-generated constructor stub

}

CIPCMessageMessage::~CIPCMessageMessage() {
	// TODO Auto-generated destructor stub
}



void CIPCMessageMessage::SetMessage(std::string p_sMessage)
{
	this->m_message.nMessageSize=p_sMessage.size()>EVENT_MAX_MESSAGESIZE?EVENT_MAX_MESSAGESIZE:p_sMessage.size();
    memcpy(m_message.sMessage,p_sMessage.c_str(),m_message.nMessageSize);

}


void CIPCMessageTypeMessage::SetMessage(int p_nType,std::string p_sMessage)
{
	this->m_message.nMessageSize=p_sMessage.size()>EVENT_MAX_MESSAGESIZE?EVENT_MAX_MESSAGESIZE:p_sMessage.size();
    memcpy(m_message.sMessage,p_sMessage.c_str(),m_message.nMessageSize);
    m_message.nMessageType=p_nType;


}

void CIPCMessageStatus::SetMessage(std::string p_sMessage)
{
	this->m_message.nMessageSize=p_sMessage.size()>EVENT_MAX_MESSAGESIZE?EVENT_MAX_MESSAGESIZE:p_sMessage.size();
    memcpy(m_message.sMessage,p_sMessage.c_str(),m_message.nMessageSize);

}
} /* namespace NETCUT_CORE_FUNCTION */
