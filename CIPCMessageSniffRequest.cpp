/*
 * CIPCMessageSniffRequest.cpp
 *
 *  Created on: Jan 25, 2016
 *      Author: root
 */

#include <CIPCMessageSniffRequest.h>

namespace NETCUT_CORE_FUNCTION {

CIPCMessageSniffRequest::CIPCMessageSniffRequest() {
	// TODO Auto-generated constructor stub

}

CIPCMessageSniffRequest::~CIPCMessageSniffRequest() {
	// TODO Auto-generated destructor stub
}
std::string CIPCMessageSniffRequest::GetDevName()
{

	if(this->m_message.nDevNameSize<=0) return "";

	return std::string(this->m_message.sDevname,this->m_message.nDevNameSize);

}


} /* namespace NETCUT_CORE_FUNCTION */
