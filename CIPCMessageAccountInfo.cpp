/*
 * CIPCMessageAccountInfo.cpp
 *
 *  Created on: May 27, 2016
 *      Author: root
 */

#include <CIPCMessageAccountInfo.h>

namespace NETCUT_CORE_FUNCTION {

CIPCMessageAccountInfo::CIPCMessageAccountInfo() {
	// TODO Auto-generated constructor stub

}

CIPCMessageAccountInfo::~CIPCMessageAccountInfo() {
	// TODO Auto-generated destructor stub
}

void CIPCMessageAccountInfo::SetValue(bool p_bHasAC,std::string p_sACName,bool p_bExpired,int32_t p_nExpireTime,std::string p_sMACStr)
{

	m_message.bHasAC=p_bHasAC;
	m_message.nACNameSize=p_sACName.size()>255?255:p_sACName.size();
	memcpy(m_message.sACName,p_sACName.c_str(),m_message.nACNameSize);
    m_message.bExpired=p_bExpired;
    m_message.nExpireTime=p_nExpireTime;
    memcpy(m_message.sMacStr,p_sMACStr.c_str(),p_sMACStr.size()>EVENT_FIX_MACSTR?EVENT_FIX_MACSTR:p_sMACStr.size());


}

} /* namespace NETCUT_CORE_FUNCTION */
