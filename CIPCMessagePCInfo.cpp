/*
 * CIPCMessagePCInfo.cpp
 *
 *  Created on: Jan 25, 2016
 *      Author: root
 */

#include <CIPCMessagePCInfo.h>

namespace NETCUT_CORE_FUNCTION {

CIPCMessagePCInfo::CIPCMessagePCInfo() {
	// TODO Auto-generated constructor stub


}
void CIPCMessagePCInfo::SetMac(const unsigned char * p_Buf)
{

	std::string sMacStr=CAddressHelper::BufferMac2str(p_Buf);
	memcpy(m_message.MacBuff, p_Buf, 6);
	memcpy(m_message.sMacStr,sMacStr.c_str(),sMacStr.size()>EVENT_FIX_MACSTR?EVENT_FIX_MACSTR:sMacStr.size());

}
void CIPCMessagePCInfo::SetIPs(std::string p_sIPs) {

	m_message.nIPSize = p_sIPs.size() > EVENT_MAX_IPADDRESS ?
	EVENT_MAX_IPADDRESS :p_sIPs.size();

	memcpy(m_message.sIPs, p_sIPs.c_str(), m_message.nIPSize);

}

void CIPCMessagePCInfo::SetBrand(std::string p_s) {

	m_message.nBrandSize = p_s.size() > EVENT_MAX_BRANDNAME ?
			EVENT_MAX_BRANDNAME :
		p_s.size();

		memcpy(m_message.sBrandName, p_s.c_str(), m_message.nBrandSize);

}

void CIPCMessagePCInfo::SetHostname(std::string p_s) {
	m_message.nHostNameSize= p_s.size() > EVENT_MAX_HOSTNAME ?
			EVENT_MAX_HOSTNAME :
			p_s.size();

			memcpy(m_message.sHostname, p_s.c_str(), m_message.nHostNameSize);


}

void CIPCMessagePCInfo::SetNickname(std::string p_s) {
	m_message.nNickNameSize= p_s.size() > EVENT_MAX_HOSTNAME ?
			EVENT_MAX_HOSTNAME :
			p_s.size();

			memcpy(m_message.sNickName, p_s.c_str(), m_message.nNickNameSize);


}


void CIPCMessagePCInfo::SetSpeedLimit(int p_nSpeedLimit) {

	m_message.nSpeedLimit=p_nSpeedLimit;


}
CIPCMessagePCInfo::~CIPCMessagePCInfo() {
	// TODO Auto-generated destructor stub
}

} /* namespace NETCUT_CORE_FUNCTION */
