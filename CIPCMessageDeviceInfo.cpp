/*
 * CIPCMessageDeviceInfo.cpp
 *
 *  Created on: Jan 13, 2016
 *      Author: root
 */

#include <CIPCMessageDeviceInfo.h>


namespace NETCUT_CORE_FUNCTION {

CIPCMessageDeviceInfo::CIPCMessageDeviceInfo() {
	// TODO Auto-generated constructor stub

	//CIPCBaseTemplate <CIPCMessageDeviceInfo,message_deviceinfo,IPCMESSAGE_ID_DEVICINFO>::CIPCBaseTemplate();


}

CIPCMessageDeviceInfo::~CIPCMessageDeviceInfo() {
	// TODO Auto-generated destructor stub
}


void CIPCMessageDeviceInfo::SetRoute(int32_t p_nGateIP) {

	this->m_message.nGateIP=p_nGateIP;

}

void CIPCMessageDeviceInfo::SetMac(unsigned char * p_sBuf) {

     memcpy(this->m_message.MacBuff,p_sBuf,6);
     std::string s=CAddressHelper::BufferMac2str(p_sBuf);
     memcpy(this->m_message.sDevMacStr,s.c_str(),s.size()>EVENT_FIX_MACSTR?EVENT_FIX_MACSTR:s.size());
}

void CIPCMessageDeviceInfo::SetMask(int32_t p_nMask)
{
	m_message.nMask=p_nMask;

}
void CIPCMessageDeviceInfo::AddIP(int32_t p_nIP) {

	if(m_IPMap.find(p_nIP)!=m_IPMap.end()) return;

	m_message.nIPs[m_message.nIPCount++]=p_nIP;
	m_IPMap[p_nIP]=p_nIP;

	string p_sIPs="";
	  for(int i=0;i<m_message.nIPCount;i++)
			        	   {
			        			in_addr in;
			        			in.s_addr = m_message.nIPs[i];
			        			p_sIPs+=(char *) inet_ntoa(in);
			        			p_sIPs+=" ";
			        	   }

	  p_sIPs.pop_back();

	m_message.nIPSize = p_sIPs.size() > EVENT_MAX_IPADDRESS ?
		EVENT_MAX_IPADDRESS :p_sIPs.size();

	memcpy(m_message.sIPs, p_sIPs.c_str(), m_message.nIPSize);


}
void CIPCMessageDeviceInfo::ResetIP() {

	m_message.nIPCount=0;
	m_IPMap.clear();
}

void CIPCMessageDeviceInfo::SetDevName(std::string p_sDevName) {

//	TRACE("size of dev %d\n",p_sDevName.size());
//	p_sDevName="lo";
	//message sbuff;
   // memcpy(sbuff.dev.sDevname,p_sDevName.c_str(),p_sDevName.size()>IF_NAMESIZE?IF_NAMESIZE:p_sDevName.size());
	m_message.nDevNameSize=p_sDevName.size()>IF_NAMESIZE?IF_NAMESIZE:p_sDevName.size();
    memcpy(m_message.sDevname,p_sDevName.c_str(),m_message.nDevNameSize);
    //m_sDevName=p_sDevName;

}

std::string CIPCMessageDeviceInfo::GetDevName()
{

	if(this->m_message.nDevNameSize<=0) return "";

	return std::string(this->m_message.sDevname,this->m_message.nDevNameSize);

}

void CIPCMessageDeviceInfo::SetUpFlag(bool p_bUp)
{
	 m_message.bUp=p_bUp;
}
void CIPCMessageDeviceInfo::SetMonitor(bool p_bOn) {

	m_message.bMonitorOn=p_bOn;

}
/*

CIPCMessage * CIPCMessageDeviceInfo::Create() {

	CIPCMessageDeviceInfo *newMessage = new CIPCMessageDeviceInfo();
	return newMessage;
}
int CIPCMessageDeviceInfo::TypeID() {
	return m_message.nType;
}
*/

} /* namespace NETCUT_CORE_FUNCTION */
