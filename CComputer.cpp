/*
 * CComputer.cpp
 *
 *  Created on: Jan 12, 2015
 *      Author: root
 */

#include "CComputer.h"

CComputer::CComputer() {
	// TODO Auto-generated constructor stub

	m_bOff = false;
	m_bHasMac = false;

	m_bAttacker = false;
	m_bNetCut = false;
	m_nGroundedLeftSeconds = 0;
	m_nLastNetCutSignTime = 0;
	m_nLastAttackerSignTime = 0;
	m_bIsMySelf = false;
	m_bIsGateWay = false;
	m_nAgeRate = 10;
	m_nSpeedLimit=0;
}

CComputer::~CComputer() {
	// TODO Auto-generated destructor stub
}

CComputer::CComputer(const CComputer& other) {

	(*this) = other;
}

bool CComputer::operator ==(const CComputer& d) {
	return IsSame(d);
}

bool CComputer::IsSame(const CComputer& other) {
	if (this->m_sIps != other.m_sIps)
		return false;
	if (this->m_bHasMac != other.m_bHasMac)
		return false;
	if (this->m_bHasMac && memcmp(this->m_sMac, other.m_sMac, 6) != 0)
		return false;

	return true;

}
CComputer& CComputer::operator=(const CGrounded& other) {
	CGrounded::operator=(other);

}
CComputer& CComputer::operator=(const CComputer& other) {

	this->m_IPs = other.m_IPs;
	this->m_bOff = other.m_bOff;
	this->m_sBrand = other.m_sBrand;
	this->m_sIps = other.m_sIps;
	this->m_sMacStr = other.m_sMacStr;
	memcpy(this->m_sMac, other.m_sMac, 6);
	this->m_sName = other.m_sName;
	this->m_Mask = other.m_Mask;
	this->m_bHasMac = other.m_bHasMac;
	this->m_bIsMySelf = other.m_bIsMySelf;
	this->m_bIsGateWay = other.m_bIsGateWay;
	this->m_nLastNetworkDiscoverTime = other.m_nLastNetworkDiscoverTime;
	this->m_nUpdateTime = other.m_nUpdateTime;
	this->m_nLastNetCutSignTime = other.m_nLastNetCutSignTime;
	this->m_nLastAttackerSignTime = other.m_nLastAttackerSignTime;
	this->m_nGroundedLeftSeconds = other.m_nGroundedLeftSeconds;
	this->m_nSpeedLimit=other.m_nSpeedLimit;

	return *this;
}

void CComputer::AddIP(const DWORD &p_nIP) {

	m_lock.lock();

	if (!this->IsMyIP(p_nIP))
		this->m_IPs[p_nIP] = false;

	ReadIPstoStr();
	m_lock.unlock();

}
void CComputer::ReadIPstoStr() {

	m_lock.lock();

	m_sIps = "";

	map<DWORD, bool>::iterator it;

	for (it = m_IPs.begin(); it != m_IPs.end(); ++it) {

		DWORD ip = (*it).first;
		m_sIps.append(CAddressHelper::IntIP2str(ip));
		m_sIps.append(" ");

	}

	m_sIps.pop_back();
	m_lock.unlock();
}
/*
 * if call with RemoveIP(),  it will remove all IPs;
 *
 void CComputer::RemoveIP(DWORD p_nIP) {

 m_lock.lock();
 list<DWORD>::iterator i;
 m_IPs.remove(p_nIP);
 if (p_nIP == 0)
 m_IPs.clear();

 ReadIPstoStr();
 m_lock.unlock();

 }

 DWORD CComputer::GetIP() {

 m_lock.lock();
 DWORD ip = m_IP;
 m_lock.unlock();
 return ip;

 }
 */
bool CComputer::IsMyIP(string p_sIP) {

	m_lock.lock();
	bool bfound = false;

	DWORD nIP = CAddressHelper::StrIP2Int(p_sIP);
	bfound = IsMyIP(nIP);

	m_lock.unlock();
	return bfound;
}

bool CComputer::IsMyIP(std::map<DWORD, bool> p_Ips) {
	m_lock.lock();
	bool bFound = false;
	map<DWORD, bool>::iterator it;

	for (it = m_IPs.begin(); it != m_IPs.end(); ++it) {

		DWORD ip = (*it).first;

		if (p_Ips.count(ip)) {
			bFound = true;
			break;
		}

	}
	m_lock.unlock();
	return bFound;

}

bool CComputer::IsSameRange(DWORD p_nIP) {

	m_lock.lock();

	bool bSameRange = false;
	map<DWORD, bool>::iterator it;

	for (it = m_IPs.begin(); it != m_IPs.end(); ++it) {

		DWORD ip = (*it).first;
		//TRACE("Compare existing IP %s to %s\n",CAddressHelper::IntIP2str(ip).c_str(),CAddressHelper::IntIP2str(p_nIP).c_str());
		if (CAddressHelper::isSameRang(ip, p_nIP, CAddressHelper::cmask)) {
			bSameRange = true;
			break;
		}
	}

	m_lock.unlock();
	return bSameRange;
}

bool CComputer::IsMyIP(DWORD p_nIP) {

	m_lock.lock();
	bool bFound;

	bFound = this->m_IPs.count(p_nIP);

	m_lock.unlock();
	return bFound;
}
string CComputer::GetIPs() {
	m_lock.lock();
	string s = this->m_sIps;

	m_lock.unlock();
	return s;
}

void CComputer::GetIPs(std::map<DWORD, bool> &p_Ips) {
	m_lock.lock();
	p_Ips = this->m_IPs;

	m_lock.unlock();

}

void CComputer::GetIPs(netcardEvent &p_Events) {

	m_lock.lock();

	p_Events.nIPSize = m_sIps.size() > EVENT_MAX_IPADDRESS ?
	EVENT_MAX_IPADDRESS :
																m_sIps.size();

	memcpy(p_Events.sIP, m_sIps.c_str(), p_Events.nIPSize);

	m_lock.unlock();

}

bool CComputer::IsMyMac(const MACADDR& p_sMac) {

	return IsMyMac(p_sMac.data());

}
bool CComputer::IsMyMac(const u_char * p_sBuf) {

	m_lock.lock();
	bool bFound = false;
	if (memcmp(this->m_sMac, p_sBuf, 6) == 0)
		bFound = true;
	m_lock.unlock();
	return bFound;

}
bool CComputer::IsMyMac(const std::string & p_sMacName) {
	m_lock.lock();
	bool bFound = false;
	if (p_sMacName == this->m_sMacStr)
		bFound = true;
	m_lock.unlock();
	return bFound;

}
bool CComputer::IsMyName(const std::string & p_sName) {

	m_lock.lock();
	bool bFound = false;
	if (p_sName != "" && p_sName == this->m_sName)
		bFound = true;
	m_lock.unlock();
	return bFound;
}
void CComputer::SetMac(const u_char * p_sBuf) {

	m_lock.lock();
	memcpy(this->m_sMac, p_sBuf, 6);
	this->mac = CAddressHelper::MacBuffer2Array(m_sMac);
	this->m_sMacStr = _helper_Mac_buff2Str(m_sMac);
	SetHasMac();
	m_lock.unlock();

}

array<u_char, 6> CComputer::GetMacArray() {

	m_lock.lock();
	array<u_char, 6> a = CAddressHelper::MacBuffer2Array(m_sMac);
	m_lock.unlock();
	return a;

}
void CComputer::GetMac(u_char *p_sBuf) {

	m_lock.lock();
	memcpy(p_sBuf, this->m_sMac, 6);

	m_lock.unlock();
}

const u_char * CComputer::GetMac() {
	m_lock.lock();
	u_char * p = this->m_sMac;

	m_lock.unlock();

	return p;

}
string CComputer::GetMacStr() {

	m_lock.lock();
	string s = this->m_sMacStr;

	m_lock.unlock();
	return s;
}
bool CComputer::SetName(const std::string & p_sName) {

	bool bNew = false;
	m_lock.lock();

	if (p_sName != m_sName) {
		this->m_sName = p_sName;
		bNew = true;

		//	TRACE("\n%s got name %s\n", this->m_sIps.c_str(),		this->m_sName.c_str());
	}

	m_lock.unlock();
	return bNew;

}
std::string CComputer::GetName() {

	m_lock.lock();
	std::string s = this->m_sName;
	m_lock.unlock();
	return s;
}
void CComputer::SetBrand(const std::string &p_sBrand) {

	m_lock.lock();
	this->m_sBrand = p_sBrand;
	m_lock.unlock();
}
std::string CComputer::GetBrand() {

	m_lock.lock();
	std::string s = this->m_sBrand;
	m_lock.unlock();
	return s;

}
void CComputer::FlagAsAttacker() {

	m_lock.lock();
	this->m_nLastAttackerSignTime = _helper_GetMiTime();
	m_bAttacker = true;
	m_lock.unlock();

}
bool CComputer::IsAttacker() {

	m_lock.lock();
	m_bAttacker =
			_helper_GetMiTime() - m_nLastAttackerSignTime > TIMEOUT_FLAG_SIGN ?
					false : true;
	bool b = this->m_bAttacker;
	m_lock.unlock();
	return b;

}
void CComputer::FlagAsNetCutDefender(bool p_bIsDefender) {
	m_lock.lock();
	this->m_nLastNetCutSignTime = p_bIsDefender ? _helper_GetMiTime() : 0;
	this->m_bNetCut = p_bIsDefender;

	//TRACE("%s is netcut user\n",this->m_sIps.c_str());

	m_lock.unlock();
}

void CComputer::SetGateWay(bool p_bGateway) {

	m_lock.lock();

	this->m_bIsGateWay = p_bGateway;

	m_lock.unlock();

}
bool CComputer::IsGateway() {

	m_lock.lock();
	bool bRet = this->m_bIsGateWay;

	m_lock.unlock();

	return bRet;

}
void CComputer::SetIsMySelf(bool p_bIsMyself) {

	m_lock.lock();

	this->m_bIsMySelf = p_bIsMyself;

	m_lock.unlock();
}
bool CComputer::IsMyself() {

	m_lock.lock();
	bool bRet = this->m_bIsMySelf;

	m_lock.unlock();

	return bRet;

}
bool CComputer::IsNetCutDefender() {

	m_lock.lock();
	m_bNetCut =
			_helper_GetMiTime() - m_nLastNetCutSignTime > TIMEOUT_FLAG_SIGN ?
					false : true;
	bool b = this->m_bNetCut;
	m_lock.unlock();
	return b;

}

void CComputer::SetAgeRate(int p_nAgeRate) {

	m_lock.lock();


	this->m_nAgeRate=p_nAgeRate;

		m_lock.unlock();

}
int CComputer::GetAgeRate() {

	m_lock.lock();
	int n = 0;

	n = m_nAgeRate;

	m_lock.unlock();
	return n;
}

int CComputer::GetSpeedLimit()
{
	m_lock.lock();
		int n = 0;

		n = m_nSpeedLimit;

		m_lock.unlock();
		return n;

}
void CComputer::SetSpeedLimit(int p_nLimitRank)
{

	m_lock.lock();

	this->m_nSpeedLimit = p_nLimitRank;
	m_lock.unlock();

}
void CComputer::SetOff(bool p_Off) {

	m_lock.lock();

	this->m_bOff = p_Off;
	if (!this->m_bOff && this->IsGrounded()) {
		this->DisableTimer();
	}

	m_lock.unlock();
}
bool CComputer::IsSetOff() {
	m_lock.lock();
	bool bStat = false;

	bStat = m_bOff;

	m_lock.unlock();
	return bStat;
}
bool CComputer::IsSpeedLimit()
{

	m_lock.lock();
	bool bStat = false;

	if(this->m_nSpeedLimit!=0)
		bStat=true;

	m_lock.unlock();
	return bStat;

}
bool CComputer::IsOff() {

	m_lock.lock();
	bool bStat = false;
	if (!IsNetCutDefender() && m_bOff)
		bStat = true;

	/*	if (IsAttacker()) {
	 bStat = true;
	 }
	 */
	if (IsGrounded()) {
		bStat = true;
	}

	if(this->IsSpeedLimit())
	{
		bStat = true;
	}

	m_lock.unlock();
	return bStat;

}

DWORD CComputer::GetMask() {

	m_lock.lock();

	DWORD nret = this->m_Mask;

	m_lock.unlock();
	return nret;
}
bool CComputer::HasMac() {

	m_lock.lock();

	bool bret = this->m_bHasMac;

	m_lock.unlock();
	return bret;
}
time_t CComputer::GetUpdateTime() {

	m_lock.lock();

	time_t bret = this->m_nUpdateTime;

	m_lock.unlock();
	return bret;
}
time_t CComputer::GetDiscoverTime() {

	m_lock.lock();

	time_t bret = this->m_nLastNetworkDiscoverTime;

	m_lock.unlock();
	return bret;
}
void CComputer::SetMask(DWORD p_nMask) {

	m_lock.lock();

	this->m_Mask = p_nMask;
	m_lock.unlock();

}
void CComputer::SetHasMac() {

	m_lock.lock();

	this->m_bHasMac = true;
	m_lock.unlock();

}
void CComputer::SetUpdateTime(time_t p_nTime) {

	m_lock.lock();

	this->m_nUpdateTime = p_nTime;
	m_lock.unlock();
}
void CComputer::SetDiscoverTime(time_t p_nTime) {

	m_lock.lock();

	this->m_nLastNetworkDiscoverTime = p_nTime;
	m_lock.unlock();
}

