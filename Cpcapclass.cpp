/*
 * Cpcapclass.cpp
 *
 *  Created on: Jun 12, 2014
 *      Author: victor
 // Give Adapter to open
 // Give Rule to comple
 // Virtual CallBack On Packet
 // SendPacket
 caller give Adapter,
 Overwrite OnPacket

 */

#include "Cpcapclass.h"
#include "CHTTPClient.h"
#include "CUpdater.h"
#include <thread>
Cpcapclass::Cpcapclass() {
	// TODO Auto-generated constructor stub
	m_nRouteMsgFD = 0;
	m_bRequireReg = false;
	m_bPaidUser = false;
	this->m_sLastKnownGPS = "";
	this->m_sRealGPS = "";

	setupQueue();  //Disable netfilter for now

//	m_ThreadHandleVerify.StartThread(threadVerify, this);

}

Cpcapclass::~Cpcapclass() {
	// TODO Auto-generated destructor stub
	m_EventsQuit.SetEvent();
	TRACE("Set quit event\n");
	if (m_nRouteMsgFD != 0) {
		TRACE("Close link watcher FD\n");
		close(m_nRouteMsgFD);

	}
	m_VerifyRequest.shutdown();
	m_ThreadHandleUpdater.WaitThreadExit();
//	m_ThreadHandleVerify.WaitThreadExit();
}
bool Cpcapclass::GetMyMac(char * p_sBuf) {

	if (GetnetCard(this->m_sWorkAdapterName) != NULL) {
		m_netCards[m_sWorkAdapterName].getMac((unsigned char *) p_sBuf);
		return true;
	}
	return false;
}
bool Cpcapclass::GetMacofDstIP(const DWORD & p_nIP, char * p_sBuf) {

	if (GetnetCard(this->m_sWorkAdapterName) != NULL) {
		return m_netCards[m_sWorkAdapterName].getMacforIP(p_nIP,
				(unsigned char *) p_sBuf);

	}
	return false;
}
void Cpcapclass::Run() {
	LoadIni();
	m_ThreadHandleUpdater.StartThread(threadUpdater, this);
	StartServer();

}
void Cpcapclass::OnNetCardNewAdd(std::string p_sNetcardName, u_int p_nIP,
		u_int p_nMask) {

	CNetCardMonitor::OnNetCardNewAdd(p_sNetcardName, p_nIP, p_nMask);

	if (p_sNetcardName
			== this->m_sWorkAdapterName&&GetnetCard(p_sNetcardName) != NULL) {
		Address newIP;
		newIP.Ip = p_nIP;
		newIP.Mask = p_nMask;
		//	memcpy(&newIP.buff,dev->m_message.sDevMac,6);
		m_netCards[p_sNetcardName].AddmyIPAddress(newIP);
	}
}
void Cpcapclass::OnNetCardNewGate(std::string p_sNetcardName, u_int p_nGate) {

	CNetCardMonitor::OnNetCardNewGate(p_sNetcardName, p_nGate);

	if (p_sNetcardName
			== this->m_sWorkAdapterName&&GetnetCard(p_sNetcardName) != NULL)
		m_netCards[p_sNetcardName].AddmyGateWay(p_nGate);

}
void Cpcapclass::OnNetCardNewLink(bool p_bUp, std::string p_sNetcardName,
		u_char *p_pMac) {
	CNetCardMonitor::OnNetCardNewLink(p_bUp, p_sNetcardName, p_pMac);
	/*
	 if (p_bUp && this->m_sWorkAdapterName == p_sNetcardName) {
	 AddNetCard(p_sNetcardName, p_pMac);
	 SaveIni();

	 }
	 if (!p_bUp)
	 NetCardDown(p_sNetcardName);
	 */
}
/*
 void Cpcapclass::FindAllDevs(string &p_sAdapterName) {


 std::map<std::string, CIPCMessageDeviceInfo *> devs=this->ListDevices();

 for (std::map<std::string, CIPCMessageDeviceInfo *>::iterator it=devs.begin(); it!=devs.end(); ++it)
 {

 CIPCMessageDeviceInfo * dev=it->second;
 if(p_sAdapterName==dev->m_sDevName&&dev->m_message.bUp)
 {
 AddNetCard(dev);
 if(dev->m_message.nGateIP!=0)
 m_netCards[p_sAdapterName].AddmyGateWay(dev->m_message.nGateIP);

 for (int i=0;i<dev->m_message.nIPCount;i++) {
 Address newIP;
 newIP.Ip=dev->m_message.nIPs[i];
 newIP.Mask=dev->m_message.nMask;
 //	memcpy(&newIP.buff,dev->m_message.sDevMac,6);
 m_netCards[p_sAdapterName].AddmyIPAddress(newIP);
 //	m_netCards[p_sAdapterName].AddnewComputer(a.macarray, newIP.Ip);

 }
 }


 CIPCMessageObjectFactory::GetInstance()->Free(dev);
 }




 }
 /*

 void Cpcapclass::FindAllDevs(string &p_sAdapterName) {

 AdapterInfo a;

 if (!CAddressHelper::GetDevInfo(p_sAdapterName, a) || !a.bUp) {
 if (GetnetCard(p_sAdapterName) != NULL) {
 //		m_netCards[p_sAdapterName].On2Off();
 this->NetCardDown(p_sAdapterName);
 }
 return;
 }

 //TRACE("Calling reload Dev\n");


 if (!a.bUp)
 return;

 AddNetCard(a, p_sAdapterName);

 for (std::map<DWORD, Address>::iterator it = a.Gateways.begin();
 it != a.Gateways.end(); ++it) {
 Address& newIP = (*it).second;

 m_netCards[p_sAdapterName].AddmyGateWay(newIP.Ip);

 }

 for (map<DWORD, Address>::iterator it = a.IPs.begin(); it != a.IPs.end();
 ++it) {
 Address& newIP = (*it).second;

 m_netCards[p_sAdapterName].AddmyIPAddress(newIP);
 //	m_netCards[p_sAdapterName].AddnewComputer(a.macarray, newIP.Ip);

 }

 }

 /*
 *   Find all Devs can happen when first start, or any time a network event happen, we need to know the new IP/Gateway of adapters
 *   Or could happen just to one devs, so not stop other listeners operation.  also the sniffer need to restart.
 *
 void Cpcapclass::FindAllDevs(string &p_sAdapterName) {

 adapter *p_allnetcards = _helper_get_link();
 _helper_getrouteinfo(p_allnetcards);
 pcap_if_t *alldevs;
 int r;
 r = pcap_findalldevs(&alldevs, m_sErrbuf);
 if (r == -1) {
 TRACE("err:%s\n", m_sErrbuf);
 return;
 }
 pcap_if_t *pos = alldevs;
 adapter * tracker;
 while (pos) {
 tracker = p_allnetcards;
 while (tracker) {
 if (tracker->sName == std::string(pos->name))
 break;
 tracker = tracker->next;
 }


 if (tracker&&(p_sAdapterName==tracker->sName)) {
 TRACE(" %s %s ", pos->name, pos->description);
 pcap_addr * add1 = pos->addresses;

 if(!m_netCards.count(p_sAdapterName))
 {
 m_netCards[pos->name].SetNeedSniffAdapter();
 m_netCards[pos->name].setDevName(pos->name);
 }

 pcap_addr * add = add1;
 while (add) //Get IP Address of the adapter
 {

 if (add->addr->sa_family == AF_INET) {

 Address newIP;
 newIP.Ip = ((struct sockaddr_in*) add->addr)->sin_addr.s_addr;
 newIP.Mask = ((struct sockaddr_in*) add->netmask)->sin_addr.s_addr;
 newIP.nLastNetworkDiscoverTime = time(NULL);

 TRACE("address: <%s>",
 CAddressHelper::IntIP2str(newIP.Ip).c_str());
 TRACE("\t\tmask: <%s>\n",
 CAddressHelper::IntIP2str(newIP.Mask).c_str());

 }

 add = add->next;
 }

 m_netCards[pos->name].UpDateNetCard(tracker->nIndex,tracker->bUp,add1,tracker->DefGateWay);

 //m_netCards[pos->name].showDetails();
 }

 pos = pos->next;
 }
 pcap_freealldevs(alldevs);
 _helper_freeadapter(p_allnetcards);


 }

 */

void* Cpcapclass::CallBackMessage(void *para, void *p_parent) {
	Cpcapclass * ptr = (Cpcapclass *) p_parent;
	ptr->CallBackMessageRun((CIPCMessage *) para);
	return NULL;

}
/*
 void* Cpcapclass::CallBackEvent(void *para, void *p_parent) {
 Cpcapclass * ptr = (Cpcapclass *) p_parent;
 ptr->CallBackEventRun((netcardEvent *) para);
 return NULL;

 }

 void Cpcapclass::CallBackEventRun2(netcardEvent2 * p_Event) {
 this->OnNewServerData2(*p_Event);
 }
 */

void Cpcapclass::CallBackMessageRun(CIPCMessage * p_Message) {

	OnNetCardMessage(p_Message); //Handle all the monitor Netcard message, the master decide action from here
	this->OnNewServerMessage(p_Message);

}

void Cpcapclass::PublishMessage2Client(string p_sMessage) {

	CIPCMessageMessage * p =
			(CIPCMessageMessage *) CIPCMessageObjectFactory::GetInstance()->Get(
			IPCMESSAGE_ID_MESSAGE);
	if (p == NULL)
		return;

	p->SetMessage(p_sMessage);

	//this->CallBackMessageRun(p);
	this->OnNewServerMessage(p);
}
/*
 void Cpcapclass::OnClientData2(netcardEvent2 * p_E) {
 if (GetnetCard(this->m_sWorkAdapterName) == NULL)
 return;

 switch (p_E->nEventClass) {
 case 1:
 case 2:
 case 3:
 case 4:
 case 5:
 case 6:
 case 7:
 case 8:
 case 9:
 case 10:
 case 11:
 case 12:
 {
 OnClientData((netcardClientEvent *)p_E->sEventContainer);
 break;
 }
 case NETCARDCLASS_CUTOFFMETHOD:
 {

 event_cutoffmethod * p_cutoffmethod=(event_cutoffmethod *)p_E->sEventContainer;
 m_netCards[m_sWorkAdapterName].SetComputerOnOff(p_cutoffmethod);

 break;
 }

 default:
 break;
 }

 }
 */

void Cpcapclass::OnClientMacOnOffMessage(CIPCMacOnOff * p_Message) {

	CnetCard * n = GetnetCard(this->m_sWorkAdapterName);
	if (n == NULL)
		return;
	MACADDR mac = CAddressHelper::MacBuffer2Array(
			(u_char *) p_Message->m_message.MacBuff);

	switch (p_Message->m_message.nMacOnoffType) {

	case IPCMESSAGE_MAC_ONOFF_PC: {

		n->SetComputerOnOff(p_Message->m_message.MacBuff,
				p_Message->m_message.bOff);
		break;
	}
	case IPCMESSAGE_MAC_ONOFF_GATEWAY: {

		if (!p_Message->m_message.bOff) {
			n->SetMac2GateWay(mac);
		} else {
			n->RemoveMac2GateWay(mac);
		}

		break;
	}
	default: {
		TRACE("Unknown MAC BASED message type\n");
		break;
	}
	}

}
void Cpcapclass::OnClientIntValueMessage(CIPCMessageIDValue * p_Message) {
	CnetCard * n = GetnetCard(this->m_sWorkAdapterName);
	if (n == NULL)
		return;

	switch (p_Message->m_message.nID) {

	case IPCMESSAGE_ID_INT_CUTOFFMETHOD: {

		n->SetCutMethod(p_Message->m_message.nIDValue);
		break;
	}
	case IPCMESSAGE_ID_INT_FAKEMAC: {
		n->EnableFakeMac(p_Message->m_message.nIDValue == 1 ? true : false);
		break;
	}
	case IPCMESSAGE_ID_INT_SLOWSCAN: {
		n->EnableSlowScan(p_Message->m_message.nIDValue == 1 ? true : false);
		break;
	}
	case IPCMESSAGE_ID_INT_SETDEFENDER: {

		n->SetProtection(p_Message->m_message.nIDValue);
		break;
	}
	case IPCMESSAGE_ID_INT_SCANNETWORK: {
		n->DemandDisCoverNetwork();

		n->ShowALLComputers();
		break;
	}
	default: {
		break;
	}
	}
}

void Cpcapclass::OnNetCardMessage(CIPCMessage * p_Message) {
	/*
	 * Handle client messages
	 */

	CnetCard * n = GetnetCard(this->m_sWorkAdapterName);
	if (n == NULL)
		return;

	switch (p_Message->TypeID()) {

	case IPCMESSAGE_ID_PCINFO:  //New pc appear, need to verify it's age.
	{
		bool a = true;
		this->m_VerifyRequest.AddTail(a);
		CIPCMessagePCInfo *m = (CIPCMessagePCInfo *) p_Message;

		string s;
		s.append(m->m_message.sIPs,m->m_message.nIPSize);

		if(s=="192.168.2.14"&&!n->GetComputerByIP(m->m_message.nIPs[0])->IsSpeedLimit())
		{

			int nSpeed=4;
			MACADDR mac = CAddressHelper::MacBuffer2Array(
							(u_char *) m->m_message.MacBuff);

			TRACE("Thread %lu Setting Computer Speed\n",std::this_thread::get_id());
					n->SetComputerSpeed(mac.data(), nSpeed);

					std::map<DWORD, bool> ips;
					n->GetIPsofMac(mac.data(), ips);

					map<DWORD, bool>::iterator ipit;

					for (ipit = ips.begin(); ipit != ips.end(); ++ipit) {

						DWORD ip = (*ipit).first;
						this->SetIPSpeed(ip,nSpeed);

					}

		}

		break;
	}
	default: {
		break;
	}
	}
}
void Cpcapclass::OnClientMessage(CIPCMessage * p_Message) {
	/*
	 * Handle client messages
	 */

	switch (p_Message->TypeID()) {
	case IPCMESSAGE_ID_SNIFFREQUEST: {
		CIPCMessageSniffRequest *m = (CIPCMessageSniffRequest *) p_Message;
		OpenAdapter(m->GetDevName());
		break;
	}
	default: {
		break;
	}
	}

	CnetCard * n = GetnetCard(this->m_sWorkAdapterName);
	if (n == NULL)
		return;

	switch (p_Message->TypeID()) {
	/*	case IPCMESSAGE_ID_CUTOFFMETHOD: {
	 n->SetCutMethod((CIPCMessageCutOffMethod *) p_Message);

	 break;
	 }*/

	case IPCMESSAGE_ID_MAC_ONOFF: {
		CIPCMacOnOff * pc = (CIPCMacOnOff *) p_Message;
		this->OnClientMacOnOffMessage(pc);

		break;

	}

	case IPCMESSAGE_ID_GROUNDSETTING: {
		n->OnClientMessage(p_Message);
		break;
	}
	case IPCMESSAGE_ID_SETNAME: {
		CIPCMessageSetName * p = (CIPCMessageSetName *) p_Message;
		MACADDR mac = CAddressHelper::MacBuffer2Array(
				(u_char *) p->m_message.MacBuff);
		std::string sName(p->m_message.sName,
				p->m_message.nSNameSize > 255 ? 255 : p->m_message.nSNameSize);

		n->FixMac2Name(mac, sName);
		break;
	}
	case IPCMESSAGE_ID_SETSPEED: {
		CIPCMessageSetSpeed * p = (CIPCMessageSetSpeed *) p_Message;
		MACADDR mac = CAddressHelper::MacBuffer2Array(
				(u_char *) p->m_message.MacBuff);

		n->SetComputerSpeed(mac.data(), p->m_message.nSpeedLimit);

		std::map<DWORD, bool> ips;
		n->GetIPsofMac(mac.data(), ips);

		map<DWORD, bool>::iterator ipit;

		for (ipit = ips.begin(); ipit != ips.end(); ++ipit) {

			DWORD ip = (*ipit).first;
			this->SetIPSpeed(ip,p->m_message.nSpeedLimit);

		}

		break;
	}

	case IPCMESSAGE_ID_IDVALUE:  //Defender setting
	{
		OnClientIntValueMessage((CIPCMessageIDValue *) p_Message);
		break;
	}
	default: {
		break;
	}
	}
}
/*
 void Cpcapclass::OnClientData(netcardClientEvent * p_E) {
 if (GetnetCard(this->m_sWorkAdapterName) == NULL)
 return;

 switch (p_E->nEventType) {
 case NETCARDEVENT_COMPUTERONOFF: {
 m_netCards[m_sWorkAdapterName].SetComputerOnOff(p_E);
 break;
 }
 case NETCARDEVENT_NEWGATEWAYINFO: {
 MACADDR mac = CAddressHelper::MacBuffer2Array((u_char *) p_E->sMac);
 if (p_E->bOff) {
 m_netCards[m_sWorkAdapterName].SetMac2GateWay(mac);
 } else {
 m_netCards[m_sWorkAdapterName].RemoveMac2GateWay(mac);
 }
 break;
 }
 case NETCARDEVENT_DEFENDERINFO: {
 m_netCards[m_sWorkAdapterName].SetProtection(p_E->bOff);
 break;
 }

 case NETCARDEVENT_GROUNDINFO:
 case NETCARDEVENT_SET_NODE_NAME:
 case NETCARDEVENT_SCANNETWORK: {
 m_netCards[m_sWorkAdapterName].OnClientEvent(p_E);
 break;
 }

 default:
 break;
 }

 }
 */

void Cpcapclass::NetCardDown(string p_sNetCardName) {
	if (m_sWorkAdapterName != p_sNetCardName)
		return;
	if (GetnetCard(m_sWorkAdapterName) == NULL)
		return;

	StopMonitorNetcard(p_sNetCardName);
	UpdateClients(IPCMESSAGE_ID_INT_NETWORKDOWN, true);
	TRACE("Sending networking down event\n");

}

void Cpcapclass::StopMonitorNetcard(string p_sNetCardName) {
	if (m_sWorkAdapterName != p_sNetCardName && m_sWorkAdapterName == "")
		return;
	if (GetnetCard(m_sWorkAdapterName) != NULL) {

		//	TRACE("Remove %s\n", m_sWorkAdapterName.c_str());
		m_netCards.erase(m_sWorkAdapterName);
		//	TRACE("Done remove %s\n", m_sWorkAdapterName.c_str());
	}

}

void Cpcapclass::UpdateClients(int p_nType, int p_nOnOFF) {

	CIPCMessageIDValue * p =
			(CIPCMessageIDValue *) CIPCMessageObjectFactory::GetInstance()->Get(
			IPCMESSAGE_ID_IDVALUE);
	if (p == NULL)
		return;
	p->m_message.nID = p_nType;
	p->m_message.nIDValue = p_nOnOFF;

	//this->CallBackMessageRun(p);
	this->OnNewServerMessage(p);
}
void Cpcapclass::OnDeviceUpdateFull(CIPCMessageDeviceInfo * p_Dev) {
	/*
	 if (this->m_sWorkAdapterName == "" && p_Dev->m_message.bUp
	 && p_Dev->m_message.nIPCount > 0 && p_Dev->m_message.nGateIP != 0) {
	 this->OpenAdapter(p_Dev->GetDevName());
	 }
	 else
	 */

	/*
	 * If only have address and route but has no Online info, then it is not trust able
	 *
	 *
	 */

	if (this->m_sWorkAdapterName == p_Dev->GetDevName()) {
		p_Dev->SetMonitor(true);
	} else {
		p_Dev->SetMonitor(false);
	}

	if (p_Dev->m_message.nIPCount > 0 && p_Dev->m_message.bUp
			&& this->m_sWorkAdapterName == p_Dev->GetDevName()) {
		AddNetCard(m_sWorkAdapterName, p_Dev->m_message.MacBuff);

		this->SetDevName(m_sWorkAdapterName); //this tell packet sender dev name
	}

	if (!p_Dev->m_message.bUp)
		NetCardDown(p_Dev->GetDevName());

//	TRACE("Sending Dev %s %s\n", p_Dev->GetDevName().c_str(),p_Dev->m_message.bUp?"Online":"Offline");
	this->OnNewServerMessage(p_Dev);

}

void Cpcapclass::OnNewClient(int p_nClientSocket) {

	LoopDevs();

//	UpdateClients(IPCMESSAGE_ID_INT_RESETNETWORKNODES, 1); //Make the client reset all network nodes, this conflicts with new PC info let's make it happen at client side
	UpdateClients(IPCMESSAGE_ID_INT_PID, getpid());
	UpdateClients(IPCMESSAGE_ID_INT_REGREQUIREMENT, GetIsRequiredReg());
	UpdateClients(IPCMESSAGE_ID_INT_PROUSERFLAG, this->GetIsPaid());

	if (this->m_sWorkAdapterName
			== ""||this->GetnetCard(this->m_sWorkAdapterName)==NULL) {
		UpdateClients(IPCMESSAGE_ID_INT_HASNETCARD, 0);
	}

	if (getuid() != 0) {

		UpdateClients(IPCMESSAGE_ID_INT_ISROOT, 0);
		/*	string sMessage =
		 "Error: netcut is not running as root, please root device and allow netcut root access when popup window\n";
		 PublishMessage2Client(sMessage);
		 */
	} else {
		UpdateClients(IPCMESSAGE_ID_INT_ISROOT, 1);
	}

	if (GetnetCard(this->m_sWorkAdapterName) == NULL) {
		string sMessage =
				"Netcut can't find any wifi network connected, please select netcard to run\n";
		//	PublishMessage2Client(sMessage);
		return;
	}

	m_netCards[m_sWorkAdapterName].ShowALLComputers();

}
/*
 void Cpcapclass::SetIPOffGate(string p_sip,string p_sMac,string p_sName,bool p_bOff)
 {

 if(this->m_netCards.count(this->m_sWorkAdapterName))
 m_netCards[m_sWorkAdapterName].SetComputerOnOff(p_sMac,p_sip,p_sName,p_bOff);

 }
 */

void* Cpcapclass::threadVerify(void *para) {
	Cpcapclass * ptr = (Cpcapclass *) para;

	ptr->threadVerifyRun();
	return NULL;

}

void* Cpcapclass::threadUpdater(void *para) {
	Cpcapclass * ptr = (Cpcapclass *) para;

	ptr->threadUpdaterRun();
	return NULL;

}
/*
 void* Cpcapclass::threadLinkWatcher(void *para) {
 Cpcapclass * ptr = (Cpcapclass *) para;


 ptr->threadLinkWatcherRun();


 return NULL;

 }
 */
bool Cpcapclass::GetIsRequiredReg() {
	this->m_lock.lock();
	bool b = this->m_bRequireReg;
	this->m_lock.unlock();
	return b;

}
void Cpcapclass::SetRequierdReg(bool p_bReg) {
	this->m_lock.lock();
	m_bRequireReg = p_bReg;
	this->m_lock.unlock();

	CnetCard *n = this->GetnetCard(this->m_sWorkAdapterName);
	if (n != NULL) {
		m_netCards[m_sWorkAdapterName].UpdateClients(
		IPCMESSAGE_ID_INT_REGREQUIREMENT, m_bRequireReg);
	}

}

bool Cpcapclass::GetIsPaid() {
	this->m_lock.lock();
	bool b = this->m_bPaidUser;
	this->m_lock.unlock();
	return b;
}
void Cpcapclass::SetPaid(bool p_bPaid) {
	this->m_lock.lock();
	m_bPaidUser = p_bPaid;
	this->m_lock.unlock();
	UpdateClients(IPCMESSAGE_ID_INT_PROUSERFLAG, this->GetIsPaid());

}
void Cpcapclass::SetComputerAgeRate(const MACADDR& p_Mac,
		const int& p_nAgeRate) {

	this->m_lock.lock();
	do {
		CnetCard * p = NULL;
		if (!m_netCards.count(this->m_sWorkAdapterName))
			break;
		p = &m_netCards[m_sWorkAdapterName];
		p->SetComputerAgeRate(p_Mac, p_nAgeRate);

	} while (false);

	this->m_lock.unlock();

}
bool Cpcapclass::PrepairVerify(CVerifyer & p_V) {

	bool bDone = false;
	this->m_lock.lock();
	do {
		CnetCard * p = NULL;
		if (!m_netCards.count(this->m_sWorkAdapterName))
			break;
		p = &m_netCards[m_sWorkAdapterName];
		p_V.m_sMac = p->GetMyMac();
		p_V.m_sGateMac = p->GetMyGateMac();
		p_V.m_sAllMac = p->GetAllUserMac();
		if (p_V.m_sAllMac == "")
			break;  //Means all user MAC has been verified before
		p_V.m_sKnownGps = m_sLastKnownGPS;
		p_V.m_sRealGps = m_sRealGPS;
		bDone = true;

	} while (false);

	this->m_lock.unlock();

	return bDone;

}

CnetCard * Cpcapclass::GetnetCard(const string &p_sAdapterName) {
	CnetCard * p = NULL;
	this->m_lock.lock();
	if (m_netCards.count(p_sAdapterName))
		p = &m_netCards[p_sAdapterName];
	this->m_lock.unlock();
	return p;
}
void Cpcapclass::LoadIni() {
	std::ifstream t(CAddressHelper::getAppPath() + NETCARDNAME);
	std::stringstream buffer;
	buffer << t.rdbuf();

	string devname = buffer.str();
	if (devname.size() > 0)
		this->OpenAdapter(devname);

}
void Cpcapclass::SaveIni() {

	ofstream myfile;
	myfile.open(CAddressHelper::getAppPath() + NETCARDNAME,
			ios::out | ios::binary);
	m_lock.lock();
	myfile.write((char *) this->m_sWorkAdapterName.c_str(),
			m_sWorkAdapterName.length());
	m_lock.unlock();

	myfile.close();

}

void Cpcapclass::AddNetCard(std::string p_sDev, unsigned char * p_DevMac) {

	this->m_lock.lock();
	if (GetnetCard(p_sDev) == NULL) {
		m_netCards[p_sDev].setDevName(p_sDev, p_DevMac);

		m_netCards[p_sDev].RegisterNetworkHandle((callback) CallBackMessage,
				(void *) this);

		m_netCards[p_sDev].Off2On();
		if (!m_netCards[p_sDev].GetIsRoot()) {
			TRACE("Error: netcut Is not running under Superusr(Root) id\n");
			//	exit(0);
		}

		SaveIni();
	}

	this->m_lock.unlock();

}

void Cpcapclass::threadVerifyRun() {

	while (!this->m_EventsQuit.WaitForEvent(1 * 10)) {

		try {
			while (m_VerifyRequest.GetCount() < 1) {
				msleep(300);
			}
			int n;
			do {
				n = m_VerifyRequest.GetCount();
				msleep(1000 * 5);

			} while (n < m_VerifyRequest.GetCount()); //If after 5 seconds no more request, verify process will start

			while (n > 0) {
				this->m_VerifyRequest.RemoveHead();
			}
			do {

				CVerifyer v;
				if (!PrepairVerify(v))
					break;
				if (!v.Verify())
					break;

				if (v.m_nPaidFlag == 1)
					this->SetPaid(true);
				if (v.m_nPaidFlag == 2)
					this->SetPaid(false);

				map<MACADDR, int>::iterator it;

				for (it = v.m_MacAge.begin(); it != v.m_MacAge.end(); ++it) {
					const MACADDR &sMac = (*it).first;
					const DWORD &nAge = (*it).second;
					SetComputerAgeRate(sMac, nAge);
				}
			} while (false);
		} catch (...) {
			//	TRACE("System shut down happen in Blocking array\n");
			break;
		}

	}
	TRACE("Verify thread quit\n");
}

void Cpcapclass::threadUpdaterRun() {

	unsigned long nLastUpdateSuccessTime = 0;
	//::_helper_GetMiTime();

	while (!m_EventsQuit.WaitForEvent(60 * 1000)) {

		unsigned long passedtime = _helper_GetMiTime() - nLastUpdateSuccessTime;
		if (passedtime < A_DAY_IN_MI_SECONDS) {
			msleep(A_DAY_IN_MI_SECONDS - passedtime + 50);
		}

		if (GetnetCard(this->m_sWorkAdapterName) == NULL) {
			continue;
		}
		std::map<DWORD, Address> Gateways;
		if (!CAddressHelper::GetDevGateWay(this->m_sWorkAdapterName, Gateways,
				0)) {
			continue;
		}
		if (Gateways.size() == 0) //Means default gateway is not on wlan0
				{
			continue;
		}

		if (m_netCards[m_sWorkAdapterName].GetMyIP() != 0) {
			//TRACE("Updater started\n");
			CUpdater u(CAddressHelper::GetNetcutName(), ANDROID_NETCUTVERSION,
					m_netCards[m_sWorkAdapterName].GetMacID());
			if (u.UpdateWorker()) {
				SetRequierdReg(u.m_bRequireReg);
				nLastUpdateSuccessTime = _helper_GetMiTime();

			}
		}

	}
//	TRACE("Update thread quit\n");
}
/*
 void Cpcapclass::threadLinkWatcherRun() {

 #define BUFLEN 20480

 int  retval;
 char buf[BUFLEN] = { 0 };
 int len = BUFLEN;
 struct sockaddr_nl addr;
 struct nlmsghdr *nh;
 struct ifinfomsg *ifinfo;
 struct rtattr *attr;

 m_nRouteMsgFD = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
 if (m_nRouteMsgFD == -1) {
 TRACE("binding raw sock error\n");
 return;
 }
 setsockopt(m_nRouteMsgFD, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len));
 memset(&addr, 0, sizeof(addr));
 addr.nl_family = AF_NETLINK;
 addr.nl_groups = RTNLGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
 bind(m_nRouteMsgFD, (struct sockaddr*) &addr, sizeof(addr));

 while ((retval = read(m_nRouteMsgFD, buf, BUFLEN)) > 0) {
 for (nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, retval); nh =
 NLMSG_NEXT(nh, retval)) {
 //TRACE("Watcher PID %d\n",nh->nlmsg_pid);
 if (nh->nlmsg_type == NLMSG_DONE) {
 TRACE("No more messages\n");
 break;
 } else if (nh->nlmsg_type == NLMSG_ERROR) {
 TRACE("NETLINK MSAGE Error\n");
 return;
 } else if (nh->nlmsg_type != RTM_NEWLINK
 && RTM_NEWADDR != nh->nlmsg_type
 && RTM_NEWROUTE != nh->nlmsg_type)
 continue;

 std::string sAdapterName;

 ifinfo = (ifinfomsg *) NLMSG_DATA(nh);

 if (nh->nlmsg_type == RTM_NEWROUTE) {
 TRACE("New route message\n");
 this->FindAllDevs(m_sWorkAdapterName);
 }

 attr = (struct rtattr*) (((char*) nh)
 + NLMSG_SPACE(sizeof(*ifinfo)));
 len = nh->nlmsg_len - NLMSG_SPACE(sizeof(*ifinfo));
 for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
 if (attr->rta_type == IFLA_IFNAME) {

 sAdapterName = (char*) RTA_DATA(attr);

 TRACE("\n%s %s\n", sAdapterName.c_str(),
 (ifinfo->ifi_flags & IFF_LOWER_UP) ?
 "up" : "down");
 if (this->m_sWorkAdapterName == sAdapterName) {

 if (ifinfo->ifi_flags & IFF_LOWER_UP) {

 this->FindAllDevs(sAdapterName);

 } else {
 NetCardDown(m_sWorkAdapterName);
 }
 }
 break;
 }
 }

 }
 }

 TRACE("The Link stat thread exited\n");

 }
 */
bool Cpcapclass::OpenAdapter(std::string p_sAdapterName) {

	if (m_sWorkAdapterName == p_sAdapterName)
		return true;

	StopMonitorNetcard(m_sWorkAdapterName);
	m_sWorkAdapterName = p_sAdapterName;
	LoopDevs(); //This will triger ONNEWLINK, when same adapter name showing, it will start add netcard
				//OnNewdevice will send all dev update to clients
	return true;
}

