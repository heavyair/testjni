/*
 * Cpcapclass.h
 *
 *  Created on: Jun 12, 2014
 *      Author: victor
 */


#include <CNetCard2.h>
#include "CPacketFilter.h"
#include <map>
#include "CThreadWorker.h"
#include "CMyLock.h"
#include <CNetCardMonitor.h>
#include <CSocketIPC.h>
#include <CBlockArray.h>
#include "CVerifyer.h"


#ifndef CPCAPCLASS_H_
#define CPCAPCLASS_H_
//#include "safequeue.hpp"
using namespace NETCUT_CORE_FUNCTION;
using namespace neosmart;

#define A_DAY_IN_MI_SECONDS 1000 * 60 * 60 * 24
//#define A_DAY_IN_MI_SECONDS 1000 * 5

class Cpcapclass : public CPacketFilter,public CSocketIPC, public CNetCardMonitor {
public:

    static void* threadUpdater(void *para);
    void threadUpdaterRun();

    static void* threadVerify(void *para);
    void threadVerifyRun();



    static void* CallBackMessage(void *para,void *p_parent);
 //   static void* CallBackEvent(void *para,void *p_parent);
 //   void CallBackEventRun(netcardEvent * p_Event);


    void CallBackMessageRun(CIPCMessage * p_Message);

	Cpcapclass();
	virtual ~Cpcapclass();


   // void SetComputerOnOff(string& p_sMac,string & p_sIPs,string & p_sName,bool & p_bOff);

	bool OpenAdapter(std::string p_sAdapterName);

//	void FindAllDevs(string &p_sAdapterName);

	//void OnClientData(netcardClientEvent * p_E);
	//void OnClientData(netcardEvent2 * p_E);
	void OnNetCardMessage(CIPCMessage * p_Message);
	void OnClientMessage(CIPCMessage * p_Message);
	void OnClientIntValueMessage(CIPCMessageIDValue * p_Message);
	void OnClientMacOnOffMessage(CIPCMacOnOff * p_Message);
	void OnNewClient(int p_nClientSocket);

	virtual void OnDeviceUpdateFull(CIPCMessageDeviceInfo * p_Dev); // any dev change will triger this
	void UpdateClients(int p_nType,int p_nOnOFF);

	void NetCardDown(string p_sNetCardName);
	void PublishMessage2Client(string p_sMessage);
//	void UpdateClients(int p_nType, int p_nOnOFF);

	bool GetIsRequiredReg();
	void SetRequierdReg(bool p_bReg);
	void SetPaid(bool p_bPaid);
	bool GetIsPaid();
	CnetCard * GetnetCard(const string &p_sAdapterName);
	bool PrepairVerify(CVerifyer & p_V);

	void AddNetCard(std::string p_sDev,unsigned char * p_DevMac);
	void StopMonitorNetcard(string p_sNetCardName);

	 void OnNetCardNewLink(bool p_bUp, std::string p_sNetcardName,u_char *p_pMac);
   void OnNetCardNewAdd(std::string p_sNetcardName,u_int p_nIP,u_int p_nMask);
 	  void OnNetCardNewGate(std::string p_sNetcardName,u_int p_nGate);

 	 void Run();

 	virtual bool GetMyMac(char * p_sBuf);
 	virtual bool GetMacofDstIP(const DWORD & p_nIP,char * p_sBuf);

private:

 	 void SetComputerAgeRate(const MACADDR& p_Mac,const int& p_nAgeRate);

 	 void LoadIni();
 	 void SaveIni();
   // void SetIPOffGate(string p_sip,string p_sMac,string p_sName,bool p_bOff);

	bool m_bRequireReg;
	bool m_bPaidUser;
    string m_sWorkAdapterName;

	char m_sErrbuf[PCAP_ERRBUF_SIZE];  //less stack memory apply/release  256 byte
    std::map<std::string,CnetCard> m_netCards;
  //  CThreadWorker m_ThreadHandleLinkWatcher;
    CThreadWorker m_ThreadHandleUpdater;
   // CThreadWorker m_ThreadHandleVerify;

	CBlockArray<bool> m_VerifyRequest;

	MyLock m_lock; /* lock */
	CNetcutEvent  m_EventsQuit;

	int m_nRouteMsgFD;
	int m_nExitFD;
	string m_sLastKnownGPS;
	string m_sRealGPS;

};

#endif /* CPCAPCLASS_H_ */
