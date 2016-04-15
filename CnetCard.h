/*
 * CnetCard.h
 *
 *  Created on: Jun 12, 2014
 *      Author: victor
 */

#ifndef CNETCARD_H_
#define CNETCARD_H_
#include <CBlockArray.h>
#include <CMyLock.h>
#include <MyLock.h>
#include <PointerQueue.h>
#include <stdlib.h>

#include <CIPCMessageObjectFactory.h>
#include "netheader.h"
#include "CPacketBase.h"
#include <list>
#include <map>
#include "CAddressHelper.h"
#include "CComputer.h"
#include "CBlackList.h"
#include <functional>
#include "netfilterqueue.h"
#include <tins/tins.h>
#include "CGrounded.h"
#include "CThreadWorker.h"
#include <CPacketReader.h>
#include <CPacketSender.h>


using namespace Tins;
using namespace NETCUT_CORE_FUNCTION;

#define MAXQUERYAGEMISECONDS  60*1000
#define MAX_TAKEIP_WAIT_SECONDS  5*1000
#define MINIMALTIMEGAPNETWORKDISCOVER 60
#define TIMEGAPBETWEENSLOWSCAN 1
#define WAITEXPIRE_TIMER 3*1000
#define CONNECTIONTESTHOSTNAME "www.google.com"

using namespace neosmart;



//int (*ptrFunc)(int,int);


//class CnetCard : public netfilterqueue {
class CnetCard :public CPacketReader, public CPacketSender {
//class CnetCard {

	//Mac,IP,ComputerName,
	enum TEST_ACTION
	{
		DIRECTTEST=0,
		NATTEST=1,
		NATTESTOK=2,
		NOMORETEST=3,
	};
	enum ConnectMeStatus
	{
		STOP=0,
		START=1,
		TESTING_DIRECT=2,
		TESTING_SPAREIP=3,
		TESTING_TAKEIP=4,
		ONLINE=5,
		FAILED=6,
	};



struct CONNECTTEST {
	DWORD nIP;
	DWORD nSrcIP;
	uint16_t nport;
	uint32_t nACKNumber;
	unsigned long nPacketTimeStampe;
    int nNextAction;  //EnableNAT, DISABLENAT
};

struct DiscoverTask
{
	DWORD nIP;
	MACADDR MAC;
	bool  bSingleIP;
	bool  bNoIPQuery;
};
struct Mac2Name
{
	string sName;
	DWORD bFixed;

};
public:

	void RegisterNetworkHandle(callback p_Handle,void * p_Parent);

/*	static void* CallBackEvent(void *para,void *p_parent);
    void CallBackEventRun(netBiosPacket * p_Event);
*/

	CnetCard();
	CnetCard& operator=( const CnetCard& other );
	CnetCard( const CnetCard& other);
	virtual ~CnetCard();

	void initNetCard();

    void SetComputerAgeRate(const MACADDR& p_Mac,const int& p_nAgeRate);

	//void TestConnection();
	bool GetIsSlowSCan();
	bool GetIsRoot();
	void setDevName(const string &p_sName,const u_char * p_macBuf);
	std::string getDevName();
	string GetMacID();

	string GetMyMac();
	string GetMyGateMac();
	string GetAllUserMac();

	void getMac(u_char *p_sBuf);
	bool getMacforIP(const DWORD & p_nIP,u_char *p_sBuf);
	void MakeArpSrcMac(u_char *p_sBuf);
	bool IsMyNetwork(const DWORD &p_nIP);
	bool IsMyIP(const DWORD &p_nNewIP);
	bool IsMyMac(const MACADDR & p_Mac);
	bool IsGateWayPacket(const MACADDR & p_Mac,DWORD p_nIP);
	bool IsGateWayMac(const MACADDR & p_Mac);
	bool IsMyGateIP(const DWORD &p_nNewIP);
	bool IsUp();
    void SetComputerOnOff(const netcardClientEvent * p_nEvent);
    void SetComputerOnOff(u_char * p_sMacBuf,bool p_bOff);
    void OnClientEvent(const netcardClientEvent * p_nEvent);
    void OnClientMessage(const CIPCMessage * p_Message);
    void SetComputerSpeed(u_char * p_sMacBuf,int p_nLimit);
    bool IsNewRangeIP(const DWORD &p_nIP);

    void GetIPsofMac(u_char *p_sBuf,std::map <DWORD,bool> &p_Ips);
	void AddmyIPAddress(Address& p_newIP);
	void AddmyGateWay(int32_t p_newGate);

	void SetMac2GateWay(const MACADDR & p_Addr);

	void RemoveMac2GateWay(MACADDR & p_Addr);
	void GetComputerMap(std::map<DWORD,CComputer>& p_Computers);
	void GetMyIP(std::map<DWORD,Address>& p_IPs);
	DWORD GetMyIP();
	DWORD GetMyMask();
	void GetMyGate(std::map<MACADDR,CComputer>& p_Gates);
    void showDetails();
    void SetNeedSniffAdapter();
    void SetProtection(bool p_bOn);
   // void SetConnectMe(ConnectMeStatus p_nConnectMe);
    int GetConnectMeStatus();

    bool SendDhcp();
   // bool SendNetbiosQuery(const MACADDR & p_TargetMac,DWORD p_nsIP,DWORD p_ndIP);
    //bool SendMDNSQuery(string p_sQuery,int p_nType) ;
    bool SendDhcpOffer();
 /*   bool sendArp(const DWORD &p_DstIP, const DWORD &p_SrcIp,
    		const u_char *p_sDstMac,const u_char *p_sSrcMac, const u_char *p_sEtherDstMac,
    		const u_char * p_sEtherSrcMac,const uint16_t p_nRequesttype); //ARPOP_REPLY
    		*/

    bool SendArpWrapper(const DWORD &p_DstIP, const DWORD &p_SrcIp,
    		const u_char *p_sDstMac, const u_char *p_sSrcMac,const u_char *p_sEtherDstMac,
    		const u_char * p_sEtherSrcMac,const uint16_t p_nRequesttype);
    void ReplyQuery(const CPacketBase & packet,CComputer * p_Computer);
 //   bool sendArp(DWORD &p_DstIP, DWORD &p_SrcIp, u_char *p_sDstMac=0,
  //  		u_char *p_sSrcMac=0, u_char *p_sEtherDstMac=0, u_char * p_sEtherSrcMac=0,
   // 		uint16_t p_nRequesttype=ARPOP_REQUEST);
    //void On2Off();

    virtual void Off2On();
    bool IsRecentQuery(const DWORD & p_IP,int p_nMyIP,u_char * p_buf);
    void AddQueryHistory(const DWORD & p_IP,int p_nMyIP,u_char * p_targetbuf);

    bool ArpQueryIP(const DWORD & p_IP,u_char * p_buf=0);
    bool QueryIP(const DWORD & p_IP,u_char * p_buf=0);
    //        void AddnewComputer(const u_char *p_buf,DWORD & p_nIP);
    void AddnewComputer(const MACADDR & macarray, const DWORD & p_nIP);
   void CleanUpARPQueryHistory(); //Take none response IP here
   void OnComputerUpdate(CComputer & p_Computer,int p_nType=NETCARDEVENT_NEWCOMPUTERINFO);
   void UpdateClient(int p_nMessageType,void * p_data,int p_nSize);
   void OnComputerGroundedUpdate(CComputer & p_Computer);
   void UpdateClients(int p_nType,int p_nOnOFF);
   void UpdateClients(const string & p_sMessage);
   void UpdateStatus(const string &p_sMessage);
   unsigned long GetLastStatusUpdateTime();
   void RenewStatusUpdateTime();
   void ShowALLComputers();
   bool DemandDisCoverNetwork();

   void AddDisCoverIP(const DWORD & p_nIP);
   void ClearAllComputer();
   void SetCutMethod(int p_nCutOffMethod);//0 cut both, 1, only gateway, 2, only target

   void EnableFakeMac(bool p_bEnableFakeMac);
   void EnableSlowScan(bool p_bEnableFakeMac);
   void ShowCutMethod();
   void MessageINT_Value(int p_nINTID,int p_nValue);
   void FixMac2Name(const MACADDR & p_mac, string p_sName);
          void AddMac2Name(const MACADDR & p_mac,string p_sName);
          string QueryMac2Name(const MACADDR & mac);
          CComputer * GetComputerByIP(const DWORD &p_nIP);

protected:
 /*  static void *threadTest(void * para);
   void threadTestRun();
        static void* threadSniffer(void *para);
    	void threadSnifferRun();

    	void threadTinsSnifferRun();

    	static	void threadGot_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
   		void threadGot_packetRun(const struct pcap_pkthdr *header, const u_char *packet);

   		static void* threadPacketWorker(void *para);
   		void threadPacketWorkerRun();

  		static void* threadConnectMe(void *para);
   		 void threadConnectMeRun();
   */
        static void* threadMakeSureOnOffWorker(void *para);
   		void threadMakeSureOnOffWorkerRun();

   		static void* threadMakeSureMeLive(void *para);
   		   		void threadMakeSureMeLiveRun();




   		static void* threadComputerInfoWorker(void *para);
   		void threadComputerInfoWorkerRun();

   		static void* threadGroundedWorker(void *para);
   	   		void threadGroundedWorkerRun();

   		static void* threadArpCacheReader(void *para);
   		   		void threadArpCacheReaderRun();


   	//	bool CallbackGotPdu(const PDU &pdu);

   static DWORD m_nMyFakeIP;
   static char m_sMyMac[6];
   static char m_sGateMac[6];


private:


        void SendDiscover();
        bool GetIsBeenAttack();
        void SetAttack();
   		DWORD GetNextAvaiableIP(DWORD & p_nIP);
   		//bool InitSendAdapter();

   //     void ClearSendAdapter(libnet_t *  p_LibnetHandle);
        bool IsKnownIP(const DWORD &p_nIP);
        bool IsKnownNode(const MACADDR & macarray,const DWORD &p_nIP);
        bool IsKnownNode(const u_char * p_sbuf, const DWORD &p_nIP);
        bool IsKnownNode(const CPacketBase &p_Packet);


        void SaveMacNodeName();
        void LoadMacNodeNames();
        void SaveBlackList();
        void SaveCutOffMethod();

        void LoadCutOffMethod();
        void LoadBlackList();
        void LoadGroundedSetting();
        void SaveGroundedSetting();

        void RemoveFromBlacklist(CComputer &p_Computer);
        void DiscoverNetwork();
        void DiscoverNetwork(const DWORD & p_nIP);


       // void MakeSureOffOn(CComputer &p_Computer,int p_nArpOP=ARPOP_REQUEST,int p_nRepeatPacket=1);
        void MakeSureOffOn(CComputer &p_Computer);
        void SetComputerOnOff(CComputer &p_Computer,bool p_bOff=true);

        int GetCutMethod();
        void OnCutoffMethodUpdate();
        void MakeSureoffAll();
        void SayIAmNetCut();
        void GetFakeMac(u_char *buff);
        //void OnIPPacket(u_char *packet,uint32_t p_nPacketLen);


        void AddIP2Query(const CPacketBase & p_Packet);
       // bool IsIPOff(DWORD p_nIP);
        bool IsMacOff(u_char * p_sBuf);
       // void ProcessForward(u_char *packet,uint32_t p_nPacketLen);
        void OnArpPacket(const CPacketBase & packet);
        void OnDHCPPacket(const CPacketBase & packet);
        void OnNetBiosPacket(const CPacketBase & packet);
        void OnMDNSPacket(const CPacketBase & packet);

        void OnTCPPacket(const CPacketBase & packet);
        void OnIPPacket(const CPacketBase & packet);

        void NewComputerProcess(const CPacketBase & packet);
        void MakesureOffOnProcess(const CPacketBase & packet);
        void DefenderProcess(const CPacketBase & packet);
        void ProcessTakeIP(const CPacketBase & packet);
        void DetectNetcutDefender(const CPacketBase & packet);







        unsigned short GetIPTransID(const DWORD & p_nIP);
        void SetIPTRansID(const DWORD & p_nIP,unsigned short p_nID);

       //void SetComputerName(DWORD p_nIP,string p_sName);
       void SetComputerName(MACADDR p_Mac, string p_sName);


       void TakeIP(DWORD p_nIP);
       DWORD GetTakeIP();


    std::string  m_sDevName; //dev name
    string m_sHostname;
    u_char m_sMac[6];  //Mac address
    MACADDR m_MACADD;
    MACADDR m_MACGateMac;
    DWORD m_nMask;
    DWORD m_nMyIP;
    DWORD m_nDefaultGateWayIP;
    std::string m_sMacString;

    DWORD m_nTakeIP;
    std::map<DWORD,Address> m_IPs;
   // std::map<DWORD,Address> m_Gateways;

    bool m_bIPFORWARDSystemValue;
    int32_t m_bCutOffMethod;


    std::map<DWORD,Address> m_queryHistory;
    std::map<DWORD,Address> m_queryNetworkHistory;
    std::map<DWORD,unsigned short> m_QueryHistoryID;

    std::map<MACADDR,Mac2Name> m_Name2MacList;


    std::map<MACADDR,CBlackList> m_Blacklist2;
    std::map<MACADDR,CComputer> m_computers;
    std::map<MACADDR,CGrounded> m_GroundSetting;
    std::map<DWORD,MACADDR> m_ip2mac;
    std::map<DWORD,DWORD> m_GatewayIPMap;

    list<DWORD> m_DiscoverWorkList;
    networkcallback m_CallNetworkHandle;

    bool m_bUp;
    bool m_bWorkOn;
    bool m_bRunAsRoot;




private:
       CNetcutEvent  m_EventsTakeIP;
       CNetcutEvent  m_EventsQuit;

       CNetcutEvent  m_EventsScanSent;

       CMyLock m_lock; /* lock */

       CONNECTTEST m_ConnectTest;



	 CThreadWorker m_OnOffworkerThread;
	 CThreadWorker m_InfoworkerThread;
	 CThreadWorker m_GroundThread;
	 CThreadWorker m_MakeSureMeLiveThread;
	 CThreadWorker m_ConnectMeThread;
	 CThreadWorker m_ArpCacheReaderThread;



//	PointerQueue<sniffitem *> m_sniffqueue;
	CBlockArray<DiscoverTask> m_DiscoverFinnalArray;

	unsigned long m_nLastBeenAttackTime;
	unsigned long m_nLastLibNetWriteTime;
	unsigned long m_nLastDisCoverNetworkTime;
	unsigned long m_nLastStatusTime;
	bool m_bProtection;
	bool m_bFakeMac;
	bool m_bSlowScan;
	int m_nCutoffMethod;
	bool m_bConnectMe;
	ConnectMeStatus m_nConnectMeRequest;

	char m_sErrbuf[PCAP_ERRBUF_SIZE];  //less stack memory apply/release  256 byte

//	libnet_t * m_LibnetHandle;/*****libnet handler*/
//	pcap_t * m_PcapHandle;
	CNbtQuery m_UDPSender;

};

#endif /* CNETCARD_H_ */
