/*
 * CAddressHelper.h
 *
 *  Created on: Jan 9, 2015
 *      Author: root
 */

#ifndef CADDRESSHELPER_H_
#define CADDRESSHELPER_H_
#include "netheader.h"
#include "CNbtQuery.h"
#include "net/if_arp.h"
#include "md5/md5.h"

#include "CKey.h"

#define ARP_HRD_ETH 	0x0001	/* ethernet hardware */
#define ARP_HRD_IEEE802	0x0006	/* IEEE 802 hardware */

/*
 * Protocol address format
 */
#define ARP_PRO_IP	0x0800	/* IP protocol */

/*
 * ARP operation
 */
#define	ARP_OP_REQUEST		1	/* request to resolve ha given pa */
#define	ARP_OP_REPLY		2	/* response giving hardware address */
#define	ARP_OP_REVREQUEST	3	/* request to resolve pa given ha */
#define	ARP_OP_REVREPLY		4	/* response giving protocol address */



class CAddressHelper {
public:
	CAddressHelper();
	virtual ~CAddressHelper();

static string getAppPath();
static string getMyPath();
static string getMyCmdlineArgv();
static list<int> getPids(const char* name);
static list<int> getPids2(const char* name);

static string readFile2(const string &fileName);
static string GetCPUFamily();
static string GetNetcutName();
static	bool isSameRang(DWORD p_n1,DWORD p_n2,DWORD p_nMask);
static  bool isSameRang(std::string& p_s1,std::string& p_s2,std::string& p_sMask);
static  std::string IntIP2str(const DWORD& p_nIP); //translate byte into string
static  DWORD BufferIP2Int(const u_char* p_Buf); //translate networkbuffer into DWORD
static  std::string BufferIP2str(const u_char* p_Buf); //translate networkbuffer into string
static std::string BufferMac2str(const u_char * p_Buf);
static MACADDR StrMac2Array(string p_sMacStr);
static DWORD StrIP2Int(const std::string& p_sIP);
static DWORD AddrIP2Int(in_addr & p_nAdd);
static void  GetIpRang(const DWORD &p_nIP,const DWORD &p_nMask,DWORD & p_startIP, DWORD &p_EndIP);
static DWORD GetMaskSize(const DWORD &p_nMask);
static DWORD GetTotalIPNumber(const DWORD & p_startIP,const DWORD &p_EndIP);
static DWORD GetNextIP(DWORD p_nUIP);
static void GetRandomMac(u_char *buff);
static string Gen_random_str(const int len);
static DWORD GetRandomIP();
//static void GetNamebyIP(DWORD p_nIP);
//static void GetNamebyIP(string & p_sIP);
static bool isBrocastIP(DWORD p_nIP);
static bool isStringIP(string & p_sStr,DWORD & p_nIP);
static DWORD GetIPFromString(string & p_str);
static bool isEmptyMac(const unsigned char *p_macbuf);
static bool isBrocastMAC(const u_char * p_sBuf);
static bool GetDevInfo(string &p_sDevName,AdapterInfo & p_AdapterInfo);
static bool IsDevOn(string p_sDevName);
static bool GetDevGateWay(string &p_sDevName,std::map<DWORD,Address> & p_Gateways,DWORD p_nMask);
static bool GetDevGateIP(string &p_sDevName,DWORD & p_nGateIP);
static bool GetInterfaceName(int if_index,char *ifName);
static bool IsInterfaceUp(string p_sIfName);
static bool GetInterfaceMac(string p_sIfName,unsigned char * p_macbuff); //DO NOT USE THIS, NOT WORKING ON ANDROID OS 6 , API 23 , require ROOT
static bool GetInterfaceIP(string p_sIfName,DWORD & p_nIP);
static bool GetNetCards(list<AdapterInfo> & p_AdapterList);
static void GetBrocastMac(u_char * p_buf);
static array<u_char,6>  GetBrocastMac();
static void GetMCastMac(DWORD p_nDstIP,u_char * p_buf);
static void GetEmptyMac(u_char * p_buf);
static void Remove_ArpEntry(DWORD p_nIP);
static void Add_ArpEntry(DWORD p_nIP,const u_char * p_sMac,string p_sDevName);

static DWORD MakeNetcutSignIP(const string& p_sMac);
static string GetMacBrand(const u_char * p_sbuff);
static array<u_char,6> MacBuffer2Array(const u_char * p_buf);
static bool   IsRunningAsRoot();
static map<DWORD,MACADDR> GetARPCache(string p_sDevName);
static DWORD GetDNS_inaddr(string p_sName);
static string GetDNS_inaddr(DWORD p_nIP);
static string GetDNS_PTRname(string p_sName);
static string GetDNS_TXTDeviceInfo(string p_sName);

static bool ChangeMacAddress(const string p_sDevName,const u_char * p_NewBuf);
static u_char m_macBrocast[6];
static u_char m_macMCast[6];
static u_char m_macEmpty[6];

static std::string GetAccountDetails();
static void SaveAccountDetails(std::string p_sContent);
static void loadMac2BrandMap();

static DWORD n224;
static DWORD n239;
static DWORD nmask;
static DWORD cmask;
static DWORD bmask;
static map<string,string> m_Mac2Brand;
static string m_sMyPath;
static string m_sMyCmdLine;
static char * * m_argv;

};

#endif
