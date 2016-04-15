/*
 * CComputer.h
 *
 *  Created on: Jan 12, 2015
 *      Author: root
 */

#ifndef CCOMPUTER_H_
#define CCOMPUTER_H_
#include "netheader.h"
#include <list>
#include "CAddressHelper.h"
#include "CGrounded.h"
#define IP_SPACER " "


#define TIMEOUT_OVERCOME_ATTACK 10*1000  //
#define SAYNETCUT_FLAG_SIGN 35*1000
#define TIMEOUT_FLAG_SIGN 120*1000


using namespace std;

class CComputer: public CGrounded {
public:
	CComputer();
	virtual ~CComputer();
	CComputer& operator=( const CComputer& other );
	CComputer& operator=( const CGrounded& other );
	bool IsSame(const CComputer& other);

	bool operator == (const CComputer& d);


//	CComputer& operator=( const Address& other );
	CComputer( const CComputer& other);
	void AddIP(const DWORD &p_nIP);
//	void RemoveIP(DWORD p_nIP=0);
	void GetIPs(std::map <DWORD,bool> &p_Ips);
	string GetIPs();
	void GetIPs(netcardEvent &p_Events);
	bool IsMyIP(DWORD p_nIP);
	bool IsSameRange(DWORD p_nIP);
	bool IsMyIP(string  p_sIP);
	bool IsMyIP(std::map <DWORD,bool> p_Ips);
	bool IsMyMac(const u_char * p_sBuf);
	bool IsMyMac(const MACADDR&  p_sMac);
	bool IsMyMac(const std::string & p_sMacName);
	bool IsMyName(const std::string & p_sName);

	void SetMac(const unsigned char * p_sBuf);
	void GetMac(unsigned char *p_sBuf);
	array<u_char,6>  GetMacArray();

	const u_char * GetMac();
	string GetMacStr();
	bool SetName(const std::string & p_sName);
	std::string GetName();
	void SetBrand(const std::string &p_sBrand);
	std::string GetBrand();
	void SetAgeRate(int p_nAgeRate);
	int GetAgeRate();
	void SetOff(bool p_Off);
    bool IsOff();
	void SetSpeedLimit(int p_nLimitRank);//0, no limit, 1, 20mb, 3 xxx
	int GetSpeedLimit();
    bool IsSpeedLimit();
    bool IsSetOff();

    void FlagAsAttacker();
    bool IsAttacker();
    void FlagAsNetCutDefender(bool p_bIsDefender=true);
    bool IsNetCutDefender();
    DWORD GetMask();
    bool HasMac();
    time_t GetUpdateTime();
    time_t GetDiscoverTime();
    void SetMask(DWORD p_nMask);
    void SetHasMac();
    void SetUpdateTime(time_t p_nTime);
    void SetDiscoverTime(time_t p_nTime);
    void  SetGateWay(bool p_bGateway);
    bool IsGateway();
    void SetIsMySelf(bool p_bIsMyself);
    bool IsMyself();
/*

    	bool IsGrounded();
       bool HasGroundedSetting();
       void SetGround(int p_nType,int p_nStartHour, int p_nStartMin,int p_nEndHour,int p_nEndMin);
       void RemoveGround(int p_nType);
       void GetGroundInfo(int p_nType,int& p_nStartHour, int& p_nStartMin,int& p_nEndHour,int& p_nEndMin);
*/
private:
    void ReadIPstoStr();
    //recursive_timed_mutex m_lock; /* lock */
    recursive_mutex m_lock;
	//std::list <DWORD> m_IPs;
    std::map <DWORD,bool> m_IPs;  // Map IP to Netcut Flag
   // DWORD m_IP;
    u_char m_sMac[6];
    string m_sMacStr;
    string m_sIps;
    std::string m_sName;
    std::string m_sBrand;
    bool m_bOff;
    int  m_nSpeedLimit; //0, no limit, 1, 20mb, 2, 1mb, 3, 128k, 4, 16k 5 2k
    bool m_bAttacker;
    bool m_bNetCut;

    bool m_bIsGateWay;
    bool m_bIsMySelf;
    int m_nAgeRate; //Age rate from 0 to 10, 7 above is normal user, 0 is new user.



	DWORD m_Mask;
	bool m_bHasMac;
	time_t m_nUpdateTime;
	time_t m_nLastNetworkDiscoverTime;

	unsigned long m_nLastNetCutSignTime;
	unsigned long m_nLastAttackerSignTime;

};

#endif /* CCOMPUTER_H_ */
