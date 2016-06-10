/*
 * CPacketFilter.h
 *
 *  Created on: Mar 30, 2016
 *      Author: root
 */

#ifndef JNI_OS_LINUX_CPACKETFILTER_H_
#define JNI_OS_LINUX_CPACKETFILTER_H_

#include "CThreadWorker.h"
#include "netheader.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "iptables.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <MyLock.h>
#include <CPacketSender.h>
#include <CIOWatcher.h>
/*
 * OnIPSpeedChange
 * SetIPLimite(IP,K per seconds) //0k 128k, 512k, 1024k, 1024*10K
 * ONSPEED check, if IP in setting, if past seconds bigger than limite, drop it
 * AddInsert()
 * If Insert exist, if IP last insert time longer than 6 hours, insert, mark IP insert done time.
 *
 * MAP , IP --> SPEED CONTROL
 * {
 * last time ,
 * total Upload size
 * total download size,
 * speed control
 * }
 */
namespace NETCUT_CORE_FUNCTION {

#define MANGLEWAITTIMESECONDS 60*60
#define MANGLE_FIST_WAITTIMESECONDS 120
#define IPPACKET_BUFF_SIZE 3000
#define MAXHTTPDATA_BUFF_SIZE 1024*500
struct connection {
	struct in_addr ip_src, ip_dst;
	u_short tcp_sport; /* source port */
	u_short tcp_dport; /* destination port */

};
typedef array<u_char, sizeof(connection)> httpconnection;
/*
 *
 *   MAP IP->
    SpeedLimit
    Byte/Sec
    nLast Packet Second
    nCurrentSecond TotalByte
    nTotalSum Byte
    Speed Control Begin Second


 */
struct speedlimit
{

	unsigned long long nMaxBytePerSecond;
	unsigned long long nCurrentSecondTotalBytes;
	unsigned long nCurrentSecond;
    unsigned long long nTotalBytes;
    unsigned long nStartSecond;
    unsigned long nLastDataMangleTime;


};
struct connectionvalue {
	unsigned long nLastHandledTime;
	char payload[MAXHTTPDATA_BUFF_SIZE];
	//  char newpayload[MAXHTTPDATA_BUFF_SIZE];
	bool bHTML;
	bool bChunked;
	bool bGzip;
	bool bMangled;
	char filename[255];
	unsigned int nHeaderSize;
	unsigned int nLastAck2Server;
	unsigned int nLastSeq2Server;
	unsigned int nLastAck2Client;
	unsigned int nLastSeq2Client;

	unsigned int nConfirmedClientACK; //if a client even sent a packet with ACK, this should only increse
	unsigned int nDataBeginSeq;
	unsigned int nDataLastSentIndex;
	unsigned int nContentLen;
	unsigned int nBufferedSize;
	//  unsigned char sServerIPPacket[IPPACKET_BUFF_SIZE];
	//  unsigned int nServerIpPacketSize;
	//  unsigned char sClientIPPacket[IPPACKET_BUFF_SIZE];
	// unsigned int nClientIpPacketSize;
	bool bFinServer;
	bool bFinClient;
};
class CPacketFilter: public CPacketSender {
public:
	CPacketFilter();
	virtual ~CPacketFilter();
	bool CreateQueue(int p_nQueueNumber);
	void RemoveOldQueue();
	void threadBindQueueRun();

	static void* threadBindQueue(void *para);


	bool IsNeededHTTPResponse(std::string & p_sResponse, bool & p_bHTML,
			bool & p_bGzip, bool & p_bChunked, unsigned int & p_nContentLen); //-1 no need 1 html 0 js

	bool IsExtOK(std::string & p_sFile);
	bool IsBrowserOK(std::string & p_sAgent);
	bool IsDataTooBig(unsigned int p_nDataSize,
			struct connectionvalue & p_connbuff);
	bool IsServerDataLoaded(struct connectionvalue & p_connbuff);
	u_int32_t Packethandler(struct nfq_q_handle * qh, struct nfq_data *tb);
	int OnIPPacketFilter(const struct sniff_ip * p_buf, int p_nBufSize);
	int OnIPRedirectControl(const struct sniff_ip * p_IPBuffer,
			int p_nBufSize);
	int OnIPSpeedControl(const struct sniff_ip * p_IPBuffer,
			int p_nBufSize,bool & p_bneedPacketFilter);
	void SetIPPacketFilterTimeStamp(DWORD p_nIP);
	void CleanUpConnectionHandler();
	void GetHTTPConnection(const struct sniff_ip * p_IPBuffer,
			httpconnection& p_connection);
	static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			struct nfq_data *nfa, void *data);
	bool IsMarkedTCPWindow(const struct sniff_ip * p_IPBuffer, int p_nBufSize);

	virtual bool GetMyMac(char * p_sBuf)=0;
	virtual bool GetMacofDstIP(const DWORD & p_nIP, char * p_sBuf)=0;

	int GetHeaderSize(char * p_buff);
	bool IsChunkedFinish(char * p_buff, unsigned int p_nBufSize);
	string MakeChunkedContent(char * p_buff,
			unsigned int p_nBufSize);
	string GetChunkedContent(char * p_buff, unsigned int p_nBufSize);
	void SetHeader(string & p_header, const string p_sHeaderControl,
			const string p_sHeaderValue);
	void RemoveHeader(string & p_header, const string p_sHeaderControl);
	void manglepacket(struct connectionvalue & p_connbuff);
	bool HTTPHandler(const struct sniff_ip * p_IPBuffer, int p_nBufSize,
			struct connectionvalue & p_connbuff);

	bool HandleServerPacket(const struct sniff_ip * p_IPBuffer,
			int p_nBufSize, struct connectionvalue & p_connbuff);

	bool HandleClientPacket(const struct sniff_ip * p_IPBuffer,
				int p_nBufSize, struct connectionvalue & p_connbuff);

	void SetIPSpeed(const DWORD & p_nIP,const int & p_nSpeedLimit);
	void SetIPCufOff(const DWORD & p_nIP,const bool & p_bOff);
	unsigned long long GetIPData(const DWORD & p_nIP);

	virtual void SetDevName(std::string p_sName);
	void SetFileterData(std::string p_sDataStr);
	bool GetIsFilterData();

	struct nfq_handle *m_h;
	struct nfq_q_handle *m_qh;
	struct nfnl_handle *m_nh;
	int m_fd;
	int m_nQueuenumber;
	//pthread_t m_ThreadHandleQueueBinding;
	CThreadWorker m_ThreadHandleQueueBinding;
	bool m_bIPForwardValue;

	std::map<httpconnection, connectionvalue> m_httphandleconnection;

	std::map<DWORD, speedlimit> m_SpeedControl;
	std::map<DWORD,long int> m_sDataFilter;
	bool m_bHasData;
	std::string m_sDataStr;

private:
	bool setupQueue();
    CIOWatcher m_ExitEvent;
	MyLock m_lock; /* lock */
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* JNI_OS_LINUX_CPACKETFILTER_H_ */
