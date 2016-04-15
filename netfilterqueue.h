/*
 * netfilterqueue.h
 *
 *  Created on: Feb 20, 2015
 *      Author: root
 */

#ifndef NETFILTERQUEUE_H_
#define NETFILTERQUEUE_H_

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

typedef void* (*RuleCallfunc)(char *,int ,u_int32_t & ,unsigned char * & ,void *);

struct filterrules {
  //  bool bInBound;
    DWORD nSrcIP;
    DWORD nDstIP;
   // int nProtocal;
    int nSrcPort;
    int nDstPort;
    RuleCallfunc rulecall;
    int nPacketaction;
};

class netfilterqueue {

public:
	enum RULETYPE
	{
	      DROP = 0x0001,
		  NAT=0x0002,
		  TEST   = 0x0003
	};
	netfilterqueue();
	virtual ~netfilterqueue();

	static void* threadBindQueue(void *para);
    void threadBindQueueRun();

    bool CreateQueue(int p_nQueueNumber);
    void RemoveOldQueue();
	bool BindQueue(string p_sDevName,int p_nQueueNumber);
    void SetFilterRule(filterrules  p_nTarget,int p_nRule);
    void DisableNAT();
    void SetNAT(const DWORD & p_nMyIP,const DWORD & p_nMask,const DWORD & p_nNATIP,const DWORD & p_nGateIP);
    void CleanNAT();
    void SetDrop(const DWORD & p_nDropIP);
//u_int32_t Packethandler (struct nfq_data *tb);
u_int32_t Packethandler(struct nfq_q_handle * qh,struct nfq_data *tb);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data);


static void* Rule1(char * p_buf,int p_nBufSize,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf,void *data);
virtual void OnRule1Run(char * p_buf,int p_nBufSize,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf);

static void* RuleNAT(char * p_buf,int p_nBufSize,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf,void *data);
virtual void OnRuleNATRun(char * p_buf,int p_nBufSize,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf);

static void* RuleDummy(char * p_buf,int p_nBufSize,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf,void *data);

private:
bool InitLibnet();
bool IsMatchRule(filterrules & p_Rule,filterrules & p_Packet);
virtual int OnIPPacketFilter(struct nfq_q_handle * qh,int id, char * p_buf,int p_nBufSize);
//virtual void OnIPPacketFilter(char * p_buf,int p_nBufSize,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf);
virtual void OnTCPPacketFilter(char * p_buf,int p_nBufSize,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf);


//virtual void OnRule1(char * p_buf,bool p_bInput,u_int32_t & p_nPacketLen,unsigned char * & p_packetbuf);

int m_nQueuenumber;

pthread_t m_ThreadHandleQueueBinding;


string m_sDevName;
char  m_sErrbuf[255];
std::list<filterrules> m_FilterRules;
DWORD m_nMyIP;
DWORD m_nMyMask;
DWORD m_nGatewayIP;
DWORD m_nNATIP;
bool m_bIPFORWARDSystemValue;


MyLock m_lock; /* lock */

protected:
bool m_bIpTableExist;
bool m_bEnableNAT;

struct nfq_handle *m_h;
struct nfq_q_handle *m_qh;
struct nfnl_handle *m_nh;

};

#endif /* NETFILTERQUEUE_H_ */
