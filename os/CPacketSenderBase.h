/*
 * CPacketSenderBase.h
 *
 *  Created on: Dec 21, 2015
 *      Author: victor
 */

#ifndef OS_CPACKETSENDERBASE_H_
#define OS_CPACKETSENDERBASE_H_
#include "CNetcutTool.h"
#include "sys/types.h"
#include "stdint.h"
#include <string>


#define T_A     1       /* host address */
#define T_NS        2       /* authoritative server */
#define T_MD        3       /* mail destination */
#define T_MF        4       /* mail forwarder */
#define T_CNAME     5       /* connonical name */
#define T_SOA       6       /* start of authority zone */
#define T_MB        7       /* mailbox domain name */
#define T_MG        8       /* mail group member */
#define T_MR        9       /* mail rename name */
#define T_NULL      10      /* null resource record */
#define T_WKS       11      /* well known service */
#define T_PTR       12      /* domain name pointer */
#define T_HINFO     13      /* host information */
#define T_MINFO     14      /* mailbox information */
#define T_MX        15      /* mail routing information */
#define T_TXT       16

struct DNS_HEADER {
	unsigned short id;			// identification number

	unsigned char rd :1;	// recursion desired
	unsigned char tc :1;	// truncated message
	unsigned char aa :1;	// authoritive answer
	unsigned char opcode :4;	// purpose of message
	unsigned char qr :1;	// query/response flag

	unsigned char rcode :4;	// response code
	unsigned char cd :1;	// checking disabled
	unsigned char ad :1;	// authenticated data
	unsigned char z :1;	// its z! reserved
	unsigned char ra :1;	// recursion available

	unsigned short q_count;		// number of question entries
	unsigned short ans_count;		// number of answer entries
	unsigned short auth_count;		// number of authority entries
	unsigned short add_count;		// number of resource entries
};

//Constant sized fields of query structure
struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA {
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD {
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

// Structure of a Query
typedef struct {
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;


namespace NETCUT_CORE_FUNCTION {

class CPacketSenderBase {
public:
	CPacketSenderBase();
	virtual ~CPacketSenderBase();
virtual bool sendArp(const DWORD &p_DstIP, const DWORD &p_SrcIp,
		const u_char *p_sDstMac, const u_char *p_sSrcMac,
		const u_char *p_sEtherDstMac, const u_char * p_sEtherSrcMac,
		const uint16_t p_nRequesttype)=0;

void SetDevName(std::string p_sName);


protected:
   std::string m_sDevName;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_CPACKETSENDERBASE_H_ */
