/*
 * netheader.h
 *
 *  Created on: Jun 12, 2014
 *      Author: victor
 */

#ifndef NETHEADER_H_
#define NETHEADER_H_
#define __cplusplus 201103L

#define ANDROID_NETCUTVERSION "15"


#include <time.h>
#include <mutex>
#include <list>
#include <map>
#include <array>


//#include <pthread.h>
//#include <semaphore.h>
//#include "pevents.h"

#include "CNetcutTool.h"

#include <stdio.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>
//#include <pcap.h>

#include <stdarg.h>  // for va_start, etc
#include <memory>    // for std::unique_ptr
#include <algorithm>
#include <stdexcept>


#include <pthread.h>

#include <iostream>
#include <fstream>


#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
//#include <linux/if.h>

#define IFF_LOWER_UP	0x10000		/* driver signals L1 up		*/

//#include <bits/sockaddr.h>
#include <asm/types.h>

#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>



#include "decode.h"
#include "trace.h"

/* default snap length (maximum bytes per packet to capture) */
#define MAXPACKET_LEN 1518
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

#define IFLIST_REPLY_BUFFER	8192



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN MAXPACKET_LEN
#define SNIFF_BUFFER_SIZE 1024*1024*2

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[6]; /* destination host address */
	u_char ether_shost[6]; /* source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl; /* version << 4 | header length >> 2 */
	u_char ip_tos; /* type of service */
	u_short ip_len; /* total length */
	u_short ip_id; /* identification */
	u_short ip_off; /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char ip_ttl; /* time to live */
	u_char ip_p; /* protocol */
	u_short ip_sum; /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	tcp_seq th_seq; /* sequence number */
	tcp_seq th_ack; /* acknowledgement number */
	u_char th_offx2; /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};

typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1:3; //according to rfc
	unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin :1; //Finish Flag
	unsigned char syn :1; //Synchronise Flag
	unsigned char rst :1; //Reset Flag
	unsigned char psh :1; //Push Flag
	unsigned char ack :1; //Acknowledgement Flag
	unsigned char urg :1; //Urgent Flag

	unsigned char ecn :1; //ECN-Echo Flag
	unsigned char cwr :1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

struct dhcp {
	unsigned char	op;		/* packet opcode type */
	unsigned char	htype;		/* hardware addr type */
	unsigned char	hlen;		/* hardware addr length */
	unsigned char	hops;		/* gateway hops */
	unsigned int	xid;		/* transaction ID */
	unsigned short	secs;		/* seconds since boot began */
	unsigned short	flags;		/* flags */
	unsigned int	ciaddr;		/* client IP address */
	unsigned int	yiaddr;		/* 'your' IP address */
	unsigned int	siaddr;		/* server IP address */
	unsigned int	giaddr;		/* gateway IP address */
	unsigned char	chaddr[16];	/* client hardware address */
	unsigned char	sname[64];	/* server host name */
	unsigned char	file[128];	/* boot file name */
	unsigned char	options[312];	/* options area */
};


typedef struct adapter
{
	adapter * next;
	std::string sName;
	int nIndex;
	bool bUp;
    in_addr DefGateWay;

}adapter;
using namespace std;

void exit_handler(int s);
void exit_cleanup();

in_addr_t _helper_NextIP(const in_addr_t & p_nAddrIP);

std::string _helper_string_format(const std::string fmt_str, ...);
void  _helper_getrouteinfo(adapter * p_adapter);
adapter * _helper_rtnl_print_link(struct nlmsghdr *h);
adapter * _helper_get_link();
void _helper_freeadapter(adapter *p_adapter);
std::string _helper_Mac_buff2Str(const u_char * p_sbuff);

std::string _helper_IP_buffer2Str(const u_char * p_sbuff);
std::string _helper_GetHexCode(char *p_Buf,int p_nSize);
void _helper_GetAdapterMac(const u_char * p_sDev,u_char * p_sMacBuff);
std::string _helper_net_host(int m);
std::string _helper_strtail(std::string const& source, size_t const length);
string _helper_Hex2Buffer(string p_sHexStr);

std::vector<std::string> _helper_splitstring(std::string p_sString,std::string p_sToken);
std::vector<string> _helper_splitstring_pair(string p_sString,string p_sToken);
void _helper_replacestring(string& p_sStr,const string& p_sFind,const string& p_sReplace);
void _helper_removestring(string& p_sStr,const string& p_sFind);

std::string string_to_hex(const std::string& input);
std::string hex_to_string(const std::string& input);
bool strreplace(std::string& p_s,std::string p_spattern,std::string p_sReplacestr);
bool getrequesturl(std::string & p_sBuf,std::string & p_sUrl);
bool getrequestext(std::string & p_sBuf,std::string & p_sExt);
bool getrequestapp(std::string & p_sBuf,std::string & p_sApp);


typedef array<u_char,6> MACADDR;


struct Address {
	DWORD Ip;
	DWORD Mask;
	u_char buff[6];
	string computername;
	bool bHasMac;
	bool bDefaultGateway;
	unsigned long nUpdateTime;
	unsigned long nLastNetworkDiscoverTime;

} ;

struct AdapterInfo
{

	std::map<DWORD,Address> IPs;
	std::map<DWORD,Address> Gateways;
	u_char Mac[6];
	MACADDR macarray;
	string hostname;
	bool bUp;

};

typedef void (*callback)(void *,void *);
struct networkcallback
{
	callback Handler;
	void * HandlerParentPointer;

};




#define BLACKLISTFILE "blacklist"
#define GROUNDEDFILE "schedule"
#define CUTOFFMETHODFILE "method"
#define NETCARDNAME "device"
#define MACNODENAMELIST "mac2nodename"
#define MACBRANDFILE "macdata"

//nEventClass
#define NETCARDCLASS_NEWCOMPUTERINFO 1
#define NETCARDCLASS_NEWGATEWAYINFO 2   // When Event Type = 2, bOff == add or remove
#define NETCARDCLASS_NETWORKDOWN 3
#define NETCARDCLASS_COMPUTERONOFF 4
#define NETCARDCLASS_DEFENDERINFO 5
#define NETCARDCLASS_SCANNETWORK 6
#define NETCARDCLASS_MESSAGE2CLIENT 7
#define NETCARDCLASS_SET_NODE_NAME 8
#define NETCARDCLASS_CONNECTMEINFO 9
#define NETCARDCLASS_REQUIREREG 10
#define NETCARDCLASS_GROUNDINFO 11
#define NETCARDCLASS_PID 12  //Old methods

#define NETCARDCLASS_CUTOFFMETHOD 13 //new strucuts


#define NETCARDEVENT_NEWCOMPUTERINFO 1
#define NETCARDEVENT_NEWGATEWAYINFO 2   // When Event Type = 2, bOff == add or remove
#define NETCARDEVENT_NETWORKDOWN 3
#define NETCARDEVENT_COMPUTERONOFF 4
#define NETCARDEVENT_DEFENDERINFO 5
#define NETCARDEVENT_SCANNETWORK 6
#define NETCARDEVENT_MESSAGE2CLIENT 7
#define NETCARDEVENT_SET_NODE_NAME 8
#define NETCARDEVENT_CONNECTMEINFO 9
#define NETCARDEVENT_REQUIREREG 10
#define NETCARDEVENT_GROUNDINFO 11
#define NETCARDEVENT_PID 12



#define EVENT_MAX_HOSTNAME 32
#define EVENT_MAX_BRANDNAME 32
#define EVENT_MAX_IPADDRESS 126
#define EVENT_FIX_MACSTR 19
#define EVENT_MAX_MESSAGESIZE EVENT_MAX_IPADDRESS

struct netcardClientEvent
{
	int8_t  nEventType;  //Computer Info 1 or Network Down
	int8_t  bOff;   //On OFF  add/remove
	char sMac[6];
	int8_t  nHostNameSize;
	char sPad[7];
	char sName[EVENT_MAX_HOSTNAME];  //nTYpe,StartHour,Startmin, EndHour, EndMin

};



struct netcardEvent
{
	int nTotalLen;
	int8_t  nEventType;  //Computer Info 1 or Network Down
	int8_t  nIPSize;
	int8_t  nHostNameSize;
	int8_t  nBrandNameSize;
	char sIP[EVENT_MAX_IPADDRESS];   //One adapter can not bind over 32 IPs
	char sName[EVENT_MAX_HOSTNAME];  //Remember to only copy 62 byte of any hostname here
	char sBrand[EVENT_MAX_BRANDNAME]; //Remember only copy 64 byte of Brand name

	int8_t bOff;   //1 off 0 on   grounded, not grouned
	int8_t bDefender;
	char sMac[6];
    int8_t bAttacker;
    char sMacStr[EVENT_FIX_MACSTR];  //Remember to only copy 19 byte of any MacString here
    int8_t bIsMyDevice;
    int8_t bIsGateway;
};

struct netcardEvent2
{
	int  nEventClass;  // Computer info, messages, network down, Attack Methods, Root status, IPTable status, ARP tables status
	char sEventContainer[1024];

};

struct EventCufOffMethods
{
	int nType; //0, Target to gateway, 1 Target to PC, 2, Target to all.
};
#endif /* NETHEADER_H_ */
