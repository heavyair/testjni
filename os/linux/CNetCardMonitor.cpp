/*
 * CNetCardMonitor.cpp
 *
 *  Created on: Jan 4, 2016
 *      Author: root
 */

#include <CNetCardMonitor.h>
#include "CAddressHelper.h"
#include <CIPCMessageDeviceInfo.h>
#include <CIPCMessageObjectFactory.h>
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000		/* driver signals L1 up		*/
#endif

namespace NETCUT_CORE_FUNCTION {

CNetCardMonitor::CNetCardMonitor() {
	// TODO Auto-generated constructor stub

	this->LoopDevs();

	m_ThreadHandleLinkWatcher.StartThread(threadLinkWatcher, this);
}

CNetCardMonitor::~CNetCardMonitor() {
	// TODO Auto-generated destructor stub
	this->m_ExitEvent.SetEvent(IOWATCHER_ID_EXIT);
	m_ThreadHandleLinkWatcher.WaitThreadExit();

	std::map<std::string, CIPCMessageDeviceInfo *>::iterator it;

	for (it = m_DevMap.begin(); it != m_DevMap.end(); ++it) {
		CIPCMessageDeviceInfo * Messages = (*it).second;
		CIPCMessageObjectFactory::GetInstance()->Free(Messages);

	}

}
void CNetCardMonitor::LoopDevs() {

	ReadDev(RTM_GETLINK, sizeof(ifinfomsg));
	ReadDev(RTM_GETADDR, sizeof(ifaddrmsg));
	ReadDev(RTM_GETROUTE, sizeof(rtmsg));

}

void CNetCardMonitor::OnDeviceUpdate(CIPCMessageDeviceInfo * p_Dev) {

	//TRACE("Send p_dev update\n");

	if(p_Dev->m_message.bUp)
	{
	unsigned char sMac[6];
			memset(sMac,0,6);
			if(CAddressHelper::GetInterfaceMac(p_Dev->m_message.sDevname,sMac))
			{
				p_Dev->SetMac(sMac);
			}
	}

	OnDeviceUpdateFull((CIPCMessageDeviceInfo *) p_Dev->Create());

	/*
	 unsigned char Emptybuf[6];
	 memset(Emptybuf,0,6);

	 if(memcmp(p_Dev->m_message.MacBuff,Emptybuf,6)!=0)  //if this dev already have a MAC, tell to update
	 {
	 OnDeviceUpdateFull(p_Dev);
	 }*/
}

void CNetCardMonitor::OnDeviceUpdateFull(CIPCMessageDeviceInfo * p_Dev) {

}

bool CNetCardMonitor::ReadDev(__u16 p_nRequestType, int p_nLen) {

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		perror("socket(): ");
		return false;
	}

	srand(time(NULL));
	int nSeq = rand();

	int rtn;

	struct {
		struct nlmsghdr nlmsg_info;
		char buffer[2048];
	} netlink_req;

	bzero(&netlink_req, sizeof(netlink_req));

	netlink_req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(p_nLen);
	netlink_req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	netlink_req.nlmsg_info.nlmsg_type = p_nRequestType;
	netlink_req.nlmsg_info.nlmsg_pid = getpid();
	netlink_req.nlmsg_info.nlmsg_seq = nSeq;

	rtn = send(fd, &netlink_req, netlink_req.nlmsg_info.nlmsg_len, 0);
	if (rtn < 0) {
		perror("send(): ");
		return false;
	}

	int pagesize = 4096;
	char read_buffer[pagesize];
	struct nlmsghdr *nlmsg_ptr;
	int nlmsg_len;

	do {
		int rtn;

		bzero(read_buffer, pagesize);
		rtn = recv(fd, read_buffer, pagesize, 0);
		if (rtn < 0) {
			perror("recv(): ");
			return false;
		}

		nlmsg_ptr = (struct nlmsghdr *) read_buffer;
		nlmsg_len = rtn;

		// fprintf (stderr, "received %d bytes\n", rtn);

		if (nlmsg_len < sizeof(struct nlmsghdr)) {
			fprintf(stderr, "received an uncomplete netlink packet\n");
			return false;
		}

		if (nlmsg_ptr->nlmsg_type == NLMSG_DONE) {
			//	TRACE("Netlink Message type %d finish\n",p_nRequestType);
			break;
		}
		process_nlmsg(nlmsg_ptr, nlmsg_len);
	} while ((nlmsg_ptr->nlmsg_seq != nSeq)
			|| (nlmsg_ptr->nlmsg_pid != getpid()));

	close(fd);

}

void* CNetCardMonitor::threadLinkWatcher(void *para) {
	CNetCardMonitor * ptr = (CNetCardMonitor *) para;

	ptr->threadLinkWatcherRun();

	return NULL;

}

void CNetCardMonitor::process_route(struct nlmsghdr *nlmsg_ptr, int nlmsg_len) {

	struct route_info {
		u_int dstAddr;
		u_int mask;
		u_int gateWay;

		char ifName[IF_NAMESIZE];
	};

	route_info rtInfo;
	bzero(&rtInfo, sizeof(rtInfo));
	struct rtmsg *rtMsg;
	struct rtattr *rtAttr;
	rtMsg = (struct rtmsg *) NLMSG_DATA(nlmsg_ptr);

	if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))

		return;

	/* get the rtattr field */
	rtAttr = (struct rtattr *) RTM_RTA(rtMsg);

	int rtLen;
	bool bHasGate = false;
	rtLen = RTM_PAYLOAD(nlmsg_ptr);
	for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {

		//printf("route att ID %d\n",rtAttr->rta_type);

		switch (rtAttr->rta_type) {
		case RTA_OIF:
			if_indextoname(*(int *) RTA_DATA(rtAttr), rtInfo.ifName);

			break;
		case RTA_GATEWAY:
			rtInfo.gateWay = *(u_int *) RTA_DATA(rtAttr);
			bHasGate = true;

			break;

		case RTA_DST:
			rtInfo.dstAddr = *(u_int *) RTA_DATA(rtAttr);

			break;
		default:
			break;
		}
	}

	if (bHasGate) {
		//	TRACE("gate %s mask %s\n",CAddressHelper::IntIP2str(rtInfo.gateWay).c_str(),CAddressHelper::IntIP2str(rtInfo.mask).c_str());
		this->OnNetCardNewGate(rtInfo.ifName, rtInfo.gateWay);
	}
}

void CNetCardMonitor::OnNetCardNewAdd(std::string p_sNetcardName, u_int p_nIP,
		u_int p_nMask) {

	if (CAddressHelper::StrIP2Int("127.0.0.1") == p_nIP)
		return;

//	TRACE("%s new add %s mask %s\n", CAddressHelper::IntIP2str(p_nIP).c_str(), p_sNetcardName.c_str(),CAddressHelper::IntIP2str(p_nMask).c_str());

	this->m_lock.lock();

	do {

		CIPCMessageDeviceInfo * dev = NULL;
		auto search = this->m_DevMap.find(p_sNetcardName);
		if (search != m_DevMap.end()) {
			dev = search->second;
		} else {
			dev =
					(CIPCMessageDeviceInfo *) CIPCMessageObjectFactory::GetInstance()->Get(
							IPCMESSAGE_ID_DEVICINFO);
			if (dev == NULL) {
				TRACE("Out of memory or outdate version\n");
				break;
			}
			m_DevMap[p_sNetcardName] = dev;
			dev->SetDevName(p_sNetcardName);

		}


		dev->SetUpFlag(true);
		dev->AddIP(p_nIP);
		dev->SetMask(p_nMask);
		this->OnDeviceUpdate(dev);
	} while (false);

	this->m_lock.unlock();
}
void CNetCardMonitor::OnNetCardNewGate(std::string p_sNetcardName,
		u_int p_nGate) {

	in_addr in;
	in.s_addr = p_nGate;
	std::string add = (char *) inet_ntoa(in);
//	TRACE("%s Gate %s\n", add.c_str(), p_sNetcardName.c_str());

	this->m_lock.lock();

	do {

		CIPCMessageDeviceInfo * dev = NULL;
		auto search = this->m_DevMap.find(p_sNetcardName);
		if (search != m_DevMap.end()) {
			dev = search->second;
		} else {
			dev =
					(CIPCMessageDeviceInfo *) CIPCMessageObjectFactory::GetInstance()->Get(
							IPCMESSAGE_ID_DEVICINFO);
			if (dev == NULL) {
				TRACE("Out of memory or outdate version\n");
				break;
			}
			m_DevMap[p_sNetcardName] = dev;
			dev->SetDevName(p_sNetcardName);
		}

		dev->SetUpFlag(true);
		dev->SetRoute(p_nGate);
		this->OnDeviceUpdate(dev); //Only send update when this dev has been processed by Interfaces or get the interface stat directly.
		this->m_lock.unlock();
	} while (false);
	/*if(p_Devs==NULL) return;
	 CIPCMessageDeviceInfo * dev=NULL;
	 auto search = p_Devs->find(p_sNetcardName);
	 if(search != p_Devs->end()) {
	 dev=search->second;
	 }
	 else {
	 dev=(CIPCMessageDeviceInfo *)CIPCMessageObjectFactory::GetInstance()->Get(IPCMESSAGE_ID_DEVICINFO);
	 if(dev==NULL)
	 {
	 TRACE("Out of memory or outdate version\n");
	 return;
	 }
	 (*p_Devs)[p_sNetcardName]=dev;
	 dev->SetDevName(p_sNetcardName);
	 }
	 dev->SetRoute(p_nGate);
	 */
}
void CNetCardMonitor::OnNetCardNewLink(bool p_bUp, std::string p_sNetcardName,
		u_char *p_pMac) {

	this->m_lock.lock();

	do {
		CIPCMessageDeviceInfo * dev = NULL;
		auto search = m_DevMap.find(p_sNetcardName);
		if (search != m_DevMap.end()) {
			dev = search->second;
			if (!p_bUp)   //if an existing dev goes down, reset it's IP address
				dev->ResetIP();
		} else {
			dev =
					(CIPCMessageDeviceInfo *) CIPCMessageObjectFactory::GetInstance()->Get(
							IPCMESSAGE_ID_DEVICINFO);
			if (dev == NULL) {
				TRACE("Out of memory or outdate version\n");
				break;
			}
			m_DevMap[p_sNetcardName] = dev;
			dev->SetDevName(p_sNetcardName);
		}

		dev->SetUpFlag(p_bUp);
		//  dev->SetUpFlag(CAddressHelper::IsInterfaceUp(p_sNetcardName));
		dev->SetMac(p_pMac);

		this->OnDeviceUpdate(dev);
	} while (false);

	this->m_lock.unlock();

	/*
	 if(p_Devs==NULL) return;
	 CIPCMessageDeviceInfo * dev=NULL;
	 auto search = p_Devs->find(p_sNetcardName);
	 if(search != p_Devs->end()) {
	 dev=search->second;
	 }
	 else {
	 dev=(CIPCMessageDeviceInfo *)CIPCMessageObjectFactory::GetInstance()->Get(IPCMESSAGE_ID_DEVICINFO);
	 if(dev==NULL)
	 {
	 TRACE("Out of memory or outdate version\n");
	 return;
	 }
	 (*p_Devs)[p_sNetcardName]=dev;
	 dev->SetDevName(p_sNetcardName);
	 }

	 dev->SetUpFlag(p_bUp);
	 dev->SetMac(p_pMac);
	 */

}
void CNetCardMonitor::process_if(struct nlmsghdr *nlmsg_ptr, int nlmsg_len) {

	struct if_info {
		int bIsUp;
		unsigned char sMac[6];
		char ifName[IF_NAMESIZE];
	};

	if_info ifInfo;
	bzero(&ifInfo, sizeof(ifInfo));
	struct ifinfomsg *ifMsg;
	struct rtattr *rtAttr;
	ifMsg = (struct ifinfomsg *) NLMSG_DATA(nlmsg_ptr);

	/* get the rtattr field */

	bool bFoundMac = false;
	int rtLen = nlmsg_ptr->nlmsg_len - NLMSG_SPACE(sizeof(*ifMsg));

	for (rtAttr = IFLA_RTA(ifMsg); RTA_OK(rtAttr, rtLen);
			rtAttr = RTA_NEXT(rtAttr, rtLen)) {
		int nLen = RTA_PAYLOAD(rtAttr);
		//printf("interface att ID %d\n",rtAttr->rta_type);

		switch (rtAttr->rta_type) {
		case IFLA_WIRELESS:
			//	TRACE("Wireless event , not interested for now\n");
			return;
			break;
		case IFLA_IFNAME:

			snprintf(ifInfo.ifName, sizeof(ifInfo.ifName), "%s",
					(char *) RTA_DATA(rtAttr));

			//	printf("dev: %s\n", ifInfo.ifName);
			break;
		case IFLA_ADDRESS:

			//	printf("Address len %d ", nLen);
			if (nLen == 6) {

				if (CAddressHelper::isEmptyMac(
						(unsigned char*) RTA_DATA(rtAttr)))
					break;
				memcpy(ifInfo.sMac, (unsigned char*) RTA_DATA(rtAttr), nLen);
				std::string s = _helper_Mac_buff2Str(ifInfo.sMac);
				//printf("mac: %s\n", s.c_str());
				bFoundMac = true;
			}

			break;

		}
	}

	/*
	 *
	 so in short: LINK MONITOR ONLY WORKS FOR BOTH TO CHECK DOWN.
	 IF_RUNNING seems required on 4.4 above, confirmed.  4.0 below can't use IF_RUNNING.
	 for 4.4 above
	 in order to confirm if an interface UP, it need to be UP and Having an Address
	 it is down, it is !IF_LOWER_UP

	 4.0 below
	 if it is UP, when UP and having an address
	 in order to confirm if an interface is DOWN, it need to !IF_LOWER_UP ---> for 4.0 below
	 */
	ifInfo.bIsUp = (!(ifMsg->ifi_flags & IFF_LOWER_UP)||!(ifMsg->ifi_flags & IFF_RUNNING)) ? 0 : 1;
//Sometime system send interface info without if lower up or running, but it is to communicate some other info
//we just need to check if it has IP, if no IP, then it's down.
	if (!ifInfo.bIsUp) {
		DWORD nIP=0;
		if(CAddressHelper::GetInterfaceIP(ifInfo.ifName,nIP))
			ifInfo.bIsUp=true;
	}
	if(!ifInfo.bIsUp)
	{
		string s = ifInfo.ifName;
		if (s == "wlan0") {
			TRACE("%s: ", ifInfo.ifName);

			if (ifMsg->ifi_flags & IFF_LOWER_UP)
				TRACE("lower_UP ");
			if (ifMsg->ifi_flags & IFF_RUNNING)
				TRACE("RUNNING ");
			if (ifMsg->ifi_flags & IFF_UP)
				TRACE("UP ");
			if (ifMsg->ifi_flags & 1 << 17)
				TRACE("IFF_DORMANT ");
			TRACE("\n");
		}
	}
	if (bFoundMac) {
		//ifInfo.bIsUp = (ifMsg->ifi_flags & IFF_LOWER_UP && ifMsg->ifi_flags & IFF_RUNNING)? 1 : 0;

		//   TRACE("%s %s\n",ifInfo.ifName,ifInfo.bIsUp ?"ONline":"Offline");

		this->OnNetCardNewLink(ifInfo.bIsUp, ifInfo.ifName, ifInfo.sMac);
	}
}

void CNetCardMonitor::process_add(struct nlmsghdr *nlmsg_ptr, int nlmsg_len) {

	struct ifadd_info {

		u_int nIP;
		char ifName[IF_NAMESIZE];
	};

	ifadd_info ifadd;
	struct ifaddrmsg *ifaddrmsg_ptr;
	struct rtattr *rtattr_ptr;
	int ifaddrmsg_len;

	char localaddr_str[INET6_ADDRSTRLEN];

	ifaddrmsg_ptr = (struct ifaddrmsg *) NLMSG_DATA(nlmsg_ptr);

	localaddr_str[0] = 0;

	rtattr_ptr = (struct rtattr *) IFA_RTA(ifaddrmsg_ptr);
	ifaddrmsg_len = IFA_PAYLOAD(nlmsg_ptr);

	for (; RTA_OK(rtattr_ptr, ifaddrmsg_len);
			rtattr_ptr = RTA_NEXT(rtattr_ptr, ifaddrmsg_len)) {
		size_t rta_payload = RTA_PAYLOAD(rtattr_ptr);
		switch (rtattr_ptr->rta_type) {
		case IFA_LOCAL:
			inet_ntop(ifaddrmsg_ptr->ifa_family, RTA_DATA(rtattr_ptr),
					localaddr_str, sizeof(localaddr_str));

			switch (ifaddrmsg_ptr->ifa_family) {
			case AF_INET:
				/* Size must match that of an address for IPv4.  */

				if (rta_payload == 4) {
					memcpy(&ifadd.nIP, RTA_DATA(rtattr_ptr), rta_payload);
				}
				break;
			}
			break;
		case IFA_LABEL:
			snprintf(ifadd.ifName, sizeof(ifadd.ifName), "%s",
					(char *) RTA_DATA(rtattr_ptr));
			break;
		default:
			break;

		}
	}

	int fd;
	DWORD nMask = 0;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (-1 == fd) {
		return;
	}

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, ifadd.ifName, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFNETMASK, &ifr);
	nMask = ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr;
	close(fd);

	this->OnNetCardNewAdd(ifadd.ifName, ifadd.nIP, nMask);

}

bool CNetCardMonitor::process_nlmsg(struct nlmsghdr *nlmsg_ptr, int nlmsg_len) {

	for (; NLMSG_OK(nlmsg_ptr, nlmsg_len);
			nlmsg_ptr = NLMSG_NEXT(nlmsg_ptr, nlmsg_len)) {

		if (nlmsg_ptr->nlmsg_type == NLMSG_DONE) {
//			TRACE("No more messages\n");
			break;
		} else if (nlmsg_ptr->nlmsg_type == NLMSG_ERROR) {
			TRACE("NETLINK MSAGE Error restarting\n");
			return false;
		}

		if (nlmsg_ptr->nlmsg_type == RTM_NEWROUTE) {
			//	TRACE("Monitor New route message %s\n",p_Devs==NULL?"thread":"caller");
			process_route(nlmsg_ptr, nlmsg_len);
		}
		if (nlmsg_ptr->nlmsg_type == RTM_NEWADDR) {
			//TRACE("Monitor New IP message %s\n",p_Devs==NULL?"thread":"caller");
			process_add(nlmsg_ptr, nlmsg_len);
		}
		if (nlmsg_ptr->nlmsg_type == RTM_NEWLINK) {
			//	TRACE("Monitor New Link message %s\n",p_Devs==NULL?"thread":"caller");
			process_if(nlmsg_ptr, nlmsg_len);

		}

	}
	return true;
}

void CNetCardMonitor::threadLinkWatcherRun() {

#define BUFLEN 20480
	int m_nRouteMsgFD;
	int retval;
	char buf[BUFLEN] = { 0 };
	int len = BUFLEN;
	struct sockaddr_nl addr;

	NEWROUTESOCKET:

	m_nRouteMsgFD = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (m_nRouteMsgFD == -1) {
		TRACE("binding raw sock error\n");
		return;
	}
	setsockopt(m_nRouteMsgFD, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len));
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTNLGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
	//addr.nl_groups = RTNLGRP_LINK;
	bind(m_nRouteMsgFD, (struct sockaddr*) &addr, sizeof(addr));

	while (1) {
		m_ExitEvent.Reset();
		m_ExitEvent.SetFD(m_nRouteMsgFD);

		if (m_ExitEvent.WaitIO() && m_ExitEvent.IsIOON(m_nRouteMsgFD)) {

			if ((retval = read(m_nRouteMsgFD, buf, BUFLEN)) > 0) {

				if (!process_nlmsg((struct nlmsghdr *) buf, retval))
					goto NEWROUTESOCKET;

			} else {

				goto NEWROUTESOCKET;
			}
		} else {
			break;
		}

	}

	close(m_nExitFD);
	TRACE("The Link stat thread exited\n");
}

} /* namespace NETCUT_CORE_FUNCTION */
