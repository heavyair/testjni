/*
 * CNetCardMonitor.h
 *
 *  Created on: Jan 4, 2016
 *      Author: root
 */

#ifndef OS_LINUX_CNETCARDMONITOR_H_
#define OS_LINUX_CNETCARDMONITOR_H_
#include <string>
#include <CNetCardMonitorBase.h>
#include "CThreadWorker.h"
#include <CIOWatcher.h>

#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <sys/ioctl.h>

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "netheader.h"
#include <CNetcutTool.h>
#include <sys/eventfd.h>

#include <CIPCMessageDeviceInfo.h>
#include <MyLock.h>
/*
 *
 *  Set a Private Dev Map
 *  Update
 *  ReadDevs Lock, --> OnDevUpdate;
 *
 */

namespace NETCUT_CORE_FUNCTION {

class CNetCardMonitor: public CNetCardMonitorBase {
public:
	CNetCardMonitor();
	virtual ~CNetCardMonitor();

	virtual void OnNetCardNewAdd(std::string p_sNetcardName,u_int p_nIP,u_int p_nMask);
	virtual void OnNetCardNewGate(std::string p_sNetcardName,u_int p_nGate);
	virtual void OnNetCardNewLink(bool p_bUp, std::string p_sNetcardName,u_char *p_pMac);
	void LoopDevs();

	virtual void OnDeviceUpdateFull(CIPCMessageDeviceInfo * p_Dev);

protected:
	void OnDeviceUpdate(CIPCMessageDeviceInfo * p_Dev);
	bool ReadDev(__u16 p_nRequestType,int p_nLen);
	bool process_nlmsg(struct nlmsghdr *nlmsg_ptr, int nlmsg_len);
	void process_add(struct nlmsghdr *nlmsg_ptr, int nlmsg_len);
	void process_if(struct nlmsghdr *nlmsg_ptr, int nlmsg_len);
	void process_route(struct nlmsghdr *nlmsg_ptr, int nlmsg_len);
	static void* threadLinkWatcher(void *para);
    void threadLinkWatcherRun();

    std::map<std::string, CIPCMessageDeviceInfo *>  m_DevMap;
    int m_nExitFD;
    CThreadWorker m_ThreadHandleLinkWatcher;
    CIOWatcher m_ExitEvent;
    MyLock m_lock; /* lock */

};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_CNETCARDMONITOR_H_ */
