/*
 * CNbtQuery.h
 *
 *  Created on: Jan 21, 2015
 *      Author: root
 */

#ifndef CNBTQUERY_H_
#define CNBTQUERY_H_
#include "CThreadWorker.h"
#include "CMyLock.h"
#include <map>
#include "PracticalSocket.h"
#include "assert.h"
#include "nbtdefs.h"
#include "netheader.h"

using namespace NETCUT_CORE_FUNCTION;
struct netBiosPacket
{
	DWORD nIP;
	string sName;
};
class CNbtQuery {
public:
	CNbtQuery();
	virtual ~CNbtQuery();

	static void fill_namerequest(struct NMBpacket *pak, int *len, short seq);
	void Query(string & p_sIP);
	void Query(const DWORD & p_nIP);
	string query_names(FILE *, SOCKET sockfd,DWORD & p_nIP);

	static int sendpacket(int sfd, const void *pak, int len,
	const struct sockaddr_in *dst);
	static int recvpacket(int sfd, void *pak, int len, struct sockaddr_in *dst);
/*
	void StartListener();
    static void* threadListener(void *para);
	void threadListenerRun();
*/
	void RegisterNetworkHandle(callback p_Handle,void * p_Parent);

    int m_ReadTimeout;

    int m_sSocket;
    bool SetupSocket();
    void OnNewName(DWORD p_nIP,string p_sName);


    unsigned short GetIPTransID(DWORD & p_nIP);
    void SetIPTRansID(DWORD & p_nIP,unsigned short p_nID);


private:
    networkcallback m_CallNetworkHandle;

    std::map<DWORD,unsigned short> m_QueryHistoryID;

    CMyLock m_lock; /* lock */

   // CThreadWorker m_InfoworkerThread;
};

#endif /* CNBTQUERY_H_ */
