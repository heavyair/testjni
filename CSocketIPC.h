/*
 * CSocketIPC.h
 *
 *  Created on: Feb 3, 2015
 *      Author: root
 */

#ifndef CSOCKETIPC_H_
#define CSOCKETIPC_H_

#include <PointerQueue.h>
#include "CThreadWorker.h"
#include "CMyLock.h"
#include <CIOWatcher.h>
#include <CIPCMessageObjectFactory.h>

#include <CNetcutEvent.h>

using namespace NETCUT_CORE_FUNCTION;
#include "netheader.h"
#define DEFAULTIPCSERVERPORT 4623
#define IOWATCHER_ID_NEWCLIENT 2
class CSocketIPC {
public:
	CSocketIPC();
	~CSocketIPC();
	void StartServer(unsigned int  p_nListenerPort=DEFAULTIPCSERVERPORT);
	void StopServer();
	virtual	void OnNewServerMessage(CIPCMessage *p_Message);  //call this to push data to clients

//virtual	void OnNewServerData(netcardEvent & p_E);  //call this to push data to clients
//virtual	void OnNewServerData2(netcardEvent2 & p_E);  //call this to push data to clients
//virtual void OnClientData(netcardClientEvent * p_E)=0;   //Overwrite this to handle client request
virtual void OnClientMessage(CIPCMessage * p_Message)=0;  //OverWrite this to handle Client message
//virtual void OnClientData2(netcardEvent2 * p_E)=0;   //Overwrite this to handle client request
virtual void OnNewClient(int p_nClientSocket)=0;  //OVerwrite this to do new client shakehands
private:
    static void* threadListener(void *para);
	void threadListenerRun();  //start server


    static void* threadWriter(void *para);
	void threadWriterRun();  // this one take server data and write into client sock
	void threadWriterRun2();  // this one take server data and write into client sock


    static void* threadReader(void *para);
	void threadReaderRun(); //got client data and call onclientdata, clean up after

    void AddClients(int p_nClientSock);
    void RemoveClient(int p_nClientSock);
    void CloseClient(int p_nClientSock);
    void RemoveAllClients();
    list<int> GetClients();
    void SetLinerZero(int p_socket);

private:
    CThreadWorker m_ListenThreadHandle;
    CThreadWorker m_WriteThreadHandle;
    CThreadWorker m_ReadThreadHandle;

    CMyLock m_lock; /* lock */

	unsigned int m_nPort;
	int m_nSocket;

	CIOWatcher m_ReaderIO;
	CIOWatcher m_ServerIO;
	std::list<int> m_clientList;
	CIPCMessageObjectFactory *m_MessageFactory;
	PointerQueue<CIPCMessage *> m_ServerMessageQueue;  //push server data here,

protected:
	CNetcutEvent  m_EventsQuit;
};

#endif /* CSOCKETIPC_H_ */
