/*
 * CSocketIPC.cpp
 *
 *  Created on: Feb 3, 2015
 *      Author: root
 */

#include "CAddressHelper.h"
#include <sys/types.h>       // For data types
#include <sys/socket.h>      // For socket(), connect(), send(), and recv()
#include <netdb.h>           // For gethostbyname()
#include <arpa/inet.h>       // For inet_addr()
#include <CSocketIPC.h>
#include <unistd.h>          // For close()
#include <netinet/in.h>      // For sockaddr_in
typedef void raw_type;       // Type used for raw data on this platform

#include <errno.h>             // For errno
#include <sys/eventfd.h>
using namespace std;

CSocketIPC::CSocketIPC() {
	// TODO Auto-generated constructor stub

	this->m_MessageFactory=CIPCMessageObjectFactory::GetInstance();
}

void CSocketIPC::StartServer(unsigned int p_nListenerPort) {
	// TODO Auto-generated constructor stub

	m_nPort = p_nListenerPort;
	this->m_nSocket = 0;
	m_ListenThreadHandle.StartThread(threadListener, this);


}

void CSocketIPC::SetLinerZero(int p_socket) {

	struct linger so_linger;
	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	setsockopt(p_socket, SOL_SOCKET, SO_LINGER, &so_linger, sizeof so_linger);

}
CSocketIPC::~CSocketIPC() {
	// TODO Auto-generated destructor stub
	StopServer();
}

void CSocketIPC::StopServer()
{

		m_EventsQuit.SetEvent();
		m_ReaderIO.ShutDown();
		m_ServerIO.ShutDown();
		m_ServerMessageQueue.shutdown();

		if (m_nSocket >= 0) {
			SetLinerZero(m_nSocket);
			close(m_nSocket);
			m_nSocket=0;
		}

		RemoveAllClients();

	     m_ListenThreadHandle.WaitThreadExit();
	     m_WriteThreadHandle.WaitThreadExit();
	     m_ReadThreadHandle.WaitThreadExit();

	//	TRACE("Done IPC Socket server Exit\n");

}
void* CSocketIPC::threadListener(void *para) {

	CSocketIPC * c = (CSocketIPC *) para;
	c->threadListenerRun();
	return 0;

}
void CSocketIPC::threadListenerRun()  //start server
{

	struct sockaddr_in myaddr;

	this->m_nSocket = socket(PF_INET, SOCK_STREAM, 0);
	//SetSocketBlockingEnabled(m_nSocket,false);

	int yes = 1;
	if (setsockopt(m_nSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))
			== -1) {

		TRACE("ERROR: setsockopt [%s]", NATIVE_ERROR);
	}

	if (m_nSocket < 0) {
		TRACE("ERROR: cannot create socket [%s]", NATIVE_ERROR);
		return;
	}

	/*----------------------------------------------------------------
	 * Bind the local endpoint to receive our responses. If we use a
	 * zero, the system will pick one for us, or we can pick our own
	 * if we wish to make it easier to get past our firewall.
	 */
	memset(&myaddr, 0, sizeof myaddr);

	myaddr.sin_family = AF_INET;
//	myaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	myaddr.sin_addr.s_addr = INADDR_ANY;

	myaddr.sin_port = htons(this->m_nPort);

	bool bLog = false;
	int n = 0;

	while (bind(m_nSocket, (struct sockaddr *) (&myaddr), sizeof *(&myaddr))
			!= 0) {
		if (!bLog) {
			TRACE(
					"ERROR: cannot bind to local socket [%s] sleep 3 seconds and retry",
					strerror(errno));
			bLog = true;
			KillPrevious();
			n++;
		}

		//return
		if(this->m_EventsQuit.WaitForEvent((3+n) * 1000)) return;

		if (n > 12)
		{
			TRACE(
								"ERROR: cannot bind to local socket [%s] ",
								strerror(errno));

			return;
		}
	}
	TRACE("Bind Socket OK\n");

	if (listen(m_nSocket, 5) != 0) {
		TRACE("ERROR: cannot listen to local socket [%s]", strerror(errno));
		return;
	}
	m_WriteThreadHandle.StartThread(threadWriter, this);
	m_ReadThreadHandle.StartThread(threadReader, this);

	SetLinerZero(m_nSocket);

	m_ServerIO.Reset();
	m_ServerIO.SetFD(m_nSocket);
	while (m_ServerIO.WaitIO() && m_ServerIO.IsIOON(m_nSocket)) {
		int newConnSD;
		if ((newConnSD = accept(m_nSocket, NULL, 0)) < 0) {
			TRACE("ERROR: cannot accept client [%s]", strerror(errno));
			break;
			//exit(0);
		} else {
			AddClients(newConnSD);
		}
		m_ServerIO.Reset();
		m_ServerIO.SetFD(m_nSocket);
	}

//	TRACE("Exit server\n");

}

void* CSocketIPC::threadWriter(void *para) {

	CSocketIPC * c = (CSocketIPC *) para;
	c->threadWriterRun();
	return 0;
}


void CSocketIPC::threadWriterRun() // this one take server data and write into client sock
{
	while (1) {

		CIPCMessage *newitem;
		newitem = this->m_ServerMessageQueue.RemoveHead();

		if (NULL == newitem) {//When queue shutdown, return NULL, we will quit from here.

	//		TRACE("Writer queue shut down happen\n");
			break;
		}

		m_lock.lock();

		std::list<int>::iterator it = m_clientList.begin();

		while (it != m_clientList.end()) {
			int nClient = *it;
			//TRACE("sending message type %d size %d\n",newitem->TypeID(),newitem->m_nMessageSize);
			if(!newitem->write(nClient))
			{

				it = m_clientList.erase(it);
				CloseClient(nClient);
			}
			else
			{
				++it;
			}

			//TRACE("sending bytes %d %d\n", n, sizeof(*newitem));

		}
		m_lock.unlock();

		this->m_MessageFactory->Free(newitem);
	}

	//TRACE("Exit Server writer thread\n");
}
/*
void CSocketIPC::threadWriterRun() // this one take server data and write into client sock
{
	while (1) {

		netcardEvent *newitem;
		newitem = this->m_ServerEventsQueue.RemoveHead();

		if (NULL == newitem) {
			break;
		}

		m_lock.lock();

		std::list<int>::iterator it = m_clientList.begin();

		while (it != m_clientList.end()) {
			int nClient = *it;

			char buff[300];
			memset(buff, 0, 300);
			memcpy(buff, newitem, sizeof(*newitem));

			int n = send(nClient, (const void *) newitem, sizeof(*newitem), 0);
			if (n < 0) {

				it = m_clientList.erase(it);
				CloseClient(nClient);
			} else {
				++it;
			}
			//TRACE("sending bytes %d %d\n", n, sizeof(*newitem));

		}
		m_lock.unlock();

		delete newitem;
	}

	TRACE("Exit Server writer\n");
}
*/
/*
 void CSocketIPC::threadWriterRun2() // this one take server data and write into client sock
 {
 while (1) {

 netcardEvent2 *newitem;
 newitem = this->m_ServerEventsQueue.RemoveHead();

 if (NULL == newitem)
 return;

 m_lock.lock();

 std::list<int>::iterator it = m_clientList.begin();

 while (it != m_clientList.end()) {
 int nClient = *it;

 char buff[300];
 memset(buff,0,300);
 memcpy(buff,newitem,sizeof(*newitem));

 int n = send(nClient, (const void *) newitem, sizeof(*newitem), 0);
 if (n < 0) {

 it = m_clientList.erase(it);
 CloseClient(nClient);
 } else {
 ++it;
 }
 //TRACE("sending bytes %d %d\n", n, sizeof(*newitem));

 }
 m_lock.unlock();

 delete newitem;
 }

 }
 */
void* CSocketIPC::threadReader(void *para) {

	CSocketIPC * c = (CSocketIPC *) para;
	c->threadReaderRun();
	return 0;


}


void CSocketIPC::threadReaderRun() //got client data and call onclientdata, clean up after
{


	while (1) {

		m_ReaderIO.Reset();


		list<int> copylist = GetClients();
		for (std::list<int>::iterator it = copylist.begin();
				it != copylist.end(); ++it) {
			int n = *it;
			m_ReaderIO.SetFD(n);
		}

		if (m_ReaderIO.WaitIO()) {
			if (m_ReaderIO.IsEventON(IOWATCHER_ID_NEWCLIENT)) {
				TRACE("New client\n");
			}

			for (std::list<int>::iterator it = copylist.begin();
					it != copylist.end(); ++it) {
				int n = *it;
				if (m_ReaderIO.IsIOON(n)) {

					CIPCMessage *m=this->m_MessageFactory->GetMessage(n);
					if(m==NULL)
					{
						this->RemoveClient(n);

					}
					else
					{
						this->OnClientMessage(m);
						m_MessageFactory->Free(m);
					}

				}
			}

		} else {
			break;
		}
	}
//	TRACE("Exit Server reader thread\n");

	//close(this->m_nNewClientFD);
}
/*
void CSocketIPC::threadReaderRun() //got client data and call onclientdata, clean up after
{


	while (1) {

		m_ReaderIO.Reset();

		int n;

		list<int> copylist = GetClients();
		for (std::list<int>::iterator it = copylist.begin();
				it != copylist.end(); ++it) {
			int n = *it;
			m_ReaderIO.SetFD(n);
		}

		if (m_ReaderIO.WaitIO()) {
			if (m_ReaderIO.IsEventON(IOWATCHER_ID_NEWCLIENT)) {
				TRACE("New client\n");
			}

			for (std::list<int>::iterator it = copylist.begin();
					it != copylist.end(); ++it) {
				int n = *it;
				if (m_ReaderIO.IsIOON(n)) {

					netcardClientEvent newitem;
					int nReadCount = recv(n, &newitem, sizeof(newitem), 0);
					if (nReadCount <= 0) {
						this->RemoveClient(n);

					} else {
						this->OnClientData(&newitem);
					}

				}
			}

		} else {
			break;
		}
	}
	TRACE("Exit Server reader thread\n");

	//close(this->m_nNewClientFD);
}
*/

/*
 void CSocketIPC::threadReaderRun2() //got client data and call onclientdata, clean up after
 {

 while (1) {

 fd_set rfds; //* list of read descriptors
 int n;
 FD_ZERO(&rfds);

 FD_SET(this->m_nNewClientFD, &rfds);
 list<int> copylist = GetClients();
 for (std::list<int>::iterator it = copylist.begin();
 it != copylist.end(); ++it) {
 int n = *it;
 FD_SET(n, &rfds);
 }

 int topn = m_nNewClientFD;

 if (copylist.size() > 0) {
 topn = m_nNewClientFD > copylist.back() ?
 m_nNewClientFD : copylist.back();
 }
 topn++;

 if ((n = select(topn, &rfds, 0, 0, NULL)) > 0) {
 if (FD_ISSET(m_nNewClientFD, &rfds)) {

 char buff[8];
 int n=read(m_nNewClientFD, buff, 8);
 if(n==8)
 {
 int32_t *number=(int32_t *)buff;
 TRACE("Got new client , need to reload select list %d\n",*number);
 }
 }

 for (std::list<int>::iterator it = copylist.begin();
 it != copylist.end(); ++it) {
 int n = *it;
 if (FD_ISSET(n, &rfds)) {

 netcardEvent2 newitem;
 int nReadCount = recv(n, &newitem, sizeof(newitem), 0);
 if (nReadCount <= 0) {
 this->RemoveClient(n);

 } else {
 this->OnClientData2(&newitem);
 }

 }
 }

 }
 }
 }

 */

list<int> CSocketIPC::GetClients() {
	m_lock.lock();

	list<int> s = this->m_clientList;
	m_lock.unlock();
	return s;

}
void CSocketIPC::AddClients(int p_nClientSock) {

	m_lock.lock();
	SetLinerZero(p_nClientSock);
	this->m_clientList.push_back(p_nClientSock);
	m_clientList.sort();

	OnNewClient(p_nClientSock);

	this->m_ReaderIO.SetEvent(IOWATCHER_ID_NEWCLIENT);

	m_lock.unlock();

}

void CSocketIPC::RemoveAllClients() {
	m_lock.lock();

	std::list<int>::iterator it = m_clientList.begin();
	while (it != m_clientList.end()) {
		int nClient = *it;
		it = m_clientList.erase(it);
		CloseClient(nClient);
	}
	m_lock.unlock();
}
void CSocketIPC::RemoveClient(int p_nClientSock) {

	m_lock.lock();

	m_clientList.remove(p_nClientSock);

	CloseClient(p_nClientSock);

	m_lock.unlock();

}
void CSocketIPC::CloseClient(int p_nClientSock) {

	if (p_nClientSock >= 0) {
		SetLinerZero(p_nClientSock);
		close(p_nClientSock);
	}

}
/*
 void CSocketIPC::OnNewServerData2(netcardEvent2 & p_E) {
 //call this to push data to clients
 netcardEvent2 *newEvent = new netcardEvent2();
 *newEvent = p_E;

 this->m_ServerEventsQueue.AddTail(newEvent);

 }
 */

void CSocketIPC::OnNewServerMessage(CIPCMessage * p_Message) {
	//call this to push data to clients

	this->m_ServerMessageQueue.AddTail(p_Message);

}
/*
void CSocketIPC::OnNewServerData(netcardEvent & p_E) {
	//call this to push data to clients
	netcardEvent *newEvent = new netcardEvent();
	*newEvent = p_E;



}

*/
