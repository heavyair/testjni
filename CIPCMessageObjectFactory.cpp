/*
 * CIPCMessageObjectFactory.cpp
 *
 *  Created on: Jan 13, 2016
 *      Author: root
 */

#include <CIPCMessageObjectFactory.h>

namespace NETCUT_CORE_FUNCTION {

std::map<int32_t, CIPCMessage *> CIPCMessageObjectFactory::m_MessageType;
std::map<int32_t, std::vector<CIPCMessage *>> CIPCMessageObjectFactory::m_MessageStorage;
CMyLock CIPCMessageObjectFactory::m_lock; /* lock */

CIPCMessageObjectFactory::CIPCMessageObjectFactory() {
	// TODO Auto-generated constructor stub
	RegisterMessagesType();

}

CIPCMessageObjectFactory * CIPCMessageObjectFactory::GetInstance() {

	static CIPCMessageObjectFactory factory;
	return &factory;

}

CIPCMessageObjectFactory::~CIPCMessageObjectFactory() {
	// TODO Auto-generated destructor stub

	std::map<int32_t, std::vector<CIPCMessage *>>::iterator it;

	for (it = m_MessageStorage.begin(); it != m_MessageStorage.end(); ++it) {
		std::vector<CIPCMessage *> &sMessages = (*it).second;
		std::vector<CIPCMessage *>::iterator sit;
		while (!sMessages.empty()) {
			CIPCMessage * s = sMessages.back();
			sMessages.pop_back();
			delete s;
		}

	}

	std::map<int32_t, CIPCMessage *>::iterator typeit;
	for (typeit = m_MessageType.begin(); typeit != m_MessageType.end();
			++typeit) {
		CIPCMessage * s = (*typeit).second;
		delete s;
	}

}
CIPCMessage * CIPCMessageObjectFactory::GetMessage(int sock) {
	/*
	 *  Read socket first 4 byte to get type, then get object of that type, return it, if any failed, return NULL
	 */
	int32_t nSize=0;
	int32_t nType = 0;

	CIPCMessage * newMess = NULL;
	do {

		int nReadCount = recv(sock, &nSize, sizeof(nSize), 0);
		if (nReadCount < sizeof(nSize))
					break;
		 nReadCount = recv(sock, &nType, sizeof(nType), 0);
		if (nReadCount < sizeof(nType))
			break;
		newMess=Get(nType);
		if (newMess == NULL)
			break;
		if (!newMess->Read(sock)) {
			Free(newMess);
			newMess = NULL;
		}
	} while (false);
	return newMess;

}

CIPCMessage * CIPCMessageObjectFactory::Get(int32_t p_nTypeID) {

	/*
	 *  Use map to test if any free message object exist, if yes, return the pointer
	 *  if no, create message use type map,
	 *  inside type map , if no such object, return null


	if(p_nTypeID==IPCMESSAGE_ID_DEVICINFO)
		{
			TRACE("Need to see this\n");
		}

			 */
	CIPCMessage * t = NULL;
	m_lock.lock();
	std::map<int32_t, std::vector<CIPCMessage *>>::iterator it;

	it = m_MessageStorage.find(p_nTypeID);
	if (it != m_MessageStorage.end()) {
		std::vector<CIPCMessage *> &sMessages = (*it).second;

		if (!sMessages.empty()) {
			t = sMessages.back();
			t->Reset();
			sMessages.pop_back();
		}
	}
	if (t == NULL) {

		std::map<int32_t, CIPCMessage *>::iterator typeit = m_MessageType.find(
				p_nTypeID);
		if (typeit != m_MessageType.end()) {
			CIPCMessage * typeobject = (*typeit).second;
			t = typeobject->Create();
		}
		else
		{
			TRACE("Wrong Message ID %d, Might be need upgrade?\n",p_nTypeID);
		}
	}

	m_lock.unlock();

	return t;
}
void CIPCMessageObjectFactory::Free(CIPCMessage * p_IPCMessage) {
	/*
	 *  put the pointer to free map
	 *
	if(p_IPCMessage->TypeID()==IPCMESSAGE_ID_DEVICINFO)
	{
		TRACE("Need to see this\n");
	}

	*/
	m_lock.lock();
	auto it = m_MessageStorage.find(p_IPCMessage->TypeID());
	if (it != m_MessageStorage.end()) {
		std::vector<CIPCMessage *> &sMessages = it->second;

		sMessages.push_back(p_IPCMessage);

	} else {
		m_MessageStorage[p_IPCMessage->TypeID()].push_back(p_IPCMessage);
	}

	m_lock.unlock();

}
void CIPCMessageObjectFactory::RegisterMessagesType() {

	/*
	 *  create object for each type and put into type map
	 */
	CIPCMessage *p = new CIPCMessageDeviceInfo();
	m_MessageType[p->TypeID()]=p;


//	TRACE("Device Info ID %d\n",p->TypeID());

	    p = new CIPCMessageSniffRequest();

		m_MessageType[p->TypeID()]=p;


		p=new CIPCMessagePCInfo();
		m_MessageType[p->TypeID()]=p;

		p=new CIPCMessageMessage();
		m_MessageType[p->TypeID()]=p;

		p=new CIPCMessageIDValue();
		m_MessageType[p->TypeID()]=p;

		p=new CIPCMessageGroundSetting();
		m_MessageType[p->TypeID()]=p;
		p=new CIPCMacOnOff();
		m_MessageType[p->TypeID()]=p;

		p=new CIPCMessageSetName();
		m_MessageType[p->TypeID()]=p;

		p=new CIPCMessageStatus();
		m_MessageType[p->TypeID()]=p;

		p=new CIPCMessageSetSpeed();
		m_MessageType[p->TypeID()]=p;


}

} /* namespace NETCUT_CORE_FUNCTION */
