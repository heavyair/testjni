/*
 * CIPCMessage.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: root
 */

#include <CIPCMessage.h>


namespace NETCUT_CORE_FUNCTION {

CIPCMessage::CIPCMessage() {
	// TODO Auto-generated constructor stub

	m_pBufferMessage=NULL;
	m_nMessageSize=0;


}

CIPCMessage::~CIPCMessage() {
	// TODO Auto-generated destructor stub
}

bool CIPCMessage::Read(int s) {

  if(m_pBufferMessage==NULL) return false;

	int nReadCount = recv(s, m_pBufferMessage+sizeof(int32_t)+sizeof(int32_t), m_nMessageSize-sizeof(int32_t)-sizeof(int32_t), 0);

	if (nReadCount != m_nMessageSize-sizeof(int32_t)-sizeof(int32_t)) {

		return false;

	} else {
		return true;
	}

}


bool CIPCMessage::write(int s) {

	if(m_pBufferMessage==NULL) return false;

//	if(send(s, (const void *) m_nMessageSize, sizeof(m_nMessageSize), 0)<0) return false;

	int n = send(s, (const void *) m_pBufferMessage, m_nMessageSize, 0);

	if (n < 0) {

		return false;

	} else {

		return true;
	}
}


CIPCMessage * CIPCMessage::Create() {

	return 0;
}

const int32_t CIPCMessage::TypeID() const {
  if(this->m_pBufferMessage==NULL) return 0;
  return (int32_t) * (int32_t *)(m_pBufferMessage+sizeof(int32_t));
}

} /* namespace NETCUT_CORE_FUNCTION */
