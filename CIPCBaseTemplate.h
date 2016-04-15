/*
 * CIPCBaseTemplate.h
 *
 *  Created on: Feb 1, 2016
 *      Author: root
 */

#ifndef CIPCBASETEMPLATE_H_
#define CIPCBASETEMPLATE_H_
#include <CIPCMessage.h>
namespace NETCUT_CORE_FUNCTION {

template<typename CREATECLASS,typename MEMBER_DATA,int32_t MESSAGE_TYPE_ID>class CIPCBaseTemplate : public CIPCMessage {
public:
	CIPCBaseTemplate();
	virtual ~CIPCBaseTemplate(){};

	virtual CIPCMessage * Create();
	virtual void Reset();
//	const	virtual int32_t TypeID() const;
	MEMBER_DATA m_message;
};

/*


template <typename CREATECLASS,typename MEMBER_DATA,int32_t MESSAGE_TYPE_ID> CIPCBaseTemplate<CREATECLASS,MEMBER_DATA,MESSAGE_TYPE_ID>::~CIPCBaseTemplate() {


}
*/



template <typename CREATECLASS,typename MEMBER_DATA,int32_t MESSAGE_TYPE_ID> CIPCBaseTemplate<CREATECLASS,MEMBER_DATA,MESSAGE_TYPE_ID>::CIPCBaseTemplate() {


	    m_pBufferMessage=(char *)&m_message;
		m_nMessageSize=sizeof(m_message);
		m_nMessageType=MESSAGE_TYPE_ID;
		//TRACE("Message Type %d Size %d\n",m_nMessageType,m_nMessageSize);
		Reset();

}

/*

template <typename CREATECLASS,typename MEMBER_DATA,int32_t MESSAGE_TYPE_ID>const int32_t CIPCBaseTemplate<CREATECLASS,MEMBER_DATA, MESSAGE_TYPE_ID>::TypeID() const{

    return MESSAGE_TYPE_ID;

}
*/
template <typename CREATECLASS,typename MEMBER_DATA,int32_t MESSAGE_TYPE_ID>void CIPCBaseTemplate<CREATECLASS,MEMBER_DATA, MESSAGE_TYPE_ID>::Reset(){

    	memset(&m_message,0,sizeof(MEMBER_DATA));

    	if(sizeof(MEMBER_DATA)>=sizeof(int32_t)*2)   //Set the header with message size, and message type
    	{
    		memcpy(m_pBufferMessage,&m_nMessageSize,sizeof(int32_t));
    		memcpy(m_pBufferMessage+sizeof(int32_t),&m_nMessageType,sizeof(int32_t));
    	}

}


template <typename CREATECLASS,typename MEMBER_DATA,int32_t MESSAGE_TYPE_ID>CIPCMessage * CIPCBaseTemplate<CREATECLASS,MEMBER_DATA, MESSAGE_TYPE_ID>::Create(){

	CREATECLASS *newMessage = new CREATECLASS();
	memcpy(newMessage->m_pBufferMessage,this->m_pBufferMessage,m_nMessageSize);
	return newMessage;

}

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CIPCBASETEMPLATE_H_ */
