/*
 * CNetcutEvent.cpp
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#include <CNetcutEvent.h>
#include <errno.h>

namespace NETCUT_CORE_FUNCTION {

CNetcutEvent::CNetcutEvent() {
	// TODO Auto-generated constructor stub

	this->m_Events=neosmart::CreateEvent(true, false);
}

CNetcutEvent::~CNetcutEvent() {
	// TODO Auto-generated destructor stub

	if(m_Events)
	{
	 neosmart::DestroyEvent(m_Events);
	}
}



bool CNetcutEvent::WaitForEvent(unsigned long milliseconds) {

	int nRet= neosmart::WaitForEvent(m_Events,milliseconds);
    if(nRet== ETIMEDOUT) return false;
    return nRet==0?true:false;

}
int CNetcutEvent::SetEvent() {

	return neosmart::SetEvent(this->m_Events);

}
int CNetcutEvent::ResetEvent() {
	return neosmart::ResetEvent(this->m_Events);
}

} /* namespace NETCUT_CORE_FUNCTION */
