/*
 * CThreadWorker.cpp
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#include "CThreadWorker.h"

namespace NETCUT_CORE_FUNCTION {

CThreadWorker::CThreadWorker() {
	// TODO Auto-generated constructor stub
	m_ThreadHandle=0;

}

CThreadWorker::~CThreadWorker() {
	// TODO Auto-generated destructor stub
	WaitThreadExit();
}

void CThreadWorker::StartThread( void *(* p_func) (void *),void* p_parent)
{
	m_ThreadHandle=0;
	pthread_create(&m_ThreadHandle, NULL, p_func, p_parent);

}
void CThreadWorker::WaitThreadExit()
{
	if (m_ThreadHandle != 0)
	{
		 pthread_join(m_ThreadHandle, NULL);
	}
	m_ThreadHandle=0;

}

} /* namespace NETCUT_CORE_FUNCTION */
