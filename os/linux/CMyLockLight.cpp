/*
 * CMyLockLight.cpp
 *
 *  Created on: Dec 17, 2015
 *      Author: victor
 */

#include <CMyLockLight.h>

namespace NETCUT_CORE_FUNCTION {

CMyLockLight::CMyLockLight() {
	// TODO Auto-generated constructor stub
	pthread_mutex_init(&m_lock, NULL);
}

CMyLockLight::~CMyLockLight() {
	// TODO Auto-generated destructor stub
	pthread_mutex_destroy(&m_lock);
}


void CMyLockLight::unlock()
{



			pthread_mutex_unlock(&m_lock);
}

void CMyLockLight::lock()
{

//	TRACE("Thread %d locking\n",std::this_thread::get_id());
	pthread_mutex_lock(&m_lock);



}

} /* namespace NETCUT_CORE_FUNCTION */
