/*
 * CMyLock.cpp
 *
 *  Created on: Dec 17, 2015
 *      Author: victor
 */

#include <CMyLock.h>
#include <thread>

namespace NETCUT_CORE_FUNCTION {

CMyLock::CMyLock() {
	// TODO Auto-generated constructor stub
	m_btrace=false;
}

CMyLock::~CMyLock() {
	// TODO Auto-generated destructor stub
}



void CMyLock::unlock()
{


//TRACE("Thread %lu Unlocking %d\n",std::this_thread::get_id(),(int)this);
m_lock.unlock();
//TRACE("Thread %lu Unlocked %d\n",std::this_thread::get_id(),(int)this);
}

void CMyLock::lock()
{

	//TRACE("Thread %lu locking %d\n",std::this_thread::get_id(),(int)this);
	m_lock.lock();
	//TRACE("Thread %lu locked %d\n",std::this_thread::get_id(),(int)this);
}

} /* namespace NETCUT_CORE_FUNCTION */
