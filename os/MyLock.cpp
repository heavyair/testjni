/*
 * MyLock.cpp
 *
 *  Created on: Mar 11, 2015
 *      Author: root
 */

#include <MyLock.h>
#include <thread>

MyLock::MyLock() {
	// TODO Auto-generated constructor stub

}

MyLock::~MyLock() {
	// TODO Auto-generated destructor stub
}

void MyLock::unlock()
{


//TRACE("Thread %lu Unlocking %d\n",std::this_thread::get_id(),(int)this);
m_lock.unlock();
//TRACE("Thread %lu Unlocked %d\n",std::this_thread::get_id(),(int)this);
}

void MyLock::lock()
{

	//TRACE("Thread %lu locking %d\n",std::this_thread::get_id(),(int)this);
	m_lock.lock();
	//TRACE("Thread %lu locked %d\n",std::this_thread::get_id(),(int)this);
}
