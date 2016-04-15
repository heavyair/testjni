/*
 * MyLock.h
 *
 *  Created on: Mar 11, 2015
 *      Author: root
 */

#ifndef OS_MYLOCK_H_
#define OS_MYLOCK_H_

#include "netheader.h"

class MyLock {
public:
	MyLock();
	virtual ~MyLock();

void unlock();
void lock();
private:

	recursive_mutex m_lock; /* lock */
};

#endif /* OS_MYLOCK_H_ */
