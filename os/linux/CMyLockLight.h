/*
 * CMyLockLight.h
 *
 *  Created on: Dec 17, 2015
 *      Author: victor
 */

#ifndef OS_LINUX_CMYLOCKLIGHT_H_
#define OS_LINUX_CMYLOCKLIGHT_H_

#include <CMyLockBase.h>
#include <pthread.h>

namespace NETCUT_CORE_FUNCTION {

class CMyLockLight: public CMyLockBase {
public:
	CMyLockLight();
	virtual ~CMyLockLight();
	void unlock();
	void lock();
private:
	pthread_mutex_t m_lock;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_CMYLOCKLIGHT_H_ */
