/*
 * CMyLock.h
 *
 *  Created on: Dec 17, 2015
 *      Author: victor
 */

#ifndef OS_LINUX_CMYLOCK_H_
#define OS_LINUX_CMYLOCK_H_

#include <CMyLockBase.h>


#include <mutex>
namespace NETCUT_CORE_FUNCTION {




class CMyLock: public CMyLockBase {
public:
	CMyLock();
	virtual ~CMyLock();

	void unlock();
	void lock();
	bool m_btrace;
	private:

		std::recursive_mutex m_lock; /* lock */

};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_CMYLOCK_H_ */
