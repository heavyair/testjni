/*
 * CThreadWorker.h
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#ifndef OS_LINUX_CTHREADWORKER_H_
#define OS_LINUX_CTHREADWORKER_H_

#include "CThreadBase.h"
#include <pthread.h>
namespace NETCUT_CORE_FUNCTION {

class CThreadWorker: public CThreadBase {
public:
	CThreadWorker();
	virtual ~CThreadWorker();

  void StartThread(void *(*p_func) (void *), void *  p_parent);
  void WaitThreadExit();

	pthread_t m_ThreadHandle;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_CTHREADWORKER_H_ */
