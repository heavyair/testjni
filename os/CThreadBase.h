/*
 * CThreadBase.h
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#ifndef CTHREADBASE_H_
#define CTHREADBASE_H_

namespace NETCUT_CORE_FUNCTION {

class CThreadBase {
public:
	CThreadBase();
	virtual ~CThreadBase();
	virtual void StartThread(void *(* p_func) (void * ),void* p_parent)=0;
	virtual void WaitThreadExit()=0;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CTHREADBASE_H_ */
