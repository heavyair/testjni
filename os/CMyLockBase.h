/*
 * CMyLockBase.h
 *
 *  Created on: Dec 17, 2015
 *      Author: victor
 */

#ifndef OS_CMYLOCKBASE_H_
#define OS_CMYLOCKBASE_H_
#include "netheader.h"
namespace NETCUT_CORE_FUNCTION {

class CMyLockBase {
public:
	CMyLockBase();
	virtual ~CMyLockBase();

	virtual void unlock()=0;
	virtual void lock()=0;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_CMYLOCKBASE_H_ */
