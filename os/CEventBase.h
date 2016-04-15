/*
 * CEventBase.h
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#ifndef OS_CEVENTBASE_H_
#define OS_CEVENTBASE_H_

namespace NETCUT_CORE_FUNCTION {

class CEventBase {
public:
	CEventBase();
	virtual ~CEventBase();

	//    virtual void CreateEvent(bool manualReset = true, bool initialState = false)=0;
		//virtual void DestroyEvent()=0;
		virtual bool WaitForEvent(unsigned long milliseconds = -1)=0;
		virtual int SetEvent()=0;
		virtual int ResetEvent()=0;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_CEVENTBASE_H_ */

