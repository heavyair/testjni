/*
 * CNetcutEvent.h
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#ifndef OS_LINUX_CNETCUTEVENT_H_
#define OS_LINUX_CNETCUTEVENT_H_

#include <pevents.h>
#include <CEventBase.h>
using namespace neosmart;

namespace NETCUT_CORE_FUNCTION {

class CNetcutEvent: public CEventBase {
public:
	CNetcutEvent();
	virtual ~CNetcutEvent();

	      //  virtual void CreateEvent(bool manualReset = true, bool initialState = false);

		//	virtual bool WaitForEvent(uint64_t milliseconds = -1);
			virtual bool WaitForEvent(unsigned long milliseconds = -1);
			virtual int SetEvent();
			virtual int ResetEvent();

protected:
			 neosmart_event_t  m_Events;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_CNETCUTEVENT_H_ */
