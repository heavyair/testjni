/*
 * CIOWatcher.h
 *
 *  Created on: Jan 6, 2016
 *      Author: root
 */

#ifndef OS_LINUX_CIOWATCHER_H_
#define OS_LINUX_CIOWATCHER_H_

#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <CNetcutTool.h>
#include <string.h>

namespace NETCUT_CORE_FUNCTION {

#define IOWATCHER_ID_EXIT 1

class CIOWatcher {
public:
	CIOWatcher();
	virtual ~CIOWatcher();
	virtual void Reset();
	virtual void SetFD(int p_nFDHandle);
	virtual bool IsIOON(int p_nFDHandle);
	virtual void SetEvent(int p_nEventID);
	virtual bool IsEventON(int p_nEventID);
	virtual bool WaitIO();
	virtual void ShutDown();


protected:
	int GetEvents();

	fd_set m_fds; /* list of read descriptors	*/
	int m_nfdmaxnum;
	int m_nEventFD;
	int8_t m_nEventID;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_CIOWATCHER_H_ */
