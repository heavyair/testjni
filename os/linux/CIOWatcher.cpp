/*
 * CIOWatcher.cpp
 *
 *  Created on: Jan 6, 2016
 *      Author: root
 */

#include <CIOWatcher.h>
#include <unistd.h>

namespace NETCUT_CORE_FUNCTION {

CIOWatcher::CIOWatcher() {
	// TODO Auto-generated constructor stub
	m_nEventFD=eventfd(0,0);
	Reset();
}

CIOWatcher::~CIOWatcher() {
	// TODO Auto-generated destructor stub
	ShutDown();

}

void CIOWatcher::ShutDown()
{
	SetEvent(IOWATCHER_ID_EXIT);
}

void CIOWatcher::SetFD(int p_nFDHandle)
{
	FD_SET(p_nFDHandle, &this->m_fds);
	m_nfdmaxnum=m_nfdmaxnum<p_nFDHandle?p_nFDHandle:m_nfdmaxnum;
}

bool CIOWatcher::IsIOON(int p_nFDHandle)
{
	if (FD_ISSET(p_nFDHandle, &m_fds)) {
       return true;
	}
	return false;
}

void CIOWatcher::SetEvent(int p_nEventID)
{
	if(m_nEventFD==0) return;

		char mess[8];

    	int8_t num=p_nEventID;
		memcpy(mess,&num,sizeof(num));
		int s = write(this->m_nEventFD, mess, sizeof(mess));
		if (s != 8) {
			TRACE("Error write to Envent FD\n");
		}


}


bool CIOWatcher::IsEventON(int p_nEventID)
{
	return p_nEventID==this->m_nEventID?true:false;
}
void CIOWatcher::Reset()
{
			FD_ZERO(&m_fds);
			m_nfdmaxnum=0;
			m_nEventID=0;
			SetFD(m_nEventFD);

}

int CIOWatcher::GetEvents()
{
    	        char buff[8];
				int n = read(this->m_nEventFD, buff, 8);
				if (n == 8) {


					memcpy(&m_nEventID,buff,sizeof(m_nEventID));

				}

				return m_nEventID;
}
bool CIOWatcher::WaitIO()
{

	m_nfdmaxnum++;
	int n=0;
	if ((n= select(m_nfdmaxnum, &m_fds, 0, 0, NULL)) > 0)
	{
		if (IsIOON(m_nEventFD)) {

			if(IOWATCHER_ID_EXIT==GetEvents())
			{
			close(m_nEventFD);
			m_nEventFD=0;
			return false;
			}
			return true;
	    }  // Exit FD works, return false, to quit caller

		return true;
	}
	return false;
}

} /* namespace NETCUT_CORE_FUNCTION */
