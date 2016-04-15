/*
 * CGrounded.cpp
 *
 *  Created on: Jun 9, 2015
 *      Author: root
 */

#include "CGrounded.h"
#include "CAddressHelper.h"
#include <time.h>

CGrounded::CGrounded() {
	// TODO Auto-generated constructor stub
	m_nDisableTimer=0;
}

CGrounded::~CGrounded() {
	// TODO Auto-generated destructor stub
}

CGrounded::CGrounded(const CGrounded& other) {

	(*this) = other;
}

CGrounded& CGrounded::operator=(const CGrounded& other) {

	this->mac = other.mac;
	this->m_GroundUnits = other.m_GroundUnits;
	this->m_nDisableTimer=other.m_nDisableTimer;
	this->m_nGroundedLeftSeconds=other.m_nGroundedLeftSeconds;
	GroundedRoutine();
	return *this;
}

bool CGrounded::Save2Buffer(char * p_BufStart, int& p_nBufSize) {

	int nTotalSize=6+4+20*m_GroundUnits.size();
	p_nBufSize=nTotalSize;
	if (p_nBufSize < nTotalSize)
	{
		p_nBufSize=nTotalSize;
		return false;
	}

	char * p = p_BufStart;

	int32_t nSize = 6;

	memcpy(p, (char *) mac.data(), nSize);
	p += 6;
	nSize = m_GroundUnits.size();
	memcpy(p, (char *) &nSize, sizeof(int32_t));
	p += sizeof(int32_t);

	list<GroundUnit>::iterator it;

	for (it = m_GroundUnits.begin(); it != m_GroundUnits.end(); ++it) {
		GroundUnit n = *it;

		memcpy(p, (char *) &n, sizeof(n));
		p += sizeof(n);
	}
	return true;

}
void CGrounded::Save2File(ofstream &p_IOStream) {
	m_lock.lock();
	int nBufSize=126;
	char buf[nBufSize];

	if(this->Save2Buffer(buf, nBufSize))
	{
		p_IOStream.write(buf, nBufSize);

	}

	m_lock.unlock();
}
void CGrounded::LoadFromFile(char * & buff) {
	m_lock.lock();
	int32_t nSize;
	mac = CAddressHelper::MacBuffer2Array((u_char *) buff);
	TRACE("Loading %s schedule offline\n",CAddressHelper::BufferMac2str(mac.data()).c_str());
	buff += 6;    //We got mac
	memcpy(&nSize, buff, sizeof(nSize)); //  we got total count
	int32_t nCount = nSize;
	buff += sizeof(int32_t);

	for (int i = 0; i < nCount; i++) {
		GroundUnit n;
		memcpy(&n, buff, sizeof(n));
		buff += sizeof(n);
		m_GroundUnits.push_back(n);
	}
	m_lock.unlock();

}
bool CGrounded::HasGroundedSetting() {

	return (m_GroundUnits.size() > 0);

}
unsigned long CGrounded::GroundedLeftSeconds() {

	m_lock.lock();
    unsigned long nLeftSeconds=0;
	bool bret = false;

	do {
		time_t gmcTime = time(NULL);
		struct tm *aTime = localtime(&gmcTime);


		int32_t  mtime, seconds, useconds;



		seconds = gmcTime;//start.tv_sec;

		int32_t nDaySeconds = seconds - aTime->tm_hour * 60 * 60
				- aTime->tm_sec;

		for (std::list<GroundUnit>::iterator it = m_GroundUnits.begin();
				it != m_GroundUnits.end(); ++it) {
			GroundUnit n = *it;
		//	TRACE("TYpe %d Start Hour %d, Finish Hour %d\n",n.nType,n.nStartHour,n.nEndHour);
			if (n.nType == 0 && n.nStartHour<n.nEndHour && seconds<n.nEndHour ) {
				nLeftSeconds=n.nEndHour-seconds>nLeftSeconds?(n.nEndHour-seconds):nLeftSeconds;
			}

			if (n.nType == 1) {
			             time_t rawtime;
						 time ( &rawtime );
						 struct tm * starttime = localtime ( &rawtime );
						 starttime->tm_hour=n.nStartHour;
						 starttime->tm_min=n.nStartMinutes;

						 int32_t nStartSeconds = mktime(starttime);

						 struct tm * endTime = localtime ( &rawtime );
						 endTime->tm_hour=n.nEndHour;
						 endTime->tm_min=n.nEndMinutes;

						 int32_t nFinishSeconds =mktime(endTime);
						 int nTempSeconds=0;
				if(nFinishSeconds<nStartSeconds)
				{
					int32_t	nNextFinishSeconds=nFinishSeconds+(24*60*60);
					int32_t nNextStartSeconds=nStartSeconds;

					int32_t	nFirstFinishSeconds=nFinishSeconds;
					int32_t nFirstStartSeconds=nStartSeconds-(24*60*60);

					if (nFirstStartSeconds < seconds && seconds < nFirstFinishSeconds) {
							nTempSeconds=nFirstFinishSeconds- seconds;
							if(nFirstStartSeconds>m_nDisableTimer&&nTempSeconds>0)
													m_nDisableTimer=0;
					}
					if (nNextStartSeconds < seconds && seconds < nNextFinishSeconds) {
							nTempSeconds=nNextFinishSeconds- seconds;
							if(nNextStartSeconds>m_nDisableTimer&&nTempSeconds>0)
								m_nDisableTimer=0;
					}

				}
				else
				{
					if(nStartSeconds < seconds && seconds < nFinishSeconds) {
					nTempSeconds=nFinishSeconds- seconds;
					if(nStartSeconds>m_nDisableTimer&&nTempSeconds>0)
											m_nDisableTimer=0;
			     	}
				}

					if(nTempSeconds>nLeftSeconds)
					{
						nLeftSeconds=nTempSeconds;
					}
			}
		}
	}
 while (false);

	m_lock.unlock();
	return nLeftSeconds;

}

bool CGrounded::IsGrounded() {

	m_lock.lock();
	bool bStat = m_nGroundedLeftSeconds>0;
	if(m_nDisableTimer>0) bStat=false;
	m_lock.unlock();
	return bStat;

}

unsigned long CGrounded::GetGroundLeftSeconds()
{

	m_lock.lock();

	unsigned long n=m_nGroundedLeftSeconds;

   m_lock.unlock();
   return n;

}

void CGrounded::GroundedRoutine()
{
	m_lock.lock();

	unsigned long nGroundSeconds=GroundedLeftSeconds();
	if(m_nDisableTimer==0)
		m_nGroundedLeftSeconds=nGroundSeconds;

	m_lock.unlock();


}
void CGrounded::DisableTimer()
{
	m_lock.lock();

	m_nDisableTimer=time(NULL);
	m_nGroundedLeftSeconds=0;

	for (std::list<GroundUnit>::iterator it = m_GroundUnits.begin();
				it != m_GroundUnits.end(); ++it) {
			GroundUnit &OldUnit = *it;
			if (OldUnit.nType == 0) {
				memset(&OldUnit,0,sizeof(OldUnit));

			}

		}

	m_lock.unlock();

}
void CGrounded::SetGround(GroundUnit p_Unit) {

	m_lock.lock();
	m_nDisableTimer=0;

	bool bFound = false;
	for (std::list<GroundUnit>::iterator it = m_GroundUnits.begin();
			it != m_GroundUnits.end(); ++it) {
		GroundUnit &OldUnit = *it;
		if (OldUnit.nType == p_Unit.nType) {
			OldUnit = p_Unit;
			bFound = true;
			break;
		}

	}

	if (!bFound) {
		m_GroundUnits.push_back(p_Unit);
	}
	GroundedRoutine();
	m_lock.unlock();
}
void CGrounded::SetGround(int p_nType, int p_nStartHour, int p_nStartMin,
		int p_nEndHour, int p_nEndMin) {
	m_lock.lock();
	GroundUnit n;
	n.nType = p_nType;
	n.nStartHour = p_nStartHour;
	n.nEndHour = p_nEndHour;
	n.nStartMinutes = p_nStartMin;
	n.nEndMinutes = p_nEndMin;
	SetGround(n);

	m_lock.unlock();
}
void CGrounded::RemoveGround(int p_nType) {
	m_lock.lock();
	for (std::list<GroundUnit>::iterator it = m_GroundUnits.begin();
			it != m_GroundUnits.end(); ++it) {
		GroundUnit OldUnit = *it;
		if (OldUnit.nType == p_nType) {
			m_GroundUnits.erase(it);
			break;
		}
	}

	m_lock.unlock();
}

GroundUnit CGrounded::GetGroundInfo(int p_nType) {

	m_lock.lock();
	GroundUnit g;
	memset(&g,0,sizeof(g));
	for (std::list<GroundUnit>::iterator it = m_GroundUnits.begin();
			it != m_GroundUnits.end(); ++it) {
		GroundUnit& OldUnit = *it;
		if (OldUnit.nType == p_nType) {
			g=OldUnit;
			break;
		}
	}
	m_lock.unlock();
	return g;
}


void CGrounded::GetGroundInfo(int p_nType, int& p_nStartHour, int& p_nStartMin,
		int& p_nEndHour, int& p_nEndMin) {
	m_lock.lock();
	for (std::list<GroundUnit>::iterator it = m_GroundUnits.begin();
			it != m_GroundUnits.end(); ++it) {
		GroundUnit OldUnit = *it;
		if (OldUnit.nType == p_nType) {
			p_nStartHour = OldUnit.nStartHour;
			p_nStartMin = OldUnit.nStartMinutes;
			p_nEndHour = OldUnit.nEndHour;
			p_nEndMin = OldUnit.nEndMinutes;
			break;
		}
	}
	m_lock.unlock();
}


