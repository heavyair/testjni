/*
 * CGrounded.h
 *
 *  Created on: Jun 9, 2015
 *      Author: root
 */

#ifndef CGROUNDED_H_
#define CGROUNDED_H_
#include "netheader.h"
#include <list>
#define GROUND_TYPE_ONETIME 0
#define GROUND_TYPE_DAILY 1

struct GroundUnit
{
	int32_t nType; //0 One time, 1 Daily
	int32_t nStartHour;   //When Type 0, it's the Start seconds in UTC /in 1, it's current local HOUR
	int32_t nStartMinutes;
	int32_t nEndHour;     //When Type 0, it's the finish seconds in UTC
	int32_t nEndMinutes;

};
class CGrounded {
public:
	CGrounded();
	virtual ~CGrounded();


	virtual bool IsGrounded();
	virtual void GroundedRoutine();

	CGrounded& operator=( const CGrounded& other );
	CGrounded( const CGrounded& other);

   void Save2File(ofstream &p_IOStream);
   void LoadFromFile(char * & buff);

   bool Save2Buffer(char * p_BufStart, int& p_nBufSize);
   unsigned long GetGroundLeftSeconds();
   void DisableTimer();

   bool HasGroundedSetting();
   void SetGround(int p_nType,int p_nStartHour, int p_nStartMin,int p_nEndHour,int p_nEndMin);
   void SetGround(GroundUnit p_Unit);
   void RemoveGround(int p_nType);
   void GetGroundInfo(int p_nType,int& p_nStartHour, int& p_nStartMin,int& p_nEndHour,int& p_nEndMin);
   GroundUnit GetGroundInfo(int p_nType);
public:
   MACADDR mac;
   list<GroundUnit> m_GroundUnits;
   unsigned long m_nGroundedLeftSeconds;
   unsigned long m_nDisableTimer;

private:
   unsigned long GroundedLeftSeconds();
   recursive_mutex m_lock;

};

#endif /* CGROUNDED_H_ */
