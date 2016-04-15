/*
 * CVerifyer.h
 *
 *  Created on: Mar 9, 2016
 *      Author: root
 */

#ifndef JNI_CVERIFYER_H_
#define JNI_CVERIFYER_H_

#include "netheader.h"

using namespace std;

namespace NETCUT_CORE_FUNCTION {

class CVerifyer {
public:
	CVerifyer();
	virtual ~CVerifyer();

	string m_sName;
	string m_sMac;
	string m_sGateMac;
	string m_sKnownGps;
	string m_sRealGps;
	string m_sAllMac;

	int m_nPaidFlag; //0 unknown, 1 paid, 2, unpaid
	map<MACADDR,int> m_MacAge;

	string GetReturn(string p_sKey);

	map<string,string> m_Return;

	bool Verify();
	/*
	 *
id=mac
gate=mac   Could be Empty
lastknowngps=xxx  Could be empty
realgps=xxx    Could be Empty
mac
mac
	 *
	 *
	 */
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* JNI_CVERIFYER_H_ */
