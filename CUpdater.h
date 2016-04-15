/*
 * CUpdater.h
 *
 *  Created on: Apr 27, 2015
 *      Author: root
 */

#ifndef CUPDATER_H_
#define CUPDATER_H_

#include "netheader.h"

using namespace std;

class CUpdater {
public:
	CUpdater(string p_sName,string p_sVersion,string p_sI);
	virtual ~CUpdater();

	bool UpdateWorker();
	bool SaveUrl2File(string p_sUrl,string p_sDstPath);

string m_sName;
string m_sVersion;
string m_sID;
bool m_bRequireUpdate;
bool m_bRequireReg;
};

#endif /* CUPDATER_H_ */
