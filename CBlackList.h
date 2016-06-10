/*
 * CBlackList.h
 *
 *  Created on: Jan 13, 2015
 *      Author: root
 */

#ifndef CBLACKLIST_H_
#define CBLACKLIST_H_
#include "netheader.h"
#include <list>
#include <map>
#include "CComputer.h"

class CBlackList {
public:
	CBlackList();
	virtual ~CBlackList();

	CBlackList& operator=( const CBlackList& other );
	CBlackList( const CBlackList& other);

	  CBlackList(CComputer & p_Computer);

	   void Save2File(ofstream &p_IOStream);
	   void LoadFromFile(char * & buff);

public:
		//u_char  mac[6];
		MACADDR mac;
		map<DWORD,bool> IPs;
		string hostname;
		int nSpeedLimit;

};

#endif /* CBLACKLIST_H_ */
