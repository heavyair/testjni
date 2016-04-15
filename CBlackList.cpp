/*
 * CBlackList.cpp
 *
 *  Created on: Jan 13, 2015
 *      Author: root
 */

#include "CBlackList.h"

CBlackList::CBlackList() {
	// TODO Auto-generated constructor stub

}

CBlackList::~CBlackList() {
	// TODO Auto-generated destructor stub
}



CBlackList::CBlackList(const CBlackList& other) {

	(*this) = other;
}

CBlackList& CBlackList::operator=(const CBlackList& other) {

	this->IPs=other.IPs;
	this->hostname=other.hostname;
    this->mac=other.mac;

	return *this;
}

CBlackList::CBlackList(CComputer & p_Computer) {
	mac=p_Computer.GetMacArray();
	p_Computer.GetIPs(IPs);
	hostname = p_Computer.GetName();
}
void CBlackList::Save2File(ofstream &p_IOStream)
{
	    DWORD nSize=6;

	    p_IOStream.write((char *)&nSize,sizeof(nSize));
	    p_IOStream.write((char *)mac.data(),nSize);
	    nSize=IPs.size();

	    p_IOStream.write((char *)&nSize,sizeof(nSize));

	    map<DWORD, bool>::iterator it;

	    	for (it = IPs.begin(); it != IPs.end(); ++it) {
	    		DWORD ip = (*it).first;
	    		p_IOStream.write((char *)&ip,sizeof(ip));
	    		   	}

         nSize=hostname.size();
         p_IOStream.write((char *)&nSize,sizeof(nSize));
	     p_IOStream.write(hostname.c_str(),hostname.size());

}

void CBlackList::LoadFromFile(char * & buff) //reference to pointer to file buffer, move as goes
{

	 DWORD nSize;
	 memcpy(&nSize,buff,sizeof(nSize)); //got mac str len
	 buff+=sizeof(nSize);
     mac=CAddressHelper::MacBuffer2Array((u_char *)buff);
     buff+=nSize;    //We got mac
     memcpy(&nSize,buff,sizeof(nSize)); //  we got total IPs count
     int nIPCount=nSize;
     buff+=sizeof(nSize);

     for(int i=0;i<nIPCount;i++)
     {
     DWORD nIP=0;
     memcpy(&nIP,buff,nSize);
     this->IPs[nIP]=false;
     buff+=sizeof(DWORD);
     }

     memcpy(&nSize,buff,sizeof(nSize));  // we got hostname length
     buff+=sizeof(nSize);
     hostname.append(buff,nSize);
     buff+=nSize;    //We got hostname

}
