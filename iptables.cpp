/*
 * iptables.c
 *
 *  Created on: Feb 20, 2015
 *      Author: root
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include "iptables.h"
#include "netheader.h"

using namespace std;

bool iptables_commands(const char * p_sCmd)
{

	int r=system(p_sCmd);
	//TRACE("System command %s return code %d\n",p_sCmd,r);
	if(r==0)
    return true;

	return false;
}

bool GetIpforward()
{

	    ifstream myfile;
	    myfile.open(IP4_FORWARD_SWITCH_FILE, ios::in | ios::binary);
	    char b='0';

	    if (myfile.is_open()) {

	    	myfile.seekg(0, ios::beg);
	    	myfile.read(&b, 1);
	    	}

	    myfile.close();
	    bool ret=b=='1'?true:false;
	    return ret;
}
void EnableIpforward(bool p_bTrue)
{
	if(p_bTrue)
	FileWrite(IP4_FORWARD_SWITCH_FILE,"1");
	else
	FileWrite(IP4_FORWARD_SWITCH_FILE,"0");
}

void EnableRedirect(std::string p_sInterfaceName,bool p_bEnable)
{
	string sFilename;
	sFilename.append("/proc/sys/net/ipv4/conf/");
	sFilename.append(p_sInterfaceName);
	sFilename.append("/send_redirects");

	if(p_bEnable)
	{
	FileWrite(IP4_ICMP_REDIRECT_FILE,"1");

	FileWrite(sFilename,"1");
	}
	else
	{
	FileWrite(IP4_ICMP_REDIRECT_FILE,"0");
	FileWrite(sFilename,"0");
	}
}
void FileWrite(std::string sFilename,std::string sData)
{

    ofstream myfile;
    myfile.open(sFilename, ios::out | ios::binary);
    if(myfile.fail()) return;
    myfile.write((char *)sData.c_str(),sData.size());
	myfile.close();
}
