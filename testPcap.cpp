//============================================================================
// Name        : testPcap.cpp
// Author      : Victor Liu
// Version     :
// Copyright   : 
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "Cpcapclass.h"

#include "netheader.h"
#include <CNetCard2.h>

#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>

#include "netfilterqueue.h"

using namespace std;



Cpcapclass *test = NULL;

void exit_cleanup()
{
	if (test != NULL)
	{
			delete test;
			test=NULL;
	}
}
void exit_handler(int s) {
	printf("Caught signal %d\n", s);
	exit_cleanup();
	exit(0);

}



int main(int argc, char * * argv) {

	/*
	int m_nEventFD=eventfd(0,0);
	char mess[8];
	int8_t num=1;
	int8_t number=0;
	memcpy(mess,&num,sizeof(num));
	int s = write(m_nEventFD, mess, sizeof(mess));
	if (s != 8) {
		TRACE("Error write to Envent FD\n");
	}
    char buff[8];
				int n = read(m_nEventFD, buff, 8);
				if (n == 8) {

					memcpy(&number,buff,sizeof(number));


				}

				TRACE("number is %d",number);

*/

	/*


	filterrules r;
	memset(&r,0,sizeof(filterrules));

	r.nDstIP=CAddressHelper::StrIP2Int("23.239.9.165");
	nq->SetFilterRule(r, nq->RULETYPE::TEST);

	memset(&r, 0, sizeof(filterrules));

	r.nSrcIP = CAddressHelper::StrIP2Int("192.168.1.104");
	nq->SetFilterRule(r, nq->RULETYPE::NAT);

	memset(&r, 0, sizeof(filterrules));

	r.nDstIP = CAddressHelper::StrIP2Int("192.168.1.2");
	nq->SetFilterRule(r, nq->RULETYPE::NAT);



	netfilterqueue * nq=new netfilterqueue();
	nq->SetNAT(CAddressHelper::StrIP2Int("192.168.1.104"),CAddressHelper::StrIP2Int("255.255.255.0"),CAddressHelper::StrIP2Int("192.168.1.2"),CAddressHelper::StrIP2Int("192.168.1.1"));
 //   nq->SetDrop(CAddressHelper::StrIP2Int("192.168.1.103"));
   	nq->BindQueue("wlan0",0);

*/
//	CAddressHelper::isSameRang(CAddressHelper::StrIP2Int("192.168.1.104"),CAddressHelper::StrIP2Int("173.87.23.11"),CAddressHelper::StrIP2Int("255.255.255.0"));

/*
	string sSpacer="st";
	TRACE("spacer [%s]",sSpacer.c_str());
	string str="Test: abc";
			int n=str.find(sSpacer);
			if(n!=string::npos)
			{
				string sName=str.substr(0,n);
				string sValue=str.substr(n+sSpacer.size(),str.size()-sSpacer.size());
				TRACE("Name [%s] value[%s]",sName.c_str(),sValue.c_str());
			}
*/
/*
    map<DWORD,MACADDR> arpmap=CAddressHelper::GetARPCache();

   	map<DWORD,MACADDR>::iterator it;

    	for (it = arpmap.begin(); it != arpmap.end(); ++it) {
    		MACADDR &sMac = (*it).second;
    		const DWORD &nIP=(*it).first;
    		 TRACE("IP %s Mac %s\n",CAddressHelper::IntIP2str(nIP).c_str(),CAddressHelper::BufferMac2str(sMac.data()).c_str());
    		}

*/





	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = exit_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
	sigaction(SIGTERM, &sigIntHandler, NULL);
	sigaction(SIGQUIT, &sigIntHandler, NULL);

	signal(SIGINT, exit_handler);


	CAddressHelper::m_argv=argv;

	std::string dev = "wlan0";
	if(argc>1)
	{
		string arg=argv[1];
		if(arg.find("-v")!=string::npos)
		{
		printf("%s\n",ANDROID_NETCUTVERSION);
		exit(0);
		}

		dev=argv[1];


	}

	CAddressHelper::m_sMyCmdLine=dev;

/*	CPacketSender s;
	s.SetDevName("wlan0");
	s.sendTCP(102,102,80,80,1,1024,TH_SYN,NULL,0);
*/
  	test = new Cpcapclass();
  	test->Run();

  	//sleep(10);
  //	delete test;

  	pause();

	return 0;






}

