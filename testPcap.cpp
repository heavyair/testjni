//============================================================================
// Name        : testPcap.cpp
// Author      : Victor Liu
// Version     :
// Copyright   : 
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "Cpcapclass.h"
#include <CHttpAccountUpdater.h>
#include "netheader.h"
#include <CNetCard2.h>

#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <COpenSSL.h>

#include "netfilterqueue.h"

using namespace std;



Cpcapclass *test = NULL;

void exit_cleanup()
{
	if (test != NULL)
	{
		    test->StopServer();
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


	/*s
	COpenSSL c;
	std::string enc;
	std::string out;
	//c.testAES("1234567812345678","12345678901234567890012345678909999999999",true,enc);

std::string sMac="YmD6nOYyYVxb+D9JK7WQ2uKr07dCcCh/57nsX5ctEygyuxUAQQPPqMNrqDMR8KmyOB6amMcfZEjGGloTc9Yp4SY+pg6oTeGoHxnk3qaJVRDF5bsXcMQ+559J0BkJKZVtbXWqwSZoxuAM3SnTaJcDXxrzDYLXevRPCAgK8EZIvIct+LeFqKCUtYuAqQqVDdOx2rN2BET39GHJiusAeCw356IuQdxysm69Gpsnj+ZSMY2WqhBwOlMXX7kfeKDQSc5Ao8OVcIHwocRzUtBCZT5ujFr3Hx6O+mZtpfEJCHznzJdeoKBOnVIG12cI0qPnnkIIEdAb9c2tPZuqPT9sySmIscFhhpNErH/NG1A76tysvdMTz6NDa2Y+x4c81/rFBMywsPaDIhexK6pF+Q+pkpuclrkCGL/4X8+OzDI6oxq/CS+NtN4p9RWMt1+csGu2eQ7ZL8P2I3okQYa2oatR+Emtpj6/FE00r1fPCzmQhpvHujqZndLf2PHzF6hi5XKOL3QZyJLUMa9SAOkTYv+9ng2/xnbjpkaOZ+PbpXRDSv3YkkvyoeXeEKK+0qgx/eFB6q2jS60qmUbTWo1pyMEMj6hAJGc51pjwW4aykf3BXXWvYuBCczP1zLiQtC7Jk77tyy4r9W9iGrAcsMDV/2j0UJJ16zLF24yA9gtCYjZkwnF8QsY=";


	out=c.RsaDecode(sMac);
	//c.testAES("1234567812345678",enc,false,out);

	//enc=c.aes_encode("12345678901234567890012345678909999999999","1234567812345678");

	//out=c.aes_decode(enc.c_str(),"1234567812345678");

	TRACE("result %s\n",out.c_str());
*/

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

  	test = new Cpcapclass();

  	test->Run();
/*

	CPacketReader test;
	test.SetDeviceName("wlan0");
	test.StartSniff();
*/

  	pause();

	return 0;






}

