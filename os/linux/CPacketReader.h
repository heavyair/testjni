/*
 * CPacketReader.h
 *
 *  Created on: Dec 15, 2015
 *      Author: victor
 */

#ifndef OS_LINUX_CPACKETREADER_H_
#define OS_LINUX_CPACKETREADER_H_

#include "CSniffer.h"
#include "CNetcutEvent.h"
#include "CThreadWorker.h"
#include <PointerQueue.h>
#include <pcap.h>


namespace NETCUT_CORE_FUNCTION {

class CPacketReader: public CSniffer {
public:
	CPacketReader();
	virtual ~CPacketReader();

	     void StartSniff();
	     void StopSniff();
	  //   bool IsWorking();

	     CNetcutEvent m_EventStop;
protected:
/*

	    	static	void threadGot_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	   		void threadGot_packetRun(const struct pcap_pkthdr *header, const u_char *packet);

	     static void* threadPacketWorker(void *para);
	        		void threadPacketWorkerRun();

	        		    void threadSnifferRun();
 CThreadWorker m_ThreadPacketWorker;
   bool CallbackGotPdu(const PDU &pdu);
	        		*/
	     static void* threadSniffer(void *para);

	     void threadSnifferRun();
	   //  void threadTinsSnifferRun();


	     static	void Got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	      void Got_packetRun(const struct pcap_pkthdr *header, const u_char *packet);


	     CThreadWorker m_ThreadSniff;


	     pcap_t * m_PcapHandle;
	     //Sniffer *m_PSnifferPointer;
	     char m_sErrbuf[PCAP_ERRBUF_SIZE];  //less stack memory apply/release  256 byte

	  //   PointerQueue<sniffitem *> m_sniffqueue;

}; /* namespace NETCUT_CORE_FUNCTION */

}

#endif /* OS_LINUX_CPACKETREADER_H_ */
