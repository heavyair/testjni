/*
 * CNbtQuery.cpp
 *
 *  Created on: Jan 21, 2015
 *      Author: root
 */

#include "CNbtQuery.h"
#include "CAddressHelper.h"

static unsigned short bind_portno = 0;

int verbose = 0;
int no_inverse_lookup = FALSE;

int show_mac_address = FALSE;

static short dest_portno = 137;

CNbtQuery::CNbtQuery() {
	// TODO Auto-generated constructor stub
	m_ReadTimeout = 10000;
	m_sSocket = 0;

}

CNbtQuery::~CNbtQuery() {
	// TODO Auto-generated destructor stub
}

bool CNbtQuery::SetupSocket() {

	if (m_sSocket != 0)
	close(m_sSocket);
	m_sSocket = 0;

	//	char errbuf[256];
	struct sockaddr_in myaddr;

	this->m_sSocket = socket(PF_INET, SOCK_DGRAM, 0);

	if (!SOCKET_IS_VALID(m_sSocket)) {
		TRACE("ERROR: cannot create socket [%s]", NATIVE_ERROR);
		return false;
	}

	int b = 1;
	int rc;

	rc = setsockopt(m_sSocket, SOL_SOCKET, SO_BROADCAST, (char *) &b, sizeof b);

	if (rc != 0) {
		TRACE("ERROR: can't set SO_BROADCAST [%s]", NATIVE_ERROR);
		close(m_sSocket);
		m_sSocket = 0;
		return false;
	}

	/*----------------------------------------------------------------
	 * Bind the local endpoint to receive our responses. If we use a
	 * zero, the system will pick one for us, or we can pick our own
	 * if we wish to make it easier to get past our firewall.
	 */
	memset(&myaddr, 0, sizeof myaddr);

	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY );
	myaddr.sin_port = htons(bind_portno);

	if (bind_in(m_sSocket, &myaddr) != 0)
	{
		TRACE("ERROR: cannot bind to local socket [%s]", strerror(errno));
		close(m_sSocket);
		m_sSocket = 0;
		return false;
	}

	//TRACE("Bound to %s.%d\n", inet_ntoa(myaddr.sin_addr),ntohs(myaddr.sin_port));

	return true;

}
void CNbtQuery::Query(const DWORD & p_nIP) {

	srand((unsigned int) _helper_GetMiTime());
	short seq = rand();

	if (!SOCKET_IS_VALID(m_sSocket))
	{
		if(!SetupSocket()) return;
	}


	struct sockaddr_in dst;
	struct NMBpacket pak;
	int sendlen;

	memset(&dst, 0, sizeof dst);

	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = p_nIP;
	dst.sin_port = htons(dest_portno);

	fill_namerequest(&pak, &sendlen, seq);

//	TRACE("SET IP %s ID %ud\n",CAddressHelper::IntIP2str(p_nIP).c_str(),ntohs(pak.tranid));

	if (-1 == sendpacket(this->m_sSocket, &pak, sendlen, &dst)) {
	//	TRACE("sending netbios query fail\n");
		SetupSocket();
 	}
	else
	{
	//TRACE("query netbios %s\n",CAddressHelper::IntIP2str(p_nIP).c_str());
	}
/*
 * 	else {
		this->SetIPTRansID(p_nIP, ntohs(pak.tranid));
	}
*/

}
void CNbtQuery::Query(string & p_sIP) {

	DWORD ip = CAddressHelper::StrIP2Int(p_sIP);
	this->Query(ip);
}

/*
 * fill_namerequest()
 *
 *	HACK: this creates a hand-crafter NMB packet that requests
 *	the NBTSTAT information. This was learned by sniffing a
 *	real transactions, and though we've learned what most of this
 *	means, we've not yet gone back to generalize it properly.
 *	We probably will.
 */
void CNbtQuery::fill_namerequest(struct NMBpacket *pak, int *len, short seq) {
	char *pbuf;

	assert(pak != 0);
	assert(len != 0);

	*len = 50;

	memset(pak, 0, *len);

	/* POPULATE THE HEADER */

	pak->tranid = htons(seq); /* transaction ID */
	pak->flags = 0;
	pak->qdcount = htons(1); /* query count */
	pak->ancount = 0;
	pak->nscount = 0;
	pak->arcount = 0;

	/*----------------------------------------------------------------
	 * Encode the NETBIOS name, which is really just a "*" that's
	 * fully padded out. Then add the status and name class at the
	 * end.
	 */
	pbuf = pak->data;

	pbuf += NETBIOS_pack_name("*", 0, pbuf);
	*pbuf++ = 0x00; /* length of next segment */

	*pbuf++ = 0x00; /* NODE STATUS */
	*pbuf++ = 0x21;

	*pbuf++ = 0x00; /* IN */
	*pbuf++ = 0x01;
}

string CNbtQuery::query_names(FILE *ofp, SOCKET sockfd, DWORD &p_nIP) {

	short seq = 1000;

	char errbuf[256];

	assert(ofp != 0);
	assert(SOCKET_IS_VALID(sockfd));

	struct sockaddr_in dst;
	struct NMBpacket pak;
	int sendlen;

	memset(&dst, 0, sizeof dst);

	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = p_nIP;
	dst.sin_port = htons(dest_portno);

	fill_namerequest(&pak, &sendlen, seq++);

	//	fprintf(ofp, "sending to %s\n", inet_ntoa(dst.sin_addr));

	/* yes, ignore response! */
	(void) sendpacket(sockfd, &pak, sendlen, &dst);

	/*----------------------------------------------------------------
	 * Figure out our starting and ending addresses to be scanning.
	 * These are treated as simple long integers that are incremented
	 * on each loop, and we must have at least one loop to be valid.
	 */

	fd_set rfds, /* list of read descriptors	*/
	wfds, /* list of write descriptors	*/
	*pwfds = 0;
	int n;
	struct timeval tv;

	/*--------------------------------------------------------
	 * Our select is just a bit tricky. We always are waiting
	 * on the read channel, but we only want to wait on the
	 * write channel if there are any more addresses in our
	 * list to process. After we've sent all the packets to
	 * the other end, we stop writing and do only reading.
	 */
	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = m_ReadTimeout;

	wfds = rfds;
	pwfds = &wfds;

	if ((n = select(sockfd + 1, &rfds, pwfds, 0, &tv)) == 0) {
		TRACE("*timeout (normal end of scan)\n");
		fflush(ofp);

	} else if (n < 0) {
		TRACE("ERROR [%s]\n", strerror(errno));
	}

	/*--------------------------------------------------------
	 * Has the read descriptor fired?
	 */
	if (n > 0 && FD_ISSET(sockfd, &rfds)) {
		int paklen;
		struct sockaddr_in src;
		struct NMBpacket pak;
		struct NMB_query_response rsp;

		memset(&src, 0, sizeof src);
		memset(&rsp, 0, sizeof rsp);

		paklen = (int) recvpacket(sockfd, &pak, sizeof pak, &src);

		/*------------------------------------------------
		 * If we actually got something from the other end,
		 * parse the response, plug in the remote's IP addr,
		 * and display it.
		 */
		if (parse_nbtstat(&pak, paklen, &rsp, errbuf)) {
			rsp.remote = src;

			if (target_responded(&rsp.remote.sin_addr)) {

				char computername[32];
				bzero(computername, 32);
				//display_nbtstat(ofp, &rsp, full_nbtstat);

				if (rsp.domain[0] == '\0' && rsp.computer[0] == '\0')
					sprintf(computername, "-no name-");
				else
					sprintf(computername, "%s\\%s", rsp.domain, rsp.computer);

				//string ip=CAddressHelper::IntIP2str(rsp.remote.sin_addr.s_addr);
				if (p_nIP == rsp.remote.sin_addr.s_addr) {
					string rets = computername;
					return rets;

				}

			}
		} else {
			//fprintf(ofp, "ERROR: no parse for %s -- %s\n",	inet_ntoa(src.sin_addr), errbuf);
		}
	}

	return "";
}

int CNbtQuery::sendpacket(int sfd, const void *pak, int len,
		const struct sockaddr_in *dst) {
	return sendpacket_direct(sfd, pak, len, dst);
}

int CNbtQuery::recvpacket(int sfd, void *pak, int len,
		struct sockaddr_in *dst) {
	return recvpacket_direct(sfd, pak, len, dst);
}

void CNbtQuery::OnNewName(DWORD p_nIP, string p_sName) {
	if (this->m_CallNetworkHandle.Handler != NULL) {
		netBiosPacket *n = new netBiosPacket();
		n->nIP = p_nIP;
		n->sName = p_sName;
		m_CallNetworkHandle.Handler(n,
				m_CallNetworkHandle.HandlerParentPointer);
		delete n;
	}

}

void CNbtQuery::RegisterNetworkHandle(callback p_Handle, void * p_Parent) {

	this->m_CallNetworkHandle.Handler = p_Handle;
	m_CallNetworkHandle.HandlerParentPointer = p_Parent;

}
/*

void CNbtQuery::StartListener() {

	m_InfoworkerThread.StartThread(threadListener,this);

}


void* CNbtQuery::threadListener(void *para) {
	CNbtQuery * c = (CNbtQuery *) para;
	c->threadListenerRun();
	return 0;
}
void CNbtQuery::threadListenerRun() {

	while (1) {

		if (!SetupSocket()) {
			TRACE("Unable to setup netbios socket\n");
			return;
		}
		char errbuf[256];
		fd_set rfds;
		int n;
		FD_ZERO(&rfds);
		FD_SET(this->m_sSocket, &rfds);

		while ((n = select(m_sSocket + 1, &rfds, 0, 0, NULL)) > 0) {
			if (FD_ISSET(m_sSocket, &rfds)) {

				int paklen;
				struct sockaddr_in src;
				struct NMBpacket pak;
				struct NMB_query_response rsp;

				memset(&src, 0, sizeof src);
				memset(&rsp, 0, sizeof rsp);

				while ((paklen = (int) recvpacket(m_sSocket, &pak, sizeof pak,&src)) > 0) {

					if (parse_nbtstat(&pak, paklen, &rsp, errbuf)) {
						rsp.remote = src;

						//		TRACE("responsed from IP %s ID %ud and %ud",CAddressHelper::IntIP2str(rsp.remote.sin_addr.s_addr).c_str(),pak.tranid,ntohs(pak.tranid));

						if (target_responded(
								&rsp.remote.sin_addr) && this->GetIPTransID(rsp.remote.sin_addr.s_addr)
								== ntohs(pak.tranid)) {

						char
							computername[32];
							bzero(computername, 32);
							//display_nbtstat(ofp, &rsp, full_nbtstat);

							if (rsp.domain[0] == '\0'
									&& rsp.computer[0] == '\0')
								sprintf(computername, "-no name-");
							else
								sprintf(computername, "%s\\%s", rsp.domain,
										rsp.computer);

							string rets = computername;
							this->OnNewName(rsp.remote.sin_addr.s_addr, rets);

						}
					}
				}
			}

			FD_ZERO(&rfds);
			FD_SET(this->m_sSocket, &rfds);
		}
	}

}
*/

unsigned short CNbtQuery::GetIPTransID(DWORD & p_nIP) {
	m_lock.lock();
	unsigned short n = 0;
	if (this->m_QueryHistoryID.count(p_nIP)) {
		n = this->m_QueryHistoryID[p_nIP];
	}
//TRACE("Found IP %s ID %ud",CAddressHelper::IntIP2str(p_nIP).c_str(),n);

	m_lock.unlock();
	return n;
}
void CNbtQuery::SetIPTRansID(DWORD & p_nIP, unsigned short p_nID) {
	m_lock.lock();

	this->m_QueryHistoryID[p_nIP] = p_nID;
//TRACE("SET IP %s ID %ud\n",CAddressHelper::IntIP2str(p_nIP).c_str(),m_QueryHistoryID[p_nIP]);

	m_lock.unlock();

}
