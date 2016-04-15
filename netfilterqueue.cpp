/*
 * netfilterqueue.cpp
 *
 *  Created on: Feb 20, 2015
 *      Author: root
 */

#include "netfilterqueue.h"
#include "CAddressHelper.h"
#include "checksum.h"
#include <regex.h>

netfilterqueue::netfilterqueue() {
	// TODO Auto-generated constructor stub
	m_ThreadHandleQueueBinding = NULL;

	m_h = NULL;
	m_qh = NULL;
	m_nh = NULL;

	/*	 m_nSrcIP=CAddressHelper::StrIP2Int("192.168.1.104");
	 m_nMaskIP=CAddressHelper::StrIP2Int("192.168.1.2");
	 m_nGatewayIP=CAddressHelper::StrIP2Int("192.168.1.1");
	 */
	m_bIpTableExist = false;
	m_bEnableNAT = false;
	m_bIPFORWARDSystemValue = GetIpforward();
	//EnableIpforward(false);
}

netfilterqueue::~netfilterqueue() {
	// TODO Auto-generated destructor stub


	if (m_qh) {
		int fd = nfq_fd(m_h);
	    shutdown(fd, SHUT_RDWR);
		//close(fd);

	}

	TRACE("closing library handle\n");
		if (m_ThreadHandleQueueBinding != NULL)
			pthread_join(m_ThreadHandleQueueBinding, NULL);

	if (m_qh) {
		nfq_destroy_queue(m_qh);
				m_qh = NULL;

	}

	if (m_h) {
		TRACE("closing netfilter queue handle\n");
		nfq_close(m_h);
		m_h = NULL;
	}



	RemoveOldQueue();
	TRACE("Done Netfilter Exit\n");

	// if(!m_bIPFORWARDSystemValue)
	// EnableIpforward(m_bIPFORWARDSystemValue);

}
void* netfilterqueue::RuleDummy(char * p_buf, int p_nBufSize,
		u_int32_t & p_nPacketLen, unsigned char * & p_packetbuf, void *data) {

	return 0;
}

void* netfilterqueue::RuleNAT(char * p_buf, int p_nBufSize,
		u_int32_t & p_nPacketLen, unsigned char * & p_packetbuf, void *data) {

	netfilterqueue *n = (netfilterqueue *) data;
	n->OnRuleNATRun(p_buf, p_nBufSize, p_nPacketLen, p_packetbuf);
	return 0;
}

void netfilterqueue::OnRuleNATRun(char * p_buf, int p_nBufSize,
		u_int32_t & p_nPacketLen, unsigned char * & p_packetbuf) {

	do {

		if (!m_bEnableNAT)
			break;

		struct sniff_ip *ip; /* The IP header */
		ipv4_hdr_t *ip_hdr;

		p_nPacketLen = p_nBufSize;
		p_packetbuf = (u_char *) malloc(p_nPacketLen);
		if (p_packetbuf == NULL) {
			p_nPacketLen = 0;
			TRACE("Failed allocte memory NAT\n");
			break;
		}
		memcpy(p_packetbuf, p_buf, p_nPacketLen);

		ip_hdr = (ipv4_hdr_t *) (p_packetbuf);
		ip = (struct sniff_ip*) (p_packetbuf);
		int size_ip = IP_HL(ip) * 4;

		DWORD senderIP = ip->ip_src.s_addr;
		DWORD targetIP = ip->ip_dst.s_addr;
		if (senderIP == this->m_nMyIP && !CAddressHelper::isBrocastIP(targetIP)
				&& !CAddressHelper::isSameRang(senderIP, targetIP,
						this->m_nMyMask))
						//if(senderIP==this->m_nMyIP)
						{
			ip->ip_src.s_addr = this->m_nNATIP;
			//	   TRACE("Changing SRC from %s to %s\n",CAddressHelper::IntIP2str(senderIP).c_str(),CAddressHelper::IntIP2str(m_nNATIP).c_str());
		}
		if (targetIP == this->m_nNATIP) {
			ip->ip_dst.s_addr = this->m_nMyIP;
			//	  TRACE("Changing DST from %s to %s\n",CAddressHelper::IntIP2str(targetIP).c_str(),CAddressHelper::IntIP2str(m_nMyIP).c_str());
		}

		do_checksum((u_char *) p_packetbuf, ip->ip_p, p_nPacketLen - size_ip);
		do_checksum((u_char *) p_packetbuf, IPPROTO_IP, p_nPacketLen);
	} while (false);

}

void* netfilterqueue::Rule1(char * p_buf, int p_nBufSize,
		u_int32_t & p_nPacketLen, unsigned char * & p_packetbuf, void *data) {

	netfilterqueue *n = (netfilterqueue *) data;
	n->OnRule1Run(p_buf, p_nBufSize, p_nPacketLen, p_packetbuf);
	return 0;
}

void netfilterqueue::OnRule1Run(char * p_buf, int p_nBufSize,
		u_int32_t & p_nPacketLen, unsigned char * & p_packetbuf) {

	const struct sniff_ip *ip; /* The IP header */
	ipv4_hdr_t *ip_hdr;
	struct sniff_ip *newip;
	ip = (struct sniff_ip*) (p_buf);
	ip_hdr = (ipv4_hdr_t *) (p_buf);
	int size_ip = IP_HL(ip) * 4;
	if (ip->ip_p != IPPROTO_TCP)
		return;

	if ((htons(ip_hdr->ip_off) & IP_OFFMASK) != 0)
		return;

	const struct tcp_header * tcp = (struct tcp_header *) ((u_char*) ip
			+ size_ip);
	u_char * tcppayloadbegin = ((u_char*) ip + size_ip + tcp->data_offset * 4);
	int tcppayloadsize = p_nBufSize - tcp->data_offset * 4 - size_ip;
	if (tcppayloadsize < 10)
		return;
	string s;
	s.append((char *) tcppayloadbegin, tcppayloadsize);
	TRACE("%s", s.c_str());

	//strreplace(s,"\\(^GET /[^ ]*\\) HTTP/1.\d\r\n","GET /")

	strreplace(s, "\\(^GET /[^ ]*\\)", "GET /");
	string newpayload = s;

	p_nPacketLen = size_ip + tcp->data_offset * 4 + newpayload.size();

	p_packetbuf = (u_char *) malloc(p_nPacketLen);
	memset(p_packetbuf, 0, p_nPacketLen);
	memcpy(p_packetbuf, ip, size_ip);

	newip = (struct sniff_ip*) (p_packetbuf);
	newip->ip_len = htons(p_nPacketLen);
//ip_hdr->ip_len = htons(ip_len);
	memcpy(p_packetbuf + size_ip, tcp, tcp->data_offset * 4);
	memcpy(p_packetbuf + size_ip + tcp->data_offset * 4, newpayload.c_str(),
			newpayload.size());

	do_checksum((u_char *) p_packetbuf, newip->ip_p, p_nPacketLen - size_ip);
	do_checksum((u_char *) p_packetbuf, IPPROTO_IP, p_nPacketLen);

}

void* netfilterqueue::threadBindQueue(void *para) {
	netfilterqueue *n = (netfilterqueue *) para;
	n->threadBindQueueRun();
	return 0;
}

void netfilterqueue::threadBindQueueRun() {

	TRACE("netfilter thread started\n");
	/*	struct nfq_handle *h;
	 struct nfq_q_handle *qh;
	 struct nfnl_handle *nh;
	 */
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	do {
		bool bWarning = false;

		if (m_h)
			nfq_close(m_h);

		m_h = nfq_open();
		if (!m_h) {
			TRACE("error during nfq_open()\n");
			break;
		}

		if (nfq_unbind_pf(m_h, AF_INET) < 0) {
			TRACE("error during nfq_unbind_pf()\n");
			break;
		}

		if (nfq_bind_pf(m_h, AF_INET) < 0) {
			TRACE("error during nfq_bind_pf()\n");
			break;
		}

		if (!CreateQueue(this->m_nQueuenumber)) {
			TRACE("Can NOT create IP Queue, use weak protection\n");
			break;
		}

		m_qh = nfq_create_queue(m_h, this->m_nQueuenumber, &cb, this);
		if (!m_qh) {

			TRACE("Can't bind queue\n");
			break;
		}

		//TRACE("Bind queue OK\n");
//	printf("setting copy_packet mode\n");
		if (nfq_set_mode(m_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
			TRACE("can't set packet_copy mode\n");
			break;
		}

		m_bIpTableExist = true;

		fd = nfq_fd(m_h);

		for (;;) {
			if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
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
				TRACE("losing packets!\n");
				continue;
			}
			TRACE("recv failed");
			break;
		}
	} while (false);


	TRACE("netfilter thread Finisheds\n");

}
void netfilterqueue::RemoveOldQueue() {

	string smypath=CAddressHelper::getAppPath();
		char buf[255];
		memset(buf, 0, 255);
		sprintf(buf,
				"%siptables -t mangle -D PREROUTING -j NFQUEUE --queue-num %d --queue-bypass",
				smypath.c_str(),m_nQueuenumber);
		iptables_commands(buf);
		memset(buf, 0, 255);
		sprintf(buf,
				"%siptables -t mangle -D POSTROUTING -j NFQUEUE --queue-num %d --queue-bypass",
				smypath.c_str(),m_nQueuenumber);
		iptables_commands(buf);

}
bool netfilterqueue::CreateQueue(int p_nQueueNumber) {

	RemoveOldQueue();

	string smypath=CAddressHelper::getAppPath();

	char buf[255];
	memset(buf, 0, 255);
	sprintf(buf,
			"%siptables -t mangle -A POSTROUTING -j NFQUEUE --queue-num %d --queue-bypass",
			smypath.c_str(),p_nQueueNumber);
	bool bRet1 = iptables_commands(buf);
	memset(buf, 0, 255);
	sprintf(buf,
			"%siptables -t mangle -A PREROUTING  -j NFQUEUE --queue-num %d --queue-bypass",
			smypath.c_str(),p_nQueueNumber);
	bool bRet2 = iptables_commands(buf);


	return (bRet1 && bRet2);

}
bool netfilterqueue::BindQueue(string p_sDevName, int p_nQueueNumber) {

	this->m_sDevName = p_sDevName;
	this->m_nQueuenumber = p_nQueueNumber;
	if (m_ThreadHandleQueueBinding != NULL)
		return true;

	if (pthread_create(&this->m_ThreadHandleQueueBinding, NULL,
			this->threadBindQueue, this)) {

		return false;

	}

	return true;

}
int netfilterqueue::cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data) {

	netfilterqueue *n = (netfilterqueue *) data;
	n->Packethandler(qh, nfa);
	return 1;

	//u_int32_t id = n->Packethandler(nfa,packet_len,packet_buf);

	/*
	 int ret= nfq_set_verdict(qh, id, NF_ACCEPT, packet_len, packet_buf);
	 if(packet_buf!=NULL)
	 {
	 if (this->m_HandleNetPacket->aligner > 0)
	 {
	 packet_buf = packet_buf - m_HandleNetPacket->aligner;
	 }
	 free(packet_buf);
	 }

	 return ret;
	 */
}
u_int32_t netfilterqueue::Packethandler(struct nfq_q_handle * qh,
		struct nfq_data *tb) {

//	u_int32_t packet_len=0;
//	unsigned char * packet_buf=NULL;

	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);

	if (ph) {
		id = ntohl(ph->packet_id);

		//printf("hw_protocol=0x%04x hook=%u id=%u ",				ntohs(ph->hw_protocol), ph->hook, id);
	}
	/*
	 hwph = nfq_get_packet_hw(tb);
	 if (hwph) {
	 int i, hlen = ntohs(hwph->hw_addrlen);

	 printf("hw_src_addr=");
	 for (i = 0; i < hlen-1; i++)				printf("%02x:", hwph->hw_addr[i]);
	 printf("%02x ", hwph->hw_addr[hlen-1]);
	 }
	 /*
	 mark = nfq_get_nfmark(tb);
	 if (mark)
	 printf("mark=%u ", mark);

	 ifi = nfq_get_indev(tb);
	 if (ifi)
	 printf("indev=%u ", ifi);

	 ifi = nfq_get_outdev(tb);
	 if (ifi)
	 printf("outdev=%u ", ifi);
	 ifi = nfq_get_physindev(tb);
	 if (ifi)
	 printf("physindev=%u ", ifi);

	 ifi = nfq_get_physoutdev(tb);
	 if (ifi)
	 printf("physoutdev=%u ", ifi);
	 */
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
//			printf("payload_len=%d ", ret);
		//return	OnIPPacketFilter((char *)data,ret,packet_len,packet_buf);
		return OnIPPacketFilter(qh, id, (char *) data, ret);
	}
//		fputc('\n', stdout);

	//	ret= nfq_set_verdict(qh, id, NF_ACCEPT, packet_len, packet_buf);
	/*		if(packet_buf!=NULL&&packet_buf!=data)
	 {
	 free(packet_buf);
	 packet_buf=NULL;

	 }
	 */
	return 0;
}

void netfilterqueue::CleanNAT() {

	m_lock.lock();

	std::list<filterrules>::iterator it;

	for (it = this->m_FilterRules.begin(); it != m_FilterRules.end();) {
		filterrules &rule = *it;
		if (RuleNAT == rule.rulecall) {
			it = m_FilterRules.erase(it);

		} else {
			++it;
		}
	}

	m_lock.unlock();

}
void netfilterqueue::SetNAT(const DWORD & p_nMyIP, const DWORD & p_nMask,
		const DWORD & p_nNATIP, const DWORD & p_nGateIP) {

	this->m_nMyIP = p_nMyIP;
	this->m_nMyMask = p_nMask;
	this->m_nNATIP = p_nNATIP;
	this->m_nGatewayIP = p_nGateIP;

//	TRACE("Set NAT on %s %s %s %s\n",CAddressHelper::IntIP2str(m_nMyIP).c_str(),CAddressHelper::IntIP2str(p_nMask).c_str(),CAddressHelper::IntIP2str(m_nNATIP).c_str(),CAddressHelper::IntIP2str(m_nGatewayIP).c_str());

	filterrules r;
	memset(&r, 0, sizeof(filterrules));

	r.nSrcIP = m_nMyIP;
	SetFilterRule(r, this->RULETYPE::NAT);

	memset(&r, 0, sizeof(filterrules));

	r.nDstIP = m_nNATIP;
	SetFilterRule(r, this->RULETYPE::NAT);

	m_bEnableNAT = true;

}
void netfilterqueue::SetDrop(const DWORD & p_nDropIP) {
	filterrules r;
	memset(&r, 0, sizeof(filterrules));
	r.nSrcIP = p_nDropIP;
	SetFilterRule(r, this->RULETYPE::DROP);

	memset(&r, 0, sizeof(filterrules));

	r.nDstIP = p_nDropIP;
	SetFilterRule(r, this->RULETYPE::DROP);

}
void netfilterqueue::SetFilterRule(filterrules p_nTarget, int p_nRule) {

	m_lock.lock();
	if (p_nRule == RULETYPE::NAT) {
		p_nTarget.rulecall = RuleNAT;
		p_nTarget.nPacketaction = NF_ACCEPT;
		m_FilterRules.push_back(p_nTarget);
	}

	if (p_nRule == RULETYPE::TEST) {
		p_nTarget.rulecall = Rule1;
		p_nTarget.nPacketaction = NF_ACCEPT;
		m_FilterRules.push_back(p_nTarget);
	}
	if (p_nRule == RULETYPE::DROP) {

		p_nTarget.rulecall = RuleDummy;
		p_nTarget.nPacketaction = NF_DROP;
		m_FilterRules.push_back(p_nTarget);
	}
	m_lock.unlock();
}

void netfilterqueue::OnTCPPacketFilter(char * p_buf, int p_nBufSize,
		u_int32_t & p_nPacketLen, unsigned char * & p_packetbuf) {

	const struct sniff_ip *ip; /* The IP header */
	ip = (struct sniff_ip*) (p_buf);

}
bool netfilterqueue::IsMatchRule(filterrules & p_Rule, filterrules & p_Packet) {

//	TRACE("Rule %s %s %s %s\n",CAddressHelper::IntIP2str(p_Rule.nSrcIP).c_str(),CAddressHelper::IntIP2str(p_Rule.nDstIP).c_str(),CAddressHelper::IntIP2str(p_Packet.nSrcIP).c_str(),CAddressHelper::IntIP2str(p_Packet.nDstIP).c_str());

	if (p_Rule.nSrcIP != 0 && p_Rule.nSrcIP != p_Packet.nSrcIP)
		return false;
	if (p_Rule.nDstIP != 0 && p_Rule.nDstIP != p_Packet.nDstIP)
		return false;
	if (p_Rule.nDstPort != 0 && p_Rule.nDstPort != p_Packet.nDstPort)
		return false;
	if (p_Rule.nSrcPort != 0 && p_Rule.nSrcPort != p_Packet.nSrcPort)
		return false;

	return true;

}
int netfilterqueue::OnIPPacketFilter(struct nfq_q_handle * qh, int id,
		char * p_buf, int p_nBufSize) {
	u_int32_t p_nPacketLen = 0;
	unsigned char * p_packetbuf = NULL;

	const struct sniff_ip *ip; /* The IP header */
	ip = (struct sniff_ip*) (p_buf);
	int size_ip = IP_HL(ip) * 4;

	filterrules thisone;
	memset(&thisone, 0, sizeof(filterrules));

	thisone.nSrcIP = ip->ip_src.s_addr;
	thisone.nDstIP = ip->ip_dst.s_addr;

	switch (ip->ip_p) {
	case IPPROTO_TCP: {
		const struct sniff_tcp * tcp = (struct sniff_tcp *) ((u_char*) ip
				+ size_ip);
		thisone.nDstPort = ntohs(tcp->th_dport);
		thisone.nSrcPort = ntohs(tcp->th_sport);
	}
	default:
		//				/TRACE("   Protocol: unknown\n");
		break;
	}

	m_lock.lock();
	std::list<filterrules>::iterator it;

	int action = NF_ACCEPT;
	for (it = this->m_FilterRules.begin(); it != m_FilterRules.end(); ++it) {
		filterrules &rule = *it;
		if (this->IsMatchRule(rule, thisone)) {
			rule.rulecall(p_buf, p_nBufSize, p_nPacketLen, p_packetbuf, this);
			action = rule.nPacketaction;
			if (action == NF_DROP) {
				//	  TRACE("Drop this packet from %s to %s\n",CAddressHelper::IntIP2str(thisone.nSrcIP).c_str(),CAddressHelper::IntIP2str(thisone.nDstIP).c_str());
				break;
			}
		}
	}
	m_lock.unlock();
	int ret = nfq_set_verdict(qh, id, action, p_nPacketLen, p_packetbuf);
	if (p_packetbuf != NULL) {
		free(p_packetbuf);
		p_nPacketLen = 0;
	}
	return ret;

}

