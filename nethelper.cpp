#include "netheader.h"

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

std::string string_to_hex(const std::string& input) {
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i) {
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

std::string hex_to_string(const std::string& input) {
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	if (len & 1)
		return output;

	output.reserve(len / 2);
	for (size_t i = 0; i < len; i += 2) {
		char a = input[i];
		const char* p = std::lower_bound(lut, lut + 16, a);
		if (*p != a)
			return output;

		char b = input[i + 1];
		const char* q = std::lower_bound(lut, lut + 16, b);
		if (*q != b)
			return output;

		output.push_back(((p - lut) << 4) | (q - lut));
	}
	return output;
}

std::string _helper_string_format(const std::string fmt, ...) {
	int size = 100;
	std::string str;
	va_list ap;
	while (1) {
		str.resize(size);
		va_start(ap, fmt);
		int n = vsnprintf((char *) str.c_str(), size, fmt.c_str(), ap);
		va_end(ap);
		if (n > -1 && n < size) {
			str.resize(n);
			return str;
		}
		if (n > -1)
			size = n + 1;
		else
			size *= 2;
	}
	return str;
}

std::string _helper_net_host(int m) {

	char buff[256];
	memset(buff, 0, 256);
	int one, two, three, four;
	one = m;
	one = one >> 24;
	two = m;
	two = two >> 16;
	two = two & 0xff;
	three = m;
	three = three >> 8;
	three = three & 0xff;
	four = m;
	four = four & 0xff;
	sprintf(&buff[0], "%u.%u.%u.%u", four, three, two, one);
	return &buff[0];
}

in_addr_t _helper_NextIP(const in_addr_t & p_nAddrIP) {
	in_addr_t n = ntohl(p_nAddrIP);
	n += 1;
	return htonl(n);

}

std::string _helper_IP_buffer2Str(const char * p_sbuff) {

	in_addr in;
	memcpy(&in.s_addr, p_sbuff, 4);
	return inet_ntoa(in);

}

static uint8_t
nibbleFromChar(char c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 255;
}

std::string _helper_Mac_buff2Str(const u_char * p_sbuff) {

	std::string s;
	s.append("[");

	s.append(_helper_GetHexCode((char *) p_sbuff, 1));
	for (int i = 1; i < 6; i++) {
		s.append(":");
		s.append(_helper_GetHexCode((char *) p_sbuff + i, 1));

	}
	s.append("]");
	return s;

}
std::string _helper_strtail(std::string const& source, size_t const length) {
	  if (length >= source.size()) { return source; }
	  return source.substr(source.size() - length);
	} // tail

void _helper_removestring(string& p_sStr,const string& p_sFind)
{
	std::size_t found = p_sStr.find(p_sFind);
		  while(found!=std::string::npos)
		  {
			  p_sStr.erase(p_sStr.find(p_sFind),p_sFind.length());
			  found = p_sStr.find(p_sFind);
		  }

}
void _helper_replacestring(string& p_sStr,const string& p_sFind,const string& p_sReplace)
{
	std::size_t found = p_sStr.find(p_sFind);
	  if (found!=std::string::npos)
	  {
		  p_sStr.replace(p_sStr.find(p_sFind),p_sFind.length(),p_sReplace);
	  }

}
std::vector<string> _helper_splitstring_pair(string p_sString,string p_sToken) {

      vector<string> strings;

	 			string s;
	 			int nIndex=0;
	 			while (nIndex<p_sString.size())
	 			{
	 				s.append(p_sString.substr(nIndex,1));

	 				if(_helper_strtail(s,p_sToken.size())==p_sToken)
	 				{
	 					s.resize(s.size()-p_sToken.size());
	 					strings.push_back(s);
	 					nIndex++;
	 					s=p_sString.substr(nIndex);
	 					strings.push_back(s);
	 					return strings;
	 				}
	 				nIndex++;
	 			}

	 			if(s.size()>0)
	 				 strings.push_back(s);

	    return strings;
}
std::vector<string> _helper_splitstring(string p_sString,string p_sToken) {

	           vector<string> strings;

	 			string s;
	 			int nIndex=0;
	 			while (nIndex<p_sString.size())
	 			{
	 				s.append(p_sString.substr(nIndex,1));

	 				if(_helper_strtail(s,p_sToken.size())==p_sToken)
	 				{
	 					s.resize(s.size()-p_sToken.size());
	 					 strings.push_back(s);
	 					s="";

	 				}
	 				nIndex++;
	 			}

	 			if(s.size()>0)
	 				 strings.push_back(s);

	    return strings;
}

std::string _helper_GetHexCode(char *p_Buf, int p_nSize) {
	char conv[] = "0123456789ABCDEF";
	std::string s;
	for (int i = 0; i < p_nSize; i++) {
		s.append(1, conv[((p_Buf[i] & 0xFF) >> 4)]);
		s.append(1, conv[((p_Buf[i] & 0xFF) & 0x0F)]);
	}

	return s;
}
int _helpper_Hex2Char(unsigned char & p_cChar,unsigned char p_Value,int & p_nOdd)
{
	p_cChar&=0xf0;
	p_Value&=0x0f;
	p_cChar|=p_Value;
   if(p_nOdd++%2)	p_cChar<<=4; //first part

   return p_nOdd%2?1:0;  //if it is odd, then index need to +1 , other wise, index +0;

}
string _helper_Hex2Buffer(string p_sHexStr)
{
	string sReturn = "";
	unsigned char *buf=new unsigned char[p_sHexStr.length()];
	memset(buf,0,p_sHexStr.length());
	int nIndex=0;
	int nOdd=1;

				for (int i = 0; i < p_sHexStr.length (); ++i)
				{
					switch (p_sHexStr [i])
					{
						case '0':
						{
							nIndex+=_helpper_Hex2Char(buf[nIndex],0x00,nOdd);
							break;
						}
						case '1':
						{
							nIndex+=_helpper_Hex2Char(buf[nIndex],0x01,nOdd);
														break;
												}

						case '2': nIndex+=_helpper_Hex2Char(buf[nIndex],0x02,nOdd); break;
						case '3': nIndex+=_helpper_Hex2Char(buf[nIndex],0x03,nOdd); break;
						case '4': nIndex+=_helpper_Hex2Char(buf[nIndex],0x04,nOdd); break;
						case '5': nIndex+=_helpper_Hex2Char(buf[nIndex],0x05,nOdd); break;
						case '6': nIndex+=_helpper_Hex2Char(buf[nIndex],0x06,nOdd); break;
						case '7': nIndex+=_helpper_Hex2Char(buf[nIndex],0x07,nOdd); break;
						case '8': nIndex+=_helpper_Hex2Char(buf[nIndex],0x08,nOdd); break;
						case '9': nIndex+=_helpper_Hex2Char(buf[nIndex],0x09,nOdd); break;
						case 'a': nIndex+=_helpper_Hex2Char(buf[nIndex],0x0a,nOdd); break;
						case 'b': nIndex+=_helpper_Hex2Char(buf[nIndex],0x0b,nOdd); break;
						case 'c': nIndex+=_helpper_Hex2Char(buf[nIndex],0x0c,nOdd); break;
						case 'd': nIndex+=_helpper_Hex2Char(buf[nIndex],0x0d,nOdd); break;
						case 'e': nIndex+=_helpper_Hex2Char(buf[nIndex],0x0e,nOdd); break;
						case 'f': nIndex+=_helpper_Hex2Char(buf[nIndex],0x0f,nOdd); break;
						default:
							continue;
					}
				}

				sReturn.append((char *)buf,nIndex);
				delete buf;
				return sReturn;
}

void _helper_GetAdapterMac(const char * p_sDev, char * p_sMacBuff) {
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, p_sDev);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		memcpy(p_sMacBuff, &s.ifr_addr.sa_data[0], 6);
	}
}

void _helper_freeadapter(adapter *p_adapter) {
	if (p_adapter == NULL)
		return;
	adapter *tracker = p_adapter;

	while (p_adapter) {
		tracker = tracker->next;
		delete p_adapter;
		p_adapter = tracker;

	}

}

adapter *
_helper_rtnl_print_link(struct nlmsghdr *h) {
	struct ifinfomsg *iface;
	struct rtattr *attribute;
	int len;
	adapter * newAdapter = new adapter;
	newAdapter->next = NULL;
	newAdapter->bUp = false;
	bzero(&newAdapter->DefGateWay, sizeof(newAdapter->DefGateWay));
	newAdapter->nIndex = -2;

	iface = (ifinfomsg *) NLMSG_DATA(h);
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
	// printf("%u: %s",iface->ifi_index, (iface->ifi_flags & IFF_LOWER_UP)? "up":"down");
	newAdapter->nIndex = iface->ifi_index;
	newAdapter->bUp = (iface->ifi_flags & IFF_LOWER_UP) ? true : false;

	/* loop over all attributes for the NEWLINK message */
	for (attribute = IFLA_RTA(iface) ; RTA_OK(attribute, len); attribute =
			RTA_NEXT(attribute, len)) {
		switch (attribute->rta_type) {
		case IFLA_IFNAME:
			//printf("Interface %d : %s\n", iface->ifi_index, (char *) RTA_DATA(attribute));
			newAdapter->sName = (char *) RTA_DATA(attribute);
			break;
		default:
			break;
		}
	}

	return newAdapter;
}

adapter * _helper_get_link() {
	adapter * first_adapter = NULL;
	adapter * tracker = first_adapter;
	typedef struct nl_req_s nl_req_t;

	struct nl_req_s {
		struct nlmsghdr hdr;
		struct rtgenmsg gen;
	};

	int fd;
	struct sockaddr_nl local; /* our local (user space) side of the communication */
	struct sockaddr_nl kernel; /* the remote (kernel space) side of the communication */

	struct msghdr rtnl_msg; /* generic msghdr struct for use with sendmsg */
	struct iovec io; /* IO vector for sendmsg */

	nl_req_t req; /* structure that describes the rtnetlink packet itself */
	char reply[IFLIST_REPLY_BUFFER]; /* a large buffer to receive lots of link information */

	pid_t pid = getpid(); /* our process ID to build the correct netlink address */
	int end = 0; /* some flag to end loop parsing */

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	memset(&local, 0, sizeof(local)); /* fill-in local address information */
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTNLGRP_LINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
		TRACE("cannot bind, are you root?");
		return NULL;
	}

	/* RTNL socket is ready for use, prepare and send request */

	memset(&rtnl_msg, 0, sizeof(rtnl_msg));
	memset(&kernel, 0, sizeof(kernel));
	memset(&req, 0, sizeof(req));

	kernel.nl_family = AF_NETLINK; /* fill-in kernel address (destination of our message) */

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_seq = 1;
	req.hdr.nlmsg_pid = pid;
	req.gen.rtgen_family = AF_PACKET; /*  no preferred AF, we will get *all* interfaces */

	io.iov_base = &req;
	io.iov_len = req.hdr.nlmsg_len;
	rtnl_msg.msg_iov = &io;
	rtnl_msg.msg_iovlen = 1;
	rtnl_msg.msg_name = &kernel;
	rtnl_msg.msg_namelen = sizeof(kernel);

	sendmsg(fd, (struct msghdr *) &rtnl_msg, 0);

	while (!end) {
		int len;
		struct nlmsghdr *msg_ptr; /* pointer to current message part */

		struct msghdr rtnl_reply; /* generic msghdr structure for use with recvmsg */
		struct iovec io_reply;

		memset(&io_reply, 0, sizeof(io_reply));
		memset(&rtnl_reply, 0, sizeof(rtnl_reply));

		io.iov_base = reply;
		io.iov_len = IFLIST_REPLY_BUFFER;
		rtnl_reply.msg_iov = &io;
		rtnl_reply.msg_iovlen = 1;
		rtnl_reply.msg_name = &kernel;
		rtnl_reply.msg_namelen = sizeof(kernel);

		len = recvmsg(fd, &rtnl_reply, 0); /* read as much data as fits in the receive buffer */
		if (len) {
			for (msg_ptr = (struct nlmsghdr *) reply; NLMSG_OK(msg_ptr, len);
					msg_ptr = NLMSG_NEXT(msg_ptr, len)) {
				switch (msg_ptr->nlmsg_type) {
				case 3: /* this is the special meaning NLMSG_DONE message we asked for by using NLM_F_DUMP flag */
					end++;
					break;
				case RTM_NEWLINK: /* this is a RTM_NEWLINK message, which contains lots of information about a link */
					if (tracker == NULL) {
						tracker = _helper_rtnl_print_link(msg_ptr);
						first_adapter = tracker;
					} else {
						tracker->next = _helper_rtnl_print_link(msg_ptr);
						tracker = tracker->next;
					}
					break;
				default: /* for education only, print any message that would not be DONE or NEWLINK,
				 which should not happen here */
					TRACE("message type %d, length %d\n", msg_ptr->nlmsg_type,
							msg_ptr->nlmsg_len);
					break;
				}
			}
		}

	}

	/* clean up and finish properly */

	close(fd);
	return first_adapter;

}

void _helper_getrouteinfo(adapter * p_adapter) {

	struct {
		struct nlmsghdr nlmsg_info;
		struct rtmsg rtmsg_info;
		char buffer[2048];
	} netlink_req;

	int fd;
	struct sockaddr_nl local;
	struct sockaddr_nl peer;
	struct msghdr msg_info;
	struct iovec iov_info;
	char read_buffer[8192];

	struct nlmsghdr *nlmsg_ptr;
	char *read_ptr;
	int nlmsg_len;
	struct rtmsg *rtmsg_ptr;
	struct rtattr *rtattr_ptr;
	int rtmsg_len;

	int rtn;

	char dst_str[128];
	char gw_str[128];
	char ifc_str[128];

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		TRACE("Error in sock open\n");
		//exit(1);
	}

	// setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len));

	bzero(&local, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTNLGRP_LINK;
	if (bind(fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
		TRACE("Error in sock bind\n");
		//exit(1);
	}

	bzero(&peer, sizeof(peer));
	peer.nl_family = AF_NETLINK;
	peer.nl_pad = 0;
	peer.nl_pid = 0;
	peer.nl_groups = 0;

	bzero(&msg_info, sizeof(msg_info));
	msg_info.msg_name = (void *) &peer;
	msg_info.msg_namelen = sizeof(peer);

	bzero(&netlink_req, sizeof(netlink_req));

	netlink_req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	netlink_req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	netlink_req.nlmsg_info.nlmsg_type = RTM_GETROUTE;

	netlink_req.rtmsg_info.rtm_family = AF_INET;
	netlink_req.rtmsg_info.rtm_table = RT_TABLE_MAIN;

	iov_info.iov_base = (void *) &netlink_req.nlmsg_info;
	iov_info.iov_len = netlink_req.nlmsg_info.nlmsg_len;
	msg_info.msg_iov = &iov_info;
	msg_info.msg_iovlen = 1;

	rtn = sendmsg(fd, &msg_info, 0);
	if (rtn < 0) {
		TRACE("Error in sendmsg\n");
		//exit(1);
	}

	bzero(read_buffer, 8192);

	read_ptr = read_buffer;
	nlmsg_len = 0;
	while (1) {
		rtn = recv(fd, read_ptr, 4096, 0);
		if (rtn < 0) {
			TRACE("Error in recv\n");
			//exit(1);
		}
		nlmsg_ptr = (struct nlmsghdr *) read_ptr;

		if (nlmsg_ptr->nlmsg_type == NLMSG_DONE) {
			break;
		}

		read_ptr = read_ptr + rtn;
		nlmsg_len = nlmsg_len + rtn;
	}
	//		TRACE("Main route table\n");
	nlmsg_ptr = (struct nlmsghdr *) read_buffer;
	for (; NLMSG_OK(nlmsg_ptr, nlmsg_len); nlmsg_ptr =
			NLMSG_NEXT(nlmsg_ptr, nlmsg_len)) {

		rtmsg_ptr = (struct rtmsg *) NLMSG_DATA(nlmsg_ptr);
		// only main route table is considered
		if (rtmsg_ptr->rtm_table != RT_TABLE_MAIN)
			continue;

		bzero(dst_str, 128);
		bzero(gw_str, 128);
		bzero(ifc_str, 128);
		int nIndex = -1;

		rtattr_ptr = (struct rtattr *) RTM_RTA(rtmsg_ptr);
		rtmsg_len = RTM_PAYLOAD(nlmsg_ptr);
		for (; RTA_OK(rtattr_ptr, rtmsg_len); rtattr_ptr =
				RTA_NEXT(rtattr_ptr, rtmsg_len)) {
			switch (rtattr_ptr->rta_type) {
			case RTA_DST:
				inet_ntop(AF_INET, RTA_DATA(rtattr_ptr), dst_str, 128);
				break;
			case RTA_GATEWAY:
				inet_ntop(AF_INET, RTA_DATA(rtattr_ptr), gw_str, 128);
				break;
			case RTA_OIF:
				sprintf(ifc_str, "%d", *((int *) RTA_DATA(rtattr_ptr) ));
				nIndex = *((int *) RTA_DATA(rtattr_ptr) );
				break;
			default:
				break;

			}
		}
		adapter *theone = NULL;
		adapter *mover = p_adapter;
		bool bDefault = false;

		if (strlen(ifc_str) != 0) {
			//									printf(" dev %s", ifc_str);
			while (mover) {
				if (mover->nIndex == nIndex) {
					theone = mover;
					break;
				}
				mover = mover->next;
			}
		}
		if (strlen(dst_str) == 0) {
			//		printf("default");
			bDefault = true;
		} else {
			//	printf("%s/%d", dst_str, rtmsg_ptr->rtm_dst_len);
		}

		if (strlen(gw_str) != 0) {
			//		printf(" via %s", gw_str);
			if (bDefault && theone)
				inet_aton(gw_str, &theone->DefGateWay);
		}

		//		printf("\n");
	}
	close(fd);

}

bool getrequestext(std::string & p_sBuf,std::string & p_sExt)
{
	if(!getrequesturl(p_sBuf,p_sExt)) return false;

	int nPos=p_sExt.find('?');
	if(std::string::npos!=nPos)
	{
		p_sExt=p_sExt.substr(0,nPos);
	}

	nPos=p_sExt.find_last_of('/');

	if(std::string::npos!=nPos)
			{
				p_sExt=p_sExt.substr(nPos+1);
			}

	nPos=p_sExt.find_last_of('.');

	if(std::string::npos!=nPos)
		{
			p_sExt=p_sExt.substr(nPos+1);
		}
	else
	{
		p_sExt="";
	}

	return true;

}
bool getrequesturl(std::string & p_sBuf,std::string & p_sUrl)
{

	if(p_sBuf.size()<13) return false;

	std::string sGet=p_sBuf.substr(0,4);
	if(sGet!="GET ") return false;
	int nUrlEnd=p_sBuf.find(" ",5);
	if(std::string::npos==nUrlEnd) return false;

	std::string sHTTPBanner=p_sBuf.substr(nUrlEnd+1,4);
	if(sHTTPBanner!="HTTP") return false;
	p_sUrl=p_sBuf.substr(5,nUrlEnd-5);
	return true;
}
bool getrequestapp(std::string & p_sBuf,std::string & p_sApp)
{


	int nAgentStart=p_sBuf.find("User-Agent: ",5);
	if(std::string::npos==nAgentStart) return false;

	nAgentStart+=12;

	int nAgentEnd=p_sBuf.find("\r\n",nAgentStart);
	if(std::string::npos==nAgentEnd) return false;

    p_sApp=p_sBuf.substr(nAgentStart,nAgentEnd-nAgentStart);
	return true;
}
bool strreplace(std::string& p_s, std::string p_spattern,
		std::string p_sReplacestr) {

	regex_t preg;
	int rc;
	size_t nmatch = 1;
	regmatch_t pmatch[1];
	bool bRet=false;

	do
	{
	if (0 != (rc = regcomp(&preg, p_spattern.c_str(), 0))) {
		//printf("regcomp() failed, returning nonzero (%d)\n", rc);
		//exit(EXIT_FAILURE);
		//return false;
		break;
	}

	if (0 != (rc = regexec(&preg, p_s.c_str(), nmatch, pmatch, 0))) {

		break;
	} else {

		p_s.replace(pmatch[0].rm_so, pmatch[0].rm_eo - pmatch[0].rm_so,
				p_sReplacestr);
		bRet=true;

	}}
	while(false);
	regfree(&preg);
	return bRet;
}

