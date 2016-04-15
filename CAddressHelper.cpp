/*
 * CAddressHelper.cpp
 *
 *  Created on: Jan 9, 2015
 *      Author: root
 */

#include "CAddressHelper.h"
#include <sys/types.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <dirent.h>
#include <net/if.h>

#ifdef CPUFEATURE
#include <cpu-features.h>
#include <sys/system_properties.h>
#endif

//CAddressHelper::GetBrocastMac(m_macBrocast);
//CAddressHelper::GetEmptyMac(m_macEmpty);

u_char CAddressHelper::m_macBrocast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
u_char CAddressHelper::m_macMCast[6] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x00 };
u_char CAddressHelper::m_macEmpty[6] = { 0, 0, 0, 0, 0, 0 };

string b1 = "224.0.0.0";
string b2 = "239.255.255.250";
string maska = "255.0.0.0";
string maskc = "255.255.255.0";

DWORD CAddressHelper::n224 = CAddressHelper::StrIP2Int(b1);
DWORD CAddressHelper::n239 = CAddressHelper::StrIP2Int(b2);
DWORD CAddressHelper::nmask = CAddressHelper::StrIP2Int(maska);
DWORD CAddressHelper::cmask = CAddressHelper::StrIP2Int(maskc);
string CAddressHelper::m_sMyPath = "";
string CAddressHelper::m_sMyCmdLine = "";
char * * CAddressHelper::m_argv = NULL;

map<string, string> CAddressHelper::m_Mac2Brand;
//static map<string,string> m_Mac2Brand;
CAddressHelper a;

CAddressHelper::CAddressHelper() {
	// TODO Auto-generated constructor stub

	CAddressHelper::loadMac2BrandMap();
}

CAddressHelper::~CAddressHelper() {
	// TODO Auto-generated destructor stub
}

void CAddressHelper::GetRandomMac(u_char *buff) {
	srand((unsigned int) time(NULL));

	for (int i = 0; i < 6; i++)
		buff[i] = rand() / 255;

}

string CAddressHelper::GetNetcutName() {
	string sName = "netcut_" + CAddressHelper::GetCPUFamily();
#ifdef CPUFEATURE

	char value[93] = "";
	__system_property_get("ro.build.version.sdk", value);
	int num = atoi(value);
	if (num < 16)
		sName += "_15";

#endif
	return sName;

}
string CAddressHelper::GetCPUFamily() {
	string sCpuFamily = "arm";
#ifdef CPUFEATURE

	AndroidCpuFamily nFamily = android_getCpuFamily();

	switch (nFamily) {

	case ANDROID_CPU_FAMILY_ARM:
	case ANDROID_CPU_FAMILY_ARM64:
		sCpuFamily = "arm";
		break;

	case ANDROID_CPU_FAMILY_X86:
	case ANDROID_CPU_FAMILY_X86_64:
		sCpuFamily = "x86";
		break;

	case ANDROID_CPU_FAMILY_MIPS:
	case ANDROID_CPU_FAMILY_MIPS64:
		sCpuFamily = "mip";
		break;

	default:
		sCpuFamily = "arm";
	}

#endif
	return sCpuFamily;

}
DWORD CAddressHelper::GetRandomIP() {

	srand((unsigned int) time(NULL));
	double n = rand() / (double) RAND_MAX;
	return (DWORD) (0xFFFFFFFF * n);

}

std::string CAddressHelper::IntIP2str(const DWORD& p_nIP) //translate byte into string
		{
	in_addr in;
	in.s_addr = p_nIP;
	return inet_ntoa(in);
}

std::string CAddressHelper::BufferMac2str(const u_char * p_Buf) {

	return _helper_Mac_buff2Str(p_Buf);

}

MACADDR CAddressHelper::StrMac2Array(string p_sMacStr) {

	p_sMacStr.erase(std::remove(p_sMacStr.begin(), p_sMacStr.end(), '['),
			p_sMacStr.end());
	p_sMacStr.erase(std::remove(p_sMacStr.begin(), p_sMacStr.end(), ']'),
			p_sMacStr.end());
	p_sMacStr.erase(std::remove(p_sMacStr.begin(), p_sMacStr.end(), ':'),
			p_sMacStr.end());

	return CAddressHelper::MacBuffer2Array(
			(unsigned char *) _helper_Hex2Buffer(p_sMacStr.c_str()).c_str());

}

bool CAddressHelper::ChangeMacAddress(const string p_sDevName,
		const u_char * p_NewBuf) {

	int s, i;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return false;
	}

	//strlcpy(ifr.ifr_name, p_sDevName.c_str(), sizeof(ifr.ifr_name));

	//strcpy(ifr.ifr_name, p_sDevName.c_str());
	memcpy(ifr.ifr_name, p_sDevName.c_str(), p_sDevName.size());
	ifr.ifr_name[p_sDevName.size()] = '\0';

	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		perror("[ERROR] Set device name");

		return false;
	}

	for (i = 0; i < 6; i++)
		ifr.ifr_hwaddr.sa_data[i] = p_NewBuf[i];

	if (ioctl(s, SIOCSIFHWADDR, &ifr)) {
		perror("SIOCSIFHWADDR");
		close(s);
		return false;
	}

	close(s);

	return true;

}
string CAddressHelper::GetDNS_TXTDeviceInfo(string p_sName) {
	int nPos = 0;
	if ((nPos = p_sName.find("._device-info._tcp.local")) != string::npos)
		p_sName.erase(nPos);

	return p_sName;

}
string CAddressHelper::GetDNS_PTRname(string p_sName) {

	int nPos = 0;
	if ((nPos = p_sName.find(".local")) != string::npos)
		p_sName.erase(nPos);

	return p_sName;
}
string CAddressHelper::GetDNS_inaddr(DWORD p_nIP) {

//	TRACE("%s\n",CAddressHelper::IntIP2str(p_nIP).c_str());
	DWORD newIP = ntohl(p_nIP);
	// TRACE("%s\n",CAddressHelper::IntIP2str(newIP).c_str());

	return CAddressHelper::IntIP2str(newIP) + ".in-addr.arpa";

}
DWORD CAddressHelper::GetDNS_inaddr(string p_sName) {
	string sIP;
	int nDotCount = 0, nPos = 0;
	if ((nPos = p_sName.find(".in-addr.arpa")) == string::npos)
		return 0;
	p_sName.erase(nPos);
	nPos = 0;
	while (nDotCount < 3) {
		if ((nPos = p_sName.rfind('.')) == string::npos)
			return 0;
		sIP.append(p_sName.substr(nPos + 1));
		sIP += ".";
		p_sName.erase(nPos);
		nDotCount++;
	}
	sIP.append(p_sName);
	return CAddressHelper::StrIP2Int(sIP);

}
std::string CAddressHelper::BufferIP2str(const u_char*p_Buf) //translate networkbuffer into string
		{

	in_addr in;
	in.s_addr = CAddressHelper::BufferIP2Int(p_Buf);
	return inet_ntoa(in);
}
DWORD CAddressHelper::BufferIP2Int(const u_char* p_Buf) //translate networkbuffer into DWORD
		{
	DWORD IP = 0;
	memcpy(&IP, p_Buf, 4);
	return IP;
}
DWORD CAddressHelper::AddrIP2Int(in_addr & p_nAdd) {
	return p_nAdd.s_addr;

}

DWORD CAddressHelper::StrIP2Int(const std::string & p_sIP) {
	return inet_addr(p_sIP.c_str());
}
string CAddressHelper::getAppPath() {

	string fullpath = CAddressHelper::getMyPath();
	size_t found = fullpath.find_last_of('/');
	if (string::npos != found)
		return fullpath.substr(0, found + 1);
	else
		return fullpath;

}

string CAddressHelper::getMyPath() {

	if (CAddressHelper::m_sMyPath.size() > 0)
		return CAddressHelper::m_sMyPath;

	char arg1[20] = { 0 };
	char exepath[4097] = { 0 };

	sprintf(arg1, "/proc/%d/exe", getpid());
	readlink(arg1, exepath, 1024);

	string fullpath = string(exepath);
	size_t found = fullpath.find_last_of(' ');
	if (string::npos != found)
		CAddressHelper::m_sMyPath = fullpath.substr(0, found + 1);
	else
		CAddressHelper::m_sMyPath = fullpath;

	return CAddressHelper::m_sMyPath;

}

string CAddressHelper::getMyCmdlineArgv() {

	return CAddressHelper::m_sMyCmdLine;

}

string CAddressHelper::readFile2(const string &fileName) {

	streamsize size;
	char * memblock;
	ifstream myfile;
	myfile.open(fileName, ios::in | ios::binary | ios::ate);

	if (myfile.is_open()) {
		size = myfile.tellg();
		memblock = new char[size];
		myfile.seekg(0, ios::beg);
		myfile.read(memblock, size);
		myfile.close();
		string s(memblock, size);
		delete[] memblock;
		return s;
	}
	return "";
}

list<int> CAddressHelper::getPids2(const char* name) {
	list<int> pids;
	DIR* dir;
	struct dirent* ent;
	char* endptr;

	string sPathWithSpace = name;
	sPathWithSpace += " ";

	if (!(dir = opendir("/proc"))) {
		perror("can't open /proc");
		return pids;
	}

	while ((ent = readdir(dir)) != NULL) {
		/* if endptr is not a null character, the directory is not
		 * entirely numeric, so ignore it */
		long lpid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != '\0') {
			continue;
		}
		if (lpid <= 72)
			continue;

		char arg1[100] = { 0 };
		char exepath[4097] = { 0 };
		sprintf(arg1, "/proc/%d/cmdline", lpid);
		string sCmdLine = CAddressHelper::readFile2(arg1);
		TRACE("cmd line %s\n", sCmdLine.c_str());
		if (sCmdLine == name) {
			pids.push_back(lpid);
			TRACE("pid %d\n", lpid);

		}
		if (sCmdLine.find(sPathWithSpace) != string::npos) {
			pids.push_back(lpid);
			TRACE("pid %d\n", lpid);
		}

	}

	closedir(dir);
	return pids;

}
list<int> CAddressHelper::getPids(const char* name) {
	list<int> pids;
	DIR* dir;
	struct dirent* ent;
	char* endptr;

	string sPathWithSpace = name;
	sPathWithSpace += " ";

	if (!(dir = opendir("/proc"))) {
		perror("can't open /proc");
		return pids;
	}

	while ((ent = readdir(dir)) != NULL) {
		/* if endptr is not a null character, the directory is not
		 * entirely numeric, so ignore it */
		long lpid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != '\0') {
			continue;
		}
		char arg1[20] = { 0 };
		char exepath[4097] = { 0 };
		sprintf(arg1, "/proc/%d/exe", lpid);
		ssize_t len = readlink(arg1, exepath, 1024);
		if (len == -1)
			continue;
		exepath[len] = '\0';
		string spath = string(exepath);
		//	TRACE("%d exe path %s\n",lpid,exepath);
		if (spath == name) {
			pids.push_back(lpid);

		}
		if (spath.find(sPathWithSpace) != string::npos) {
			pids.push_back(lpid);
		}

	}

	closedir(dir);
	return pids;

}

DWORD CAddressHelper::MakeNetcutSignIP(const string& p_sMac) {
	time_t rawtime;
	struct tm * ptm;
	time(&rawtime);
	ptm = gmtime(&rawtime);
	char strbuf[255];
	memset(strbuf, 0, 255);
	sprintf(strbuf, "%s %s %d", p_sMac.c_str(), ANTICUTKEY, ptm->tm_mday);
	string KeyIP = strbuf;
	MD5 md5er(KeyIP);
	string CryptStr = md5er.hexdigest();
	u_char *buf = (u_char *) CryptStr.c_str();
	return CAddressHelper::BufferIP2Int(buf);

}

bool CAddressHelper::isBrocastMAC(const u_char * p_sBuf) {
	if (memcmp(p_sBuf, CAddressHelper::m_macBrocast, 6) == 0)
		return true;
	return false;

}
bool CAddressHelper::isEmptyMac(const unsigned char *p_macbuf) {

	unsigned char nomac[6];
	memset(nomac, 0, 6);
	if (0 == memcmp(p_macbuf, nomac, 6))
		return true;

	return false;

}

bool CAddressHelper::isBrocastIP(DWORD p_nIP) {

	if (CAddressHelper::n239 == p_nIP)
		return true;
	return CAddressHelper::isSameRang(p_nIP, CAddressHelper::n224,
			CAddressHelper::nmask);

}

bool CAddressHelper::isSameRang(DWORD p_n1, DWORD p_n2, DWORD p_nMask) {

	p_n1 = p_n1 & p_nMask;
	p_n2 = p_n2 & p_nMask;

	//TRACE("P1 %s\nP2 %s\n",CAddressHelper::IntIP2str(p_n1).c_str(),CAddressHelper::IntIP2str(p_n2).c_str());
	return (p_n1 == p_n2);

}
/*
 void CAddressHelper::GetNamebyIP(DWORD p_nIP)
 {


 m_nbt.Query(p_nIP);
 }

 void CAddressHelper::GetNamebyIP(string & p_sIP)
 {

 DWORD n=CAddressHelper::StrIP2Int(p_sIP);
 CAddressHelper::GetNamebyIP(n);
 }
 */
DWORD CAddressHelper::GetNextIP(DWORD p_nUIP) {
	p_nUIP = ntohl(p_nUIP);
	p_nUIP++;
	return htonl(p_nUIP);
}

DWORD CAddressHelper::GetTotalIPNumber(const DWORD & p_startIP,
		const DWORD &p_EndIP) {
	//Get the first IP     Mask are all 1, so & left what masked network part
	DWORD n1 = ntohl(p_startIP);
	DWORD n2 = ntohl(p_EndIP);
	return (n2 - n1);

}

void CAddressHelper::GetIpRang(const DWORD &p_nIP, const DWORD &p_nMask,
		DWORD & p_startIP, DWORD &p_EndIP) {
	//Get the first IP     Mask are all 1, so & left what masked network part
	p_startIP = p_nIP & p_nMask;
	//get the last IP   revese mask, with start IP a xor ^ will get all max Ip
	DWORD NotIP = ~p_nMask;
	NotIP = NotIP ^ p_startIP;

	p_EndIP = CAddressHelper::StrIP2Int(IntIP2str(NotIP));

}
void CAddressHelper::GetMCastMac(DWORD p_nDstIP, u_char * p_buf) {

	char a = CAddressHelper::m_macMCast[4];
	a = a & (0xff << 7);
	char * ip = (char *) &p_nDstIP;
	char a1 = *(ip + 1);
	a1 = a1 & (0xff >> 1);
	a = a | a1;
	memcpy(p_buf, CAddressHelper::m_macMCast, 3);
	*(p_buf + 3) = a;
	memcpy(p_buf + 4, ip + 2, 2);

	//  TRACE("Target Mac is %s\n",CAddressHelper::BufferMac2str(p_buf).c_str());

}
void CAddressHelper::GetBrocastMac(u_char * p_buf) {

	u_char buf[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	memcpy(p_buf, buf, 6);

}
void CAddressHelper::GetEmptyMac(u_char * p_buf) {
	memset(p_buf, 0, 6);

}

string CAddressHelper::GetMacBrand(const u_char * p_sbuff) {

	std::string s;
	s.append(_helper_GetHexCode((char *) p_sbuff, 1));
	for (int i = 1; i < 3; i++) {

		s.append(_helper_GetHexCode((char *) p_sbuff + i, 1));

	}
	if (CAddressHelper::m_Mac2Brand.count(s))
		return CAddressHelper::m_Mac2Brand[s];
	return "";

}

bool CAddressHelper::IsRunningAsRoot() {
	return (getuid() == 0 || geteuid() == 0);
}

map<DWORD, MACADDR> CAddressHelper::GetARPCache(string p_sDevName) {
	map<DWORD, MACADDR> arpmap;
	unsigned char zerobuf[6];
	memset(zerobuf, 0, 6);

	const int size = 256;
	char ip_address[size];
	int hw_type;
	int flags;
	char mac_address[size];
	char mask[size];
	char device[size];

	do
	{
	FILE* fp = fopen("/proc/net/arp", "r");
	if (fp == NULL) {
		//TRACE("Error opening /proc/net/arp");
		break;
	}

	char line[size];
	fgets(line, size, fp); // Skip the first line, which consists of column headers.
	while (fgets(line, size, fp)) {
		sscanf(line, "%s 0x%x 0x%x %s %s %s\n", ip_address, &hw_type, &flags,
				mac_address, mask, device);

		if (p_sDevName != device)
			continue;
		//printf("IP = %s, MAC = %s", ip_address, mac_address);
		DWORD nIP = CAddressHelper::StrIP2Int(ip_address);

		MACADDR sMac = CAddressHelper::MacBuffer2Array(
				(unsigned char *) _helper_Hex2Buffer(mac_address).data());
		// TRACE("IP %s Mac %s\n",CAddressHelper::IntIP2str(nIP).c_str(),CAddressHelper::BufferMac2str(sMac.data()).c_str());
		if (memcmp(zerobuf, sMac.data(), 6) != 0) {
			arpmap[nIP] = sMac;
		}
	}

	fclose(fp);
	}while(false);
	return arpmap;

}
array<u_char, 6> CAddressHelper::MacBuffer2Array(const u_char * p_buf) {

	array<u_char, 6> a;
	memcpy(a.data(), p_buf, 6);
	return a;

}
array<u_char, 6> CAddressHelper::GetBrocastMac() {

	return CAddressHelper::MacBuffer2Array(CAddressHelper::m_macBrocast);

}

bool CAddressHelper::isSameRang(std::string& p_s1, std::string& p_s2,
		std::string& p_sMask) {

	return isSameRang(inet_addr(p_s1.c_str()), inet_addr(p_s2.c_str()),
			inet_addr(p_sMask.c_str()));

}

bool CAddressHelper::GetNetCards(list<AdapterInfo> & p_AdapterList) {
	return true;
}
/*
 bool CAddressHelper::GetDevInfo(string &p_sDevName, AdapterInfo & p_AdapterInfo) {

 struct ifaddrs *ifaddr, *ifa;
 int n;
 p_AdapterInfo.bUp=false;

 if (getifaddrs(&ifaddr) == -1) {
 perror("getifaddrs");
 return false;
 }



 for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
 if (p_sDevName == ifa->ifa_name) {
 //TRACE("%s ", ifa->ifa_name);
 //TRACE(" %s\n", ifa->ifa_flags & IFF_LOWER_UP ? "UP" : "Down");

 p_AdapterInfo.bUp = ifa->ifa_flags & IFF_LOWER_UP;

 if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {


 DWORD nIP =
 ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
 DWORD nMask =
 ((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr;
 //	TRACE(" %s %s", CAddressHelper::IntIP2str(nIP).c_str(),	CAddressHelper::IntIP2str(nMask).c_str());
 Address s;
 s.Ip=nIP;
 s.Mask=nMask;
 p_AdapterInfo.IPs.push_back(s);
 }

 }

 }

 freeifaddrs(ifaddr);

 int fd;
 struct ifreq ifr;

 fd = socket(AF_INET, SOCK_DGRAM, 0);

 if(-1==fd)
 {
 return false;

 }


 ifr.ifr_addr.sa_family = AF_INET;


 strncpy(ifr.ifr_name, p_sDevName.c_str(), IFNAMSIZ - 1);

 //ioctl(fd, SIOCGIFADDR, &ifr);

 //printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
 //ioctl(fd, SIOCGIFNETMASK, &ifr);


 //printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr));
 if(-1!=ioctl(fd, SIOCGIFHWADDR, &ifr))
 {
 //	printf("%s\n",	CAddressHelper::BufferMac2str(&ifr.ifr_hwaddr.sa_data[0]).c_str());

 memcpy(p_AdapterInfo.Mac,&ifr.ifr_hwaddr.sa_data[0],6);
 }

 close(fd);


 int sock, i;
 struct ifreq ifreqs[20];
 struct ifconf ic;

 ic.ifc_len = sizeof ifreqs;
 ic.ifc_req = ifreqs;

 sock = socket(AF_INET, SOCK_DGRAM, 0);
 if (sock < 0) {
 perror("socket");
 exit(1);
 }

 if (ioctl(sock, SIOCGIFCONF, &ic) < 0) {
 perror("SIOCGIFCONF");
 exit(1);
 }

 for (i = 0; i < ic.ifc_len/sizeof(struct ifreq); ++i)
 printf("%s: %s\n", ifreqs[i].ifr_name,
 inet_ntoa(((struct sockaddr_in*)&ifreqs[i].ifr_addr)->sin_addr));



 return GetDevGateWay(p_sDevName,p_AdapterInfo.Gateways);

 }
 */
bool CAddressHelper::IsDevOn(string p_sDevName) {
	bool retB = false;
	int fd;
	DWORD nMask = 0;
	struct ifreq ifr;

	do {
		fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (-1 == fd) {
			break;
		}

		ifr.ifr_addr.sa_family = AF_INET;

		strncpy(ifr.ifr_name, p_sDevName.c_str(), IFNAMSIZ - 1);

		if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
			TRACE("Device %s does not exist\n", p_sDevName.c_str());
			break;
		}
		retB = true;
	} while (false);

	close(fd);
	return retB;

	/*	ioctl(fd, SIOCGIFFLAGS, &ifr);

	 p_AdapterInfo.bUp = ifr.ifr_flags & IFF_UP;
	 */

}

bool CAddressHelper::GetInterfaceIP(string p_sIfName, DWORD & p_nIP) {

	bool bFoundDev=false;
	int sock, i;
	struct ifreq ifreqs[20];
	struct ifconf ic;

	ic.ifc_len = sizeof ifreqs;
	ic.ifc_req = ifreqs;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return false;
	}

	if (ioctl(sock, SIOCGIFCONF, &ic) < 0) {
		perror("SIOCGIFCONF");
		close(sock);
		return false;
	}

	for (i = 0; i < ic.ifc_len / sizeof(struct ifreq); ++i) {

		if (p_sIfName == ifreqs[i].ifr_name) {

			bFoundDev = true;
			p_nIP = ((struct sockaddr_in*) &ifreqs[i].ifr_addr)->sin_addr.s_addr;
            break;
		}
	}

	close(sock);

	return bFoundDev;

}

bool CAddressHelper::GetInterfaceMac(string p_sIfName,
		unsigned char * p_macbuff) {

	bool bFoundDev = false;
	int fd;
	DWORD nMask = 0;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (-1 == fd) {
		return false;

	}

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, p_sIfName.c_str(), IFNAMSIZ - 1);

	if (-1 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
			TRACE("Device %s does not exist\n", p_sIfName.c_str());
		return false;
	}

	memcpy(p_macbuff, &ifr.ifr_hwaddr.sa_data[0], 6);

	return true;

}
bool CAddressHelper::GetDevInfo(string &p_sDevName,
		AdapterInfo & p_AdapterInfo) {

	bool bFoundDev = false;
	int fd;
	DWORD nMask = 0;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (-1 == fd) {
		return false;

	}

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, p_sDevName.c_str(), IFNAMSIZ - 1);

	//ioctl(fd, SIOCGIFADDR, &ifr);

	//printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	ioctl(fd, SIOCGIFNETMASK, &ifr);

	//	printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr));
	nMask = ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr;

	if (-1 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		//	printf("%s\n",	CAddressHelper::BufferMac2str(&ifr.ifr_hwaddr.sa_data[0]).c_str());
		TRACE("Device %s does not exist\n", p_sDevName.c_str());
		return false;
	}

	memcpy(p_AdapterInfo.Mac, &ifr.ifr_hwaddr.sa_data[0], 6);
	p_AdapterInfo.macarray = CAddressHelper::MacBuffer2Array(p_AdapterInfo.Mac);

	ioctl(fd, SIOCGIFFLAGS, &ifr);

	p_AdapterInfo.bUp = ifr.ifr_flags & IFF_UP;

	close(fd);

	int sock, i;
	struct ifreq ifreqs[20];
	struct ifconf ic;

	ic.ifc_len = sizeof ifreqs;
	ic.ifc_req = ifreqs;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return false;
	}

	if (ioctl(sock, SIOCGIFCONF, &ic) < 0) {
		perror("SIOCGIFCONF");
		close(sock);
		return false;
	}

	for (i = 0; i < ic.ifc_len / sizeof(struct ifreq); ++i) {

		if (p_sDevName == ifreqs[i].ifr_name) {

			bFoundDev = true;
			Address s;
			s.Ip = ((struct sockaddr_in*) &ifreqs[i].ifr_addr)->sin_addr.s_addr;
			s.Mask = nMask;
			s.bHasMac = true;
			memcpy(s.buff, p_AdapterInfo.Mac, 6);
			p_AdapterInfo.IPs[s.Ip] = s;
		}
	}

	close(sock);
	if (!bFoundDev)
		return bFoundDev;

	return GetDevGateWay(p_sDevName, p_AdapterInfo.Gateways, nMask);

}

void CAddressHelper::loadMac2BrandMap() {
	ifstream myfile;
	string fullpath = CAddressHelper::getAppPath();
	fullpath += MACBRANDFILE;
	myfile.open(fullpath, ios::in);

	if (myfile.is_open()) {

		std::string line;
		while (std::getline(myfile, line)) {
			string code = line.substr(0, 6);
			string brand = line.substr(6);
			//TRACE("%s %s",code.c_str(),brand.c_str());
			CAddressHelper::m_Mac2Brand[code] = brand;
		}
	}

	myfile.close();

}
bool CAddressHelper::GetDevGateWay(string &p_sDevName,
		std::map<DWORD, Address> & p_Gateways, DWORD p_nMask) {

#define ROUTEBUFFSIZE 2048
//#define ROUTEBUFFSIZE 1024
#define ROUTETABLELIMIT 24
//#define ROUTETABLELIMIT 0
//#pragma pack(2)
// Structure for sending the request
	typedef struct {
		struct nlmsghdr nlMsgHdr;
		struct rtmsg rtMsg;
		u_char buf[1024];
	} route_request;

	struct RouteInfo {
		unsigned int dstAddr;
		unsigned int mask;
		unsigned int gateWay;
		unsigned int flags;
		unsigned int srcAddr;
		char proto;
		char ifName[IF_NAMESIZE];
	};

	int route_sock, i, j;
	route_request NewRequest;
	route_request *request = &NewRequest;
	int retValue = -1, nbytes = 0, reply_len = 0;
	u_char reply_ptr[ROUTEBUFFSIZE];
	ssize_t counter = ROUTEBUFFSIZE;
	int count = 0;
	struct rtmsg *rtp;
	struct rtattr *rtap;
	struct nlmsghdr *nlp;
	int rtl;
	struct RouteInfo route[ROUTETABLELIMIT];
	u_char* buf = reply_ptr;
	unsigned long bufsize;

	route_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (-1 == route_sock) {
		TRACE("Unable to get gateway netlink_sock\n");
		return false;
	}

	bzero(request, sizeof(route_request));

	request->nlMsgHdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	request->nlMsgHdr.nlmsg_type = RTM_GETROUTE;
	request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	// set the routing message header
	request->rtMsg.rtm_family = AF_INET;
	request->rtMsg.rtm_table = RT_TABLE_MAIN; //	RT_TABLE_MAIN

	if ((retValue = send(route_sock, request, sizeof(route_request), 0)) < 0) {
		TRACE("Error Finding Gateway\n");
		return false;
	}

	for (;;) {
		if (counter < sizeof(struct nlmsghdr)) {
			TRACE("Routing table is bigger than 1024\n");
			return false;
		}

		nbytes = recv(route_sock, &reply_ptr[reply_len], counter, 0);

		if (nbytes <= 0) {
			TRACE("Error in recv\n");
			break;
		}

		/*
		 * if (nbytes == 0)
		 TRACE("EOF in netlink\n");
		 */
		nlp = (struct nlmsghdr*) (&reply_ptr[reply_len]);

//		TRACE("Router NetLINK PID %d\n",nlp->nlmsg_pid);

		if (nlp->nlmsg_type == NLMSG_DONE) {
			// All data has been received.
			// Truncate the reply to exclude this message,
			// i.e. do not increase reply_len.
			break;
		}

		if (nlp->nlmsg_type == NLMSG_ERROR) {
			TRACE("Error in msg\n");
			return false;
		}

		reply_len += nbytes;
		counter -= nbytes;

	}

	bufsize = reply_len;
	//TRACE("Router Buffer size %d\n",bufsize);
	// string to hold content of the route
	// table (i.e. one entry)

	// outer loop: loops thru all the NETLINK
	// headers that also include the route entry
	// header
	nlp = (struct nlmsghdr *) buf;

	for (i = -1; NLMSG_OK(nlp, bufsize); nlp = NLMSG_NEXT(nlp, bufsize)) {
		// get route entry header
		rtp = (struct rtmsg *) NLMSG_DATA(nlp);
		// we are only concerned about the
		// tableId route table
		if (rtp->rtm_table != RT_TABLE_MAIN)
			continue;
		if (i >= ROUTETABLELIMIT)
			break;  //Can only hold 24 route
		i++;

		// init all the strings
		bzero(&route[i], sizeof(struct RouteInfo));
		//flags = rtp->rtm_flags;
		route[i].proto = rtp->rtm_protocol;

		// inner loop: loop thru all the attributes of
		// one route entry
		rtap = (struct rtattr *) RTM_RTA(rtp);
		rtl = RTM_PAYLOAD(nlp);
		for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
			switch (rtap->rta_type) {
			// destination IPv4 address
			case RTA_DST:
				count = 32 - rtp->rtm_dst_len;

				route[i].dstAddr = *(unsigned long *) RTA_DATA(rtap);

				route[i].mask = 0xffffffff;
				for (; count != 0; count--)
					route[i].mask = route[i].mask << 1;

				//	printf("dst:%s \tmask:0x%x \t",CAddressHelper::IntIP2str(route[i].dstAddr).c_str(), route[i].mask);
				break;
			case RTA_GATEWAY:
				route[i].gateWay = *(unsigned long *) RTA_DATA(rtap);
				//	printf("gw:%s\t",CAddressHelper::IntIP2str(route[i].gateWay).c_str());
				break;
			case RTA_PREFSRC:
				route[i].srcAddr = *(unsigned long *) RTA_DATA(rtap);
				//	printf("src:%s\t", CAddressHelper::IntIP2str(route[i].srcAddr).c_str());
				break;
				// unique ID associated with the network
				// interface
			case RTA_OIF:
				CAddressHelper::GetInterfaceName(*((int *) RTA_DATA(rtap)),
						route[i].ifName);
				//	printf("ifname %s\n", route[i].ifName);
				break;
			default:
				break;
			}

		}
		//set Flags

	}

	//TRACE("Total Route info %d\n", i);
	// Print the route records
//	printf("Destination\tGateway \tNetmask \tflags \tIfname \n");
//	printf("———–\t——- \t——–\t——\t—— \n");
	for (j = 0; j <= i; j++) {

		if (p_sDevName == route[j].ifName && route[j].gateWay != 0) {
			Address newGate;
			newGate.Ip = route[j].gateWay;
			newGate.Mask = p_nMask;
			p_Gateways[newGate.Ip] = newGate;

			//	TRACE(" %s \t %s\n",CAddressHelper::IntIP2str(route[j].gateWay).c_str(), route[j].ifName);

		}
		/*
		 printf("%s \t %s \t0x%08x \t%d \t%s\n",
		 CAddressHelper::IntIP2str(route[j].dstAddr).c_str(),
		 CAddressHelper::IntIP2str(route[j].gateWay).c_str(),
		 route[j].mask,
		 route[j].flags,
		 route[j].ifName);
		 */

	}
	return true;
}

bool CAddressHelper::GetDevGateIP(string &p_sDevName,
		DWORD & p_nGateIP) {

#define ROUTEBUFFSIZE 2048

#define ROUTETABLELIMIT 24

	typedef struct {
		struct nlmsghdr nlMsgHdr;
		struct rtmsg rtMsg;
		u_char buf[1024];
	} route_request;

	struct RouteInfo {
		unsigned int dstAddr;
		unsigned int mask;
		unsigned int gateWay;
		unsigned int flags;
		unsigned int srcAddr;
		char proto;
		char ifName[IF_NAMESIZE];
	};

	int route_sock, i, j;
	route_request NewRequest;
	route_request *request = &NewRequest;
	int retValue = -1, nbytes = 0, reply_len = 0;
	u_char reply_ptr[ROUTEBUFFSIZE];
	ssize_t counter = ROUTEBUFFSIZE;
	int count = 0;
	struct rtmsg *rtp;
	struct rtattr *rtap;
	struct nlmsghdr *nlp;
	int rtl;
	struct RouteInfo route[ROUTETABLELIMIT];
	u_char* buf = reply_ptr;
	unsigned long bufsize;

	route_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (-1 == route_sock) {
		TRACE("Unable to get gateway netlink_sock\n");
		return false;
	}

	bzero(request, sizeof(route_request));

	request->nlMsgHdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	request->nlMsgHdr.nlmsg_type = RTM_GETROUTE;
	request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	// set the routing message header
	request->rtMsg.rtm_family = AF_INET;
	request->rtMsg.rtm_table = RT_TABLE_MAIN; //	RT_TABLE_MAIN

	if ((retValue = send(route_sock, request, sizeof(route_request), 0)) < 0) {
		TRACE("Error Finding Gateway\n");
		return false;
	}

	for (;;) {
		if (counter < sizeof(struct nlmsghdr)) {
			TRACE("Routing table is bigger than 1024\n");
			return false;
		}

		nbytes = recv(route_sock, &reply_ptr[reply_len], counter, 0);

		if (nbytes <= 0) {
			TRACE("Error in recv\n");
			break;
		}
    	nlp = (struct nlmsghdr*) (&reply_ptr[reply_len]);

//		TRACE("Router NetLINK PID %d\n",nlp->nlmsg_pid);

		if (nlp->nlmsg_type == NLMSG_DONE) {
			break;
		}

		if (nlp->nlmsg_type == NLMSG_ERROR) {
			TRACE("Error in msg\n");
			return false;
		}

		reply_len += nbytes;
		counter -= nbytes;

	}

	bufsize = reply_len;
	//TRACE("Router Buffer size %d\n",bufsize);
	// string to hold content of the route
	// table (i.e. one entry)

	// outer loop: loops thru all the NETLINK
	// headers that also include the route entry
	// header
	nlp = (struct nlmsghdr *) buf;

	for (i = -1; NLMSG_OK(nlp, bufsize); nlp = NLMSG_NEXT(nlp, bufsize)) {
		// get route entry header
		rtp = (struct rtmsg *) NLMSG_DATA(nlp);
		// we are only concerned about the
		// tableId route table
		if (rtp->rtm_table != RT_TABLE_MAIN)
			continue;
		if (i >= ROUTETABLELIMIT)
			break;  //Can only hold 24 route
		i++;

		// init all the strings
		bzero(&route[i], sizeof(struct RouteInfo));
		//flags = rtp->rtm_flags;
		route[i].proto = rtp->rtm_protocol;

		// inner loop: loop thru all the attributes of
		// one route entry
		rtap = (struct rtattr *) RTM_RTA(rtp);
		rtl = RTM_PAYLOAD(nlp);
		for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
			switch (rtap->rta_type) {
			// destination IPv4 address
			case RTA_DST:
				count = 32 - rtp->rtm_dst_len;

				route[i].dstAddr = *(unsigned long *) RTA_DATA(rtap);

				route[i].mask = 0xffffffff;
				for (; count != 0; count--)
					route[i].mask = route[i].mask << 1;

				//	printf("dst:%s \tmask:0x%x \t",CAddressHelper::IntIP2str(route[i].dstAddr).c_str(), route[i].mask);
				break;
			case RTA_GATEWAY:
				route[i].gateWay = *(unsigned long *) RTA_DATA(rtap);
				//	printf("gw:%s\t",CAddressHelper::IntIP2str(route[i].gateWay).c_str());
				break;
			case RTA_PREFSRC:
				route[i].srcAddr = *(unsigned long *) RTA_DATA(rtap);
				//	printf("src:%s\t", CAddressHelper::IntIP2str(route[i].srcAddr).c_str());
				break;
				// unique ID associated with the network
				// interface
			case RTA_OIF:
				CAddressHelper::GetInterfaceName(*((int *) RTA_DATA(rtap)),
						route[i].ifName);
				//	printf("ifname %s\n", route[i].ifName);
				break;
			default:
				break;
			}

		}
		//set Flags

	}

	//TRACE("Total Route info %d\n", i);
	// Print the route records
//	printf("Destination\tGateway \tNetmask \tflags \tIfname \n");
//	printf("———–\t——- \t——–\t——\t—— \n");
	for (j = 0; j <= i; j++) {

		if (p_sDevName == route[j].ifName && route[j].gateWay != 0) {
			p_nGateIP = route[j].gateWay;

	//		TRACE(" %s \t %s\n",CAddressHelper::IntIP2str(route[j].gateWay).c_str(), route[j].ifName);

		}
		/*
		 printf("%s \t %s \t0x%08x \t%d \t%s\n",
		 CAddressHelper::IntIP2str(route[j].dstAddr).c_str(),
		 CAddressHelper::IntIP2str(route[j].gateWay).c_str(),
		 route[j].mask,
		 route[j].flags,
		 route[j].ifName);
		 */

	}
	return true;
}
bool CAddressHelper::IsInterfaceUp(string p_sIfName) {

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	struct ifreq ethreq;

	memset(&ethreq, 0, sizeof(ethreq));

	/* set the name of the interface we wish to check */
	strncpy(ethreq.ifr_name, p_sIfName.c_str(), IFNAMSIZ);
	/* grab flags associated with this interface */
	ioctl(fd, SIOCGIFFLAGS, &ethreq);
	//bool bRet=((ethreq.ifr_flags & IFF_LOWER_UP) && (ethreq.ifr_flags & IFF_RUNNING));
	bool bRet = ethreq.ifr_flags & IFF_UP;
	close(fd);

	// ifInfo.bIsUp = (ifMsg->ifi_flags & IFF_LOWER_UP && ifMsg->ifi_flags & IFF_RUNNING)? 1 : 0;
	return bRet;
}
bool CAddressHelper::GetInterfaceName(int if_index, char *ifName) {
	int fd;

	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		return false;
	}

	ifr.ifr_ifindex = if_index;

	if (ioctl(fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		return false;
	}

	strcpy(ifName, ifr.ifr_name);
	return true;
}
void CAddressHelper::Remove_ArpEntry(DWORD p_nIP) {

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	do {
		if (fd < 0)
			break;

		struct arpreq ar;
		struct sockaddr_in *sock;
		memset(&ar, 0, sizeof(struct arpreq));
		sock = (struct sockaddr_in *) &ar.arp_pa;
		sock->sin_family = AF_INET;
		sock->sin_addr.s_addr = p_nIP;//CAddressHelper::StrIP2Int("192.168.1.120");

		if (ioctl(fd, SIOCDARP, (char *) &ar) < 0) {
			//if (errno != ENXIO)
			//	perror("lowARPreg REM1 failed SIOCDARP");
		};

	} while (false);

	if (fd >= 0) {
		close(fd);
	}
}
void CAddressHelper::Add_ArpEntry(DWORD p_nIP, const u_char * p_sMac,
		string p_sDevName) {

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	do {
		if (fd < 0)
			break;

		struct arpreq ar;
		struct sockaddr_in *sock;
		memset(&ar, 0, sizeof(struct arpreq));
		sock = (struct sockaddr_in *) &ar.arp_pa;
		sock->sin_family = AF_INET;
		sock->sin_addr.s_addr = p_nIP;//CAddressHelper::StrIP2Int("192.168.1.120");

		ar.arp_ha.sa_family = ARP_HRD_ETH;

		strcpy(ar.arp_dev, p_sDevName.c_str());

		memcpy(ar.arp_ha.sa_data, p_sMac, 6);
		ar.arp_flags = (ATF_PERM);
		if (ioctl(fd, SIOCSARP, (char *) &ar) < 0) {
			//	perror("lowARPreg PROXY failed SIOCSARP");
		};
	} while (false);

	if (fd >= 0) {
		close(fd);
	}
}
