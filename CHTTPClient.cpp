/*
 * CHTTPClient.cpp
 *
 *  Created on: Apr 27, 2015
 *      Author: root
 */

#include <regex.h>
#include "CHTTPClient.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "netheader.h"

CHTTPClient::CHTTPClient(string p_sAgentName) {

	this->m_sUserAgent = p_sAgentName;
	m_pSocket=NULL;
}

CHTTPClient::~CHTTPClient() {

	if(m_pSocket!=NULL)
	delete m_pSocket;
}

int CHTTPClient::Read(char *p_sbuf, int p_nbufLen) {

	if(NULL==m_pSocket) return 0;
	return m_pSocket->recv(p_sbuf, p_nbufLen);

}

unsigned long CHTTPClient::GetContentSize()
{
  return atoi(m_Responses["Content-Length"].c_str());
}

std::vector<string> CHTTPClient::splitstring(string p_sString,string p_sToken) {

	           vector<string> strings;

	 			string s;
	 			int nStartIndex=0;
	 			int nIndex=p_sString.find(p_sToken,nStartIndex);
	 			while(nIndex!=string::npos)
	 			{
	 				s=p_sString.substr(nStartIndex,nIndex-nStartIndex);

 					strings.push_back(s);
 					nStartIndex=nIndex+p_sToken.size();
 					nIndex=p_sString.find(p_sToken,nStartIndex);
	 			}
	 				if(nStartIndex<p_sString.size())
	 				{
	 					nIndex=p_sString.size();
	 					strings.push_back(p_sString.substr(nStartIndex,nIndex-nStartIndex));
	 				}

	    return strings;
}

void CHTTPClient::ParseHeader()
{


	std::vector<string> responses=splitstring(m_sReturnHeader,"\r\n");

	for(int i=0;i<responses.size();i++)
	{
		string sSpacer=(i==0)?" ":": ";
		int n=responses[i].find(sSpacer);
		if(n!=string::npos)
		{
			string sName=i==0?HTTP_RESPONSE_CODE:responses[i].substr(0,n);
			string sValue=responses[i].substr(n+sSpacer.size(),responses[i].size()-sSpacer.size());
			this->m_Responses[sName]=sValue;
		}
	}

}
std::string CHTTPClient::UrlDecode(const std::string& str)
{
    std::string strTemp = "";
    size_t length = str.length();
    for (size_t i = 0; i < length; i++)
    {
        if (str[i] == '+') strTemp += ' ';
        else if (str[i] == '%')
        {
         //   assert(i + 2 < length);
            unsigned char high = FromHex((unsigned char)str[++i]);
            unsigned char low = FromHex((unsigned char)str[++i]);
            strTemp += high*16 + low;
        }
        else strTemp += str[i];
    }
    return strTemp;
}
std::string CHTTPClient::UrlEncode(std::string const & source)
{
	  std::string strTemp = "";
	    size_t length = source.length();
	    for (size_t i = 0; i < length; i++)
	    {
	        if (isalnum((unsigned char)source[i]) ||
	            (source[i] == '-') ||
	            (source[i] == '_') ||
	            (source[i] == '.') ||
	            (source[i] == '~'))
	            strTemp += source[i];
	        else if (source[i] == ' ')
	            strTemp += "+";
	        else
	        {
	            strTemp += '%';
	            strTemp += ToHex((unsigned char)source[i] >> 4);
	            strTemp += ToHex((unsigned char)source[i] % 16);
	        }
	    }
	    return strTemp;
}

unsigned char CHTTPClient::ToHex(unsigned char x)
{
    return  x > 9 ? x + 55 : x + 48;
}

unsigned char CHTTPClient::FromHex(unsigned char x)
{
    unsigned char y;
    if (x >= 'A' && x <= 'Z') y = x - 'A' + 10;
    else if (x >= 'a' && x <= 'z') y = x - 'a' + 10;
    else if (x >= '0' && x <= '9') y = x - '0';
    else y=0;
    return y;
}

bool CHTTPClient::OpenUrl(bool p_bGet,const string & p_sUrl,const string & p_sPostContent)
{


	        char buf[4192];
			memset(buf, 0, 4192);
			string sHost;
			int nPort, ret;
			string sUri;
			bool sRet =false;
		//	TRACE("Parse URL %s\n", p_sUrl.c_str());
			if (!parseURL(p_sUrl, sHost, nPort, sUri)) {
		//		TRACE("Unable to parse URL %s\n", p_sUrl.c_str());
				return false;
			}

			string sBuf;

			try {
				this->m_pSocket=new TCPSocket(sHost, nPort);
			//	TRACE("Connected to %s\n", sHost.c_str());

				char *get =
						"GET /%s HTTP/1.0\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: Close\r\nHost: %s\r\n\r\n";
				char *post ="POST /%s HTTP/1.0\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nAccept: */*\r\nConnection: Close\r\nHost: %s\r\n\r\n";

				if(p_bGet)
				{
				sprintf(buf, get, sUri.c_str(), m_sUserAgent.c_str(), sHost.c_str());
				sBuf=buf;
				}
				else
				{
				sprintf(buf, post, sUri.c_str(), m_sUserAgent.c_str(),p_sPostContent.size(),sHost.c_str());
				sBuf=buf;
				sBuf+=p_sPostContent;
				}
				m_pSocket->send(sBuf.c_str(),sBuf.size());
			//	TRACE("Sent request %s\n", buf);
				string sDoubleLine="\r\n\r\n";
				string sHeader;
				char c;
				while ((ret = m_pSocket->recv(&c, 1)) != 0) {
					sHeader.append(1,c);
					if(tail(sHeader,4)==sDoubleLine)
					{
						m_sReturnHeader=sHeader;
					//	printf("Beging[%s]end",sHeader.c_str());
					//	printf("End");
						ParseHeader();
						string bGoodResponse="200";
					//	TRACE("Header code %s\n",m_Responses[HTTP_RESPONSE_CODE].c_str());
						if(m_Responses[HTTP_RESPONSE_CODE].find(bGoodResponse)!=string::npos)
								{
						sRet=true;
						}
						break;
					}

				}
				//TRACE("Header code %s\n",sHeader.c_str());
			} catch (SocketException &e) {

				TRACE("Socket Err: %s\n", e.what());
				if(m_pSocket!=NULL)
				{
				delete m_pSocket;
				m_pSocket=NULL;
				}

			}
		//	TRACE("Finish open url %s\n", sHost.c_str());
			return sRet;

}

bool CHTTPClient::OpenUrl(const string & p_sUrl) {

	return OpenUrl(true,p_sUrl,"");

}

std::string CHTTPClient::tail(std::string const& source, size_t const length) {
	  if (length >= source.size()) { return source; }
	  return source.substr(source.size() - length);
	} // tail


bool CHTTPClient::parseURL(const string & p_sUrl, string & p_Out_sHost,
		int & p_Out_nPort, string & p_Out_sUri) {
	//"\\(^GET /[^ ]*\\)"
	//string sPattern="http://\\([^/]*\\)\\(:\\d+\\)?\\([^ ]*\\)";
	// string sPattern='^(([^:]+)://)?([^:/]+)(:([0-9]+))?(/.*)';
	// p_sUrl="http://www.arcai.com:80/abx/xyz.php";
	// p_sUrl="http://www.arcai.com/abx/xyz.php";
	//string sPattern="http://([^/:]*)(:\\d+)([^ ]*)";
	string sPattern = "http://([^/:]*)(:([0-9]+))?(.*)?";
	regex_t preg;
	int rc;
	size_t nmatch = 5;
	regmatch_t pmatch[5];

	bool bMatched = false;
	if (0 != (rc = regcomp(&preg, sPattern.c_str(), REG_EXTENDED))) {
		printf("regcomp() failed, returning nonzero (%d)\n", rc);
		//exit(EXIT_FAILURE);
		return false;
	}

	if (REG_NOMATCH
			!= (rc = regexec(&preg, p_sUrl.c_str(), nmatch, pmatch, 0))) {
		p_Out_sHost = p_sUrl.substr(pmatch[1].rm_so,
				pmatch[1].rm_eo - pmatch[1].rm_so);
		if (pmatch[3].rm_so != -1 && pmatch[3].rm_eo != -1) {
			p_Out_nPort = atoi(
					p_sUrl.substr(pmatch[3].rm_so,
							pmatch[3].rm_eo - pmatch[3].rm_so).c_str());
		} else {
			p_Out_nPort = 80;
		}
		if (pmatch[4].rm_so != -1 && pmatch[4].rm_eo != -1) {
			p_Out_sUri = p_sUrl.substr(pmatch[4].rm_so,
					pmatch[4].rm_eo - pmatch[4].rm_so);
		} else {
			p_Out_sUri = "";
		}
		bMatched = true;

	}
	regfree(&preg);

	return bMatched;
}
