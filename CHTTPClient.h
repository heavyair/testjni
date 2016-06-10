/*
 * CHTTPClient.h
 *
 *  Created on: Apr 27, 2015
 *      Author: root
 */

#ifndef CHTTPCLIENT_H_
#define CHTTPCLIENT_H_
#include <string>
#include <vector>
#include <map>
#include "PracticalSocket.h"

using namespace std;

#define HTTP_RESPONSE_CODE "HTTP_RESPONSE_CODE"

class CHTTPClient {

public:
	CHTTPClient(string p_sAgentName="netcut");
	~CHTTPClient();
	int Read(char *p_sbuf,int p_nbufLen);
	bool OpenUrl(const string & p_sUrl);
	bool OpenUrl(bool p_bGet,const string & p_sUrl,const string & p_sPostContent);
	std::string UrlEncode(std::string const & source);
	std::string UrlDecode(const std::string& str);
	unsigned char FromHex(unsigned char x);
	unsigned char ToHex(unsigned char x);
	std::string tail(std::string const& source, size_t const length);
	std::vector<string> splitstring(string p_sString,string p_sToken);
	void ParseHeader();

public:
	bool parseURL(const string & p_sUrl,string & p_Out_sHost, int & p_Out_nPort, string & p_Out_sUri);

	unsigned long GetContentSize();
	string m_sUserAgent;
	string m_sReturnHeader;
	TCPSocket * m_pSocket;
	std::map<string,string> m_Responses;
};

#endif /* CHTTPCLIENT_H_ */
