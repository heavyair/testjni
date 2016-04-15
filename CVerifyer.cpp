/*
 * CVerifyer.cpp
 *
 *  Created on: Mar 9, 2016
 *      Author: root
 */

#include "CVerifyer.h"
#include <CZlib.h>
#include "CHTTPClient.h"
#include "CBase64.h"
#include "netheader.h"
#include "CAddressHelper.h"

namespace NETCUT_CORE_FUNCTION {

CVerifyer::CVerifyer() {
	// TODO Auto-generated constructor stub
	this->m_nPaidFlag = 0;

}

CVerifyer::~CVerifyer() {
	// TODO Auto-generated destructor stub
}

bool CVerifyer::Verify() {

	this->m_nPaidFlag = 0;

	string QueryOption = "name=" + m_sName;
	QueryOption += ":id=" + m_sMac;
	QueryOption += ":id2=" + m_sGateMac;
	QueryOption += ":id3=" + m_sKnownGps;
	QueryOption += ":id4=" + m_sRealGps;
	QueryOption += ":id5=" + m_sAllMac;

	string sQueryStr = base64_encode((unsigned char *) QueryOption.c_str(),
			QueryOption.size());

	CZlib c;
	if (!c.Compress((unsigned char *) sQueryStr.c_str(), sQueryStr.length())) {
		TRACE("Unable to compress\n");
		return false;
	}
	string sPostData((const char *)c.m_pResult, c.m_nResultSize);

	string m_sUpdateUrl = "http://www.arcai.com/netCut/verify.php";

	string sRetStr = "";

	CHTTPClient client;

	if (!client.OpenUrl(false, m_sUpdateUrl, sPostData)) {
		TRACE("Error: Can't open %s\n", m_sUpdateUrl.c_str());
		return false;
	}

	int numBytes;
	char buff;
	while (1) {
		numBytes = client.Read(&buff, 1);
		if (numBytes > 0) {
			sRetStr.append(1, buff);
		} else {
			break;
		}
	}
	sQueryStr = base64_decode(sRetStr);
	std::vector<string> RetArray = ::_helper_splitstring(sQueryStr, "\r\n");

	for (int i = 0; i < RetArray.size(); i++) {
		string s = base64_decode(RetArray[i]);
		vector<string> pairs = _helper_splitstring_pair(s, "=");
		if (pairs.size() == 2) {
			this->m_Return[pairs[0]] = pairs[1];
		}
	}


	         string sPaid=GetReturn("paid");
				if(sPaid=="true")
				{
					this->m_nPaidFlag = 1;
				}
				if(sPaid=="false")
				{
					this->m_nPaidFlag = 2;
				}

				string sMacAge=GetReturn("macage");
				if(sMacAge!="")
				{
					std::vector<string> magagearray = ::_helper_splitstring(sMacAge, "\r\n");
					for (int i = 0; i < magagearray.size(); i++) {
							string s = RetArray[i];
							vector<string> pairs = _helper_splitstring_pair(s, "=");
							if (pairs.size() == 2) {
                             this->m_MacAge[CAddressHelper::StrMac2Array(pairs[0])]=atoi(pairs[1].c_str());

							}
						}
				}

	return true;

}

string CVerifyer::GetReturn(string p_sKey) {

	std::map<string,string>::iterator it;
	it=m_Return.find(p_sKey);

	if(it!=m_Return.end())
	{
	 return m_Return[p_sKey];
	}
	else
	{
		return "";
	}

}

} /* namespace NETCUT_CORE_FUNCTION */
