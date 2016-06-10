/*
 * CHttpAccountUpdater.cpp
 *
 *  Created on: May 30, 2016
 *      Author: root
 */

#include <CHttpAccountUpdater.h>
#include <COpenSSL.h>
#include "CAddressHelper.h"
#include "CHTTPClient.h"

namespace NETCUT_CORE_FUNCTION {

CHttpAccountUpdater::CHttpAccountUpdater() {
	// TODO Auto-generated constructor stub

}

CHttpAccountUpdater::~CHttpAccountUpdater() {
	// TODO Auto-generated destructor stub
}

bool CHttpAccountUpdater::StatUpdate(std::string & p_sRet)
{
// Generate random 16 byte key, encrypt with RSA public server key, send to server
// Server return with 1|0 + data encrypted with the key
// data st=
// Decrypt the data and return ture

   string sDesKey=CAddressHelper::Gen_random_str(16);
	CHTTPClient client;
    COpenSSL s;
   	string sLogininfo=s.RsaEncodeServer(sDesKey);

   	string sQueryStr="st=";
   	sQueryStr+=client.UrlEncode(sLogininfo);


   	string m_sUpdateUrl="http://www.arcai.com/netCut/netcutst.php";

   		//TRACE("URL: %s \n",m_sUpdateUrl.c_str());



string sRetStr="";

   					if(!client.OpenUrl(false,m_sUpdateUrl,sQueryStr))
   						{
   						TRACE("Error: Can't open %s\n",m_sUpdateUrl.c_str());
   						return false;
   						}


   				     	int numBytes;
   									char buff;
   									numBytes = client.Read(&buff, 1);
   									if(numBytes>0)
   									{
   										int n=atoi(&buff);
   					                    if(n!=1)
   					                    	return false;
   									}
   									else{
   									return false;
   										}

   									while (1)
   								     {
   										numBytes = client.Read(&buff, 1);
   										if(numBytes>0)
   										{
   											sRetStr.append(1,buff);
   										}
   										else
   										{
   											break;
   										}
   									}

   							COpenSSL s2;
   							std::string sSt=s.aes_decode((const char *)sRetStr.c_str(),(char *)sDesKey.c_str());

   							if(sSt.size()==0) return false;
   							std::size_t nPos=sSt.find("st=");

                            if(nPos!=0) return false;
                            p_sRet=sSt.substr(3);
                            if(p_sRet.size()==0) return false;

/*
                            ofstream myfile;
                            		myfile.open("stdata.txt", ios::out);
                            		myfile.write((char *) p_sRet.c_str(), p_sRet.size());
                    		myfile.close();
  */

   									return true;

}
bool CHttpAccountUpdater::Login(std::string p_sUser,std::string p_sPass,std::string p_sMac)
{

	string sQueryStr;

	CHTTPClient client;
	if(p_sUser.size()==0)
	{
		 sQueryStr="refreshlogin=";
		 string sAccountInfo=CAddressHelper::GetAccountDetails();
		 if(sAccountInfo.size()==0) return false;
		 sQueryStr+=client.UrlEncode(sAccountInfo);;

	}
	else
	{
	char buf[1024];
	memset(buf,0,1024);
	sprintf(buf,"username=%s\npassword=%s\nmac=%s",p_sUser.c_str(),p_sPass.c_str(),p_sMac.c_str());

	  string QueryOption=buf;
	  string sDesKey=CAddressHelper::Gen_random_str(16);

	   COpenSSL s;
	   string sKey=s.RsaEncodeServer(sDesKey);

	   string sLogininfo=s.aes_encode((const char *)QueryOption.c_str(),(char *)sDesKey.c_str());
	   sQueryStr="k=";
	   	sQueryStr+=client.UrlEncode(sKey);

	   sQueryStr+="&l=";
	   sQueryStr+=client.UrlEncode(sLogininfo);

	   ofstream myfile;
                           		myfile.open("logindata.txt", ios::out);
                    			myfile.write((char *) sDesKey.c_str(), sDesKey.size());

                           		myfile.write((char *) "\n",1);
								myfile.write((char *) QueryOption.c_str(), QueryOption.size());
								myfile.write((char *) "\n",1);
                           		myfile.write((char *) sQueryStr.c_str(), sQueryStr.size());
                   		myfile.close();


	}




	string m_sUpdateUrl="http://www.arcai.com/netCut/netcutlogin.php";

	//string m_sUpdateUrl="http://www.cceye.com/wp-content/dev/testget.php";

	//TRACE("URL: %s \n",m_sUpdateUrl.c_str());

	string sRetStr="";


				if(!client.OpenUrl(false,m_sUpdateUrl,sQueryStr))
					{
					TRACE("Error: Can't open %s\n",m_sUpdateUrl.c_str());
					return false;
					}




				int numBytes;
				char buff;
				numBytes = client.Read(&buff, 1);
				if(numBytes>0)
				{
					int n=atoi(&buff);
                    if(n!=1)
                    	return false;
				}
				else{
				return false;
					}

				while (1)
			     {
					numBytes = client.Read(&buff, 1);
					if(numBytes>0)
					{
					sRetStr.append(1,buff);
					}
					else
					{
						break;
					}
				}


				CAddressHelper::SaveAccountDetails(sRetStr);

				return true;

}



} /* namespace NETCUT_CORE_FUNCTION */
