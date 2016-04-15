/*
 * CUpdater.cpp
 *
 *  Created on: Apr 27, 2015
 *      Author: root
 */

#include "CUpdater.h"
#include "CHTTPClient.h"
#include "CBase64.h"
#include "netheader.h"
#include "CAddressHelper.h"

CUpdater::CUpdater(string p_sName,string p_sVersion,string p_sID) {
	// TODO Auto-generated constructor stub
this->m_sName=p_sName;
this->m_sVersion=p_sVersion;
this->m_sID=p_sID;
m_bRequireUpdate=false;
}

CUpdater::~CUpdater() {
	// TODO Auto-generated destructor stub
}


bool CUpdater::UpdateWorker()
{


	char buf[1024];
	memset(buf,0,1024);
	sprintf(buf,"name=%s:version=%s:id=%s",this->m_sName.c_str(),m_sVersion.c_str(),this->m_sID.c_str());
	string QueryOption=buf;

	string sQueryStr=base64_encode((unsigned char *)QueryOption.c_str(),QueryOption.size());

	string m_sUpdateUrl="http://www.arcai.com/netCut/Update3.php?query="+sQueryStr;

	//TRACE("URL: %s \n",m_sUpdateUrl.c_str());

	string sRetStr="";


				CHTTPClient client;
				if(!client.OpenUrl(m_sUpdateUrl))
					{
					TRACE("Error: Can't open %s\n",m_sUpdateUrl.c_str());
					return false;
					}


				int numBytes;
				char buff;
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
				sQueryStr=base64_decode(sRetStr);
				std::vector<string> RetArray=::_helper_splitstring(sQueryStr,"\r\n");
				if(RetArray.size()!=4) return false;





				string sUpdateRequired=base64_decode(RetArray[0]);

				if("Upgrade"==sUpdateRequired)
					{
					 string sFile2Copy=base64_decode(RetArray[1]);
															std::vector<string> sDownloads=_helper_splitstring(sFile2Copy,"\r\n");

															for(int i=0;i<sDownloads.size();i++)
															{
																string sDowndLoad=sDownloads[i];
																_helper_removestring(sDowndLoad,"\r");
																_helper_removestring(sDowndLoad,"\n");
																int lastslash=sDowndLoad.find('=');
																string sUrl=sDowndLoad.substr(0,lastslash);
																int nIndex=lastslash+1;
																string sFileName=sDowndLoad.substr(nIndex,sDowndLoad.size()-nIndex);
																_helper_replacestring(sFileName,"{app}",CAddressHelper::getAppPath());
																//TRACE("Loading %s\n",sFileName.c_str());
																if(!this->SaveUrl2File(sUrl,sFileName))
																	{
																	TRACE("Unable to save update\n");
																	return false;
																	}
															}

															string sCommands2Run=base64_decode(RetArray[2]);
															_helper_replacestring(sCommands2Run,"{app}",CAddressHelper::getAppPath());

															std::vector<string> ssCmd2Run=_helper_splitstring(sCommands2Run,"\r\n");

																for(int i=0;i<ssCmd2Run.size();i++)
																{
																	string Cmd=ssCmd2Run[i];
																//	TRACE("running %s\n",Cmd.c_str());

																	system(Cmd.c_str());
																}

						m_bRequireUpdate=true;

						exit_cleanup();
						string rerun=CAddressHelper::getMyPath()+" "+CAddressHelper::m_sMyCmdLine+ " &";
						system(rerun.c_str());

					//	execve(CAddressHelper::getMyPath().c_str(), CAddressHelper::m_argv,NULL);
					//	exit_handler(SIGTERM);
						exit(0);
					//	StartNewProcess();
						return true;

					}

   			 if("Reg"==sUpdateRequired)
				{
				m_bRequireReg=true;
				}

   			return true;

}


bool CUpdater::SaveUrl2File(string p_sUrl,string p_sDstPath)
{
	                CHTTPClient client;
					if(!client.OpenUrl(p_sUrl)) return false;

					string sTempFile=p_sDstPath+".dat";
					ofstream myfile;
					myfile.open(sTempFile,ios::out | ios::binary);

					int numBytes;
					char buff;
					int nCount=0;
					while(1)
					{
						numBytes = client.Read(&buff, 1);
						if(numBytes>0)
						{
						myfile.write(&buff,1);
						nCount++;
						}
						else
						{
							break;
						}

					}

					myfile.close();
					if(nCount!=client.GetContentSize()) return false;
					unlink(p_sDstPath.c_str());
					rename(sTempFile.c_str(),p_sDstPath.c_str());

					chmod(p_sDstPath.c_str(), S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

					return true;
}
