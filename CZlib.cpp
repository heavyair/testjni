/*
 * CZlib.cpp
 *
 *  Created on: Mar 10, 2016
 *      Author: root
 */

#include <CZlib.h>
#include <stdlib.h>
#include <string.h>
namespace NETCUT_CORE_FUNCTION {

CZlib::CZlib() {
	// TODO Auto-generated constructor stub
	m_pResult=NULL;
}

CZlib::~CZlib() {
	// TODO Auto-generated destructor stub
	initBuffer();

}

void CZlib::initBuffer()
{

	if(m_pResult!=NULL)
			delete m_pResult;

		m_pResult=NULL;
		m_nResultSize=0;

}


bool CZlib::UnCompress(unsigned char * p_buf,unsigned long p_nBufSize)
{
	unsigned long nTempSize=p_nBufSize;


TRYAGAIN:

	if(!prepareBuffer(false,nTempSize)) return false;

	 int err;
	 err = uncompress(m_pResult, &m_nResultSize, p_buf, p_nBufSize);
	 switch(err)
	 {
	 case Z_OK:
	 {
		 return true;
		 break;
	 }
	 case Z_BUF_ERROR:
	 {
		 if(nTempSize/p_nBufSize>1024) return false;

		 nTempSize*=5;
		 goto TRYAGAIN;
		 break;
	 }
	 default:
	 {
		 return false;
	 }
	 }

}


bool CZlib::Compress(unsigned char * p_buf,unsigned long p_nBufSize)
{

	if(!prepareBuffer(true,p_nBufSize)) return false;

	  int err;
	  err = compress(m_pResult, &m_nResultSize, (const Bytef*)p_buf, p_nBufSize);
     if(Z_OK!=err)
    	 {
    	 return false;
    	 }
     return true;
}

bool CZlib::prepareBuffer(bool p_bCompress,unsigned long p_nSourceSize)
{
/*
 *
 * The ZLIB does not have header that store source size, so , uncompress need to test
 * eg: Uncompressed size should be 5:1 , let's make it 6*soure size + 32
 *
 */	  initBuffer();
      if(p_bCompress)
      {
    	  unsigned int nSize=compressBound(p_nSourceSize);
    	  m_nResultSize=((nSize/32)+4)*32*2;

    	  m_pResult=(unsigned char *)malloc(m_nResultSize);
    	  if(m_pResult==NULL) return false;

    	  memset(m_pResult,0,m_nResultSize);
    	 // memcpy(m_pResult,&p_nSourceSize,sizeof(p_nSourceSize));
    	  return true;
      }
      else
      {
    	  m_nResultSize=(((p_nSourceSize*ZLIBMAXCOMPRESSLEVEL)/32)+4)*32*2;
    	  m_pResult=(unsigned char *)malloc(m_nResultSize);
    	  if(m_pResult==NULL) return false;
          memset(m_pResult,0,m_nResultSize);
          return true;
      }
}

} /* namespace NETCUT_CORE_FUNCTION */
