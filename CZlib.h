/*
 * CZlib.h
 *
 *  Created on: Mar 10, 2016
 *      Author: root
 */

#ifndef CZLIB_H_
#define CZLIB_H_

#include "zlib.h"
namespace NETCUT_CORE_FUNCTION {

#define ZLIBMAXCOMPRESSLEVEL 6

class CZlib {

public:
	CZlib();
	virtual ~CZlib();
	bool Compress(unsigned char * p_buf,unsigned long p_nBufSize);
	bool UnCompress(unsigned char * p_buf,unsigned long p_nBufSize);

	unsigned char * m_pResult;
	unsigned long m_nResultSize;

private:
	bool prepareBuffer(bool p_bCompress,unsigned long p_nSourceSize);
	void initBuffer();

};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* CZLIB_H_ */
