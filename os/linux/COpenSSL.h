/*
 * COpenSSL.h
 *
 *  Created on: May 15, 2016
 *      Author: root
 */

#ifndef OS_LINUX_COPENSSL_H_
#define OS_LINUX_COPENSSL_H_

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

namespace NETCUT_CORE_FUNCTION {

class COpenSSL {
public:
	COpenSSL();
	virtual ~COpenSSL();
	std::string RsaDecodeServer(std::string p_sEncrypted);
	std::string RsaEncodeServer(std::string p_sEncrypted);
	//void test();
	std::string aes_encode(const char *sourcestr, char *key = "");
	std::string aes_decode(const char *crypttext, char *key = "");
	bool testAES(std::string p_sKey,std::string p_sData2Encrypt,bool p_bEnc,std::string & p_sEncStr);


private:

	RSA * createRSA(unsigned char * key,bool p_bPublic);
	int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
	int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
	int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
	int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
	void printLastError(char *msg);

	int m_padding;
	std::string m_sServerPubKey;
};

} /* namespace NETCUT_CORE_FUNCTION */

#endif /* OS_LINUX_COPENSSL_H_ */
