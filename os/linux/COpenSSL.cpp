/*
 * COpenSSL.cpp
 *
 *  Created on: May 15, 2016
 *      Author: root
 */
#include "CBase64.h"
#include <COpenSSL.h>
#include <CNetcutTool.h>
#include <sstream>
#include <fstream>
#include <iostream>
using namespace std;
namespace NETCUT_CORE_FUNCTION {

COpenSSL::COpenSSL() {
	// TODO Auto-generated constructor stub
	m_padding = RSA_PKCS1_PADDING;
	m_sServerPubKey="-----BEGIN PUBLIC KEY-----\n"
			"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl0PsY15gZiL8XXr0f5zW\n"
			"s3zdrKkvWgqiO7nEnF3AzgULd9VzjqyfnpxIjSgPWdctpXb7alPd1W6K9WkQAGU7\n"
			"KeL2v47L1s7VhU30ovJeFZLVkz+eSdNzqbO1uMB3hn902Rmpx4DWnrOJMIEVzox/\n"
			"8Nhp2F+xVYr+2OY0MLEGuqADM0vUL9nS96Rx2joBhufxCmWkFy4ITANEc63smhN/\n"
			"N6Khncby7J2pAhGXPTb3AFXjNZpL0RxKjCCH2ahBbtQStZe3bRb6JNGNtxVYqmE7\n"
			"V5+y1RuSdldy+PXEwRC9q8ezB02vbrYtzoguv4yCR0mDjus5OhM0HoTsyZv/r1Nw\n"
			"15z0nlJhrUpEn7dpVkfBgECudfa0fGIxAZqlccXXhKA7kX3WNJo1vKpegLtRn96G\n"
			"MzBr/A5VG2oSd9C37i+gWUfOaG1Ed0m1CwwIOlmn95ISSNO13HkBRl/wi98B0/4q\n"
			"tlNOvCtDy35uLqA6MkxawJnxGKJWRbAKQgDkMpuqedmrw8tvbEg716WtgtCYInlW\n"
			"BvtXQtCeBI/LhsDwsyQsLTu+lncEAjnSGuEBeUUR29R7tlSPmnzF1fPqRnlSiMTu\n"
			"PnIDlpWXEja/E4TImA5k3pHWzFhDmZr/xt4l0imeRoD53hcHMEmk1u3Z8bIqTD+W\n"
			"E6LRvIyZ7T+WqNpJPMn56PcCAwEAAQ==\n"
			"-----END PUBLIC KEY-----\n";
}

COpenSSL::~COpenSSL() {
	// TODO Auto-generated destructor stub
}

RSA * COpenSSL::createRSA(unsigned char * key, bool p_bPublic) {
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		TRACE("Failed to create key BIO");
		return 0;
	}
	if (p_bPublic) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (rsa == NULL) {
		TRACE("Failed to create RSA");
	}

	return rsa;
}

int COpenSSL::public_encrypt(unsigned char * data, int data_len,
		unsigned char * key, unsigned char *encrypted) {
	RSA * rsa = createRSA(key, 1);
	if (rsa == 0)
		return -1;

	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, m_padding);
	return result;
}
int COpenSSL::private_decrypt(unsigned char * enc_data, int data_len,
		unsigned char * key, unsigned char *decrypted) {
	RSA * rsa = createRSA(key, 0);
	if (rsa == 0)
		return -1;

	int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa,
			m_padding);
	return result;
}

int COpenSSL::private_encrypt(unsigned char * data, int data_len,
		unsigned char * key, unsigned char *encrypted) {
	RSA * rsa = createRSA(key, 0);
	if (rsa == 0)
		return -1;

	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, m_padding);
	return result;
}
int COpenSSL::public_decrypt(unsigned char * enc_data, int data_len,
		unsigned char * key, unsigned char *decrypted) {
	RSA * rsa = createRSA(key, 1);
	if (rsa == 0)
		return -1;

	int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa,
			m_padding);
	return result;
}


string COpenSSL::aes_encode(const char *sourcestr, char *key)
{
    if (strcmp(key, "") == 0)
    {
    	return "";
    }

    int len = strlen(sourcestr);
    unsigned char iv[AES_BLOCK_SIZE+1] = "6543210987654321";  // 注意，iv绝对不能是const的，否则会段错误

    unsigned char * out = (unsigned char *)malloc(1024*1024);
    if (out == NULL) {
        fprintf(stderr, "No Memory!\n");
    }
    AES_KEY aes;
    if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
    {
        return NULL;
    }
    /* 计算补0后的长度 */
    int out_len = ((len - 1) / 16 + 1)* 16;
    char * sstr = (char *)malloc(sizeof(char) * out_len + 1);
    /* 补0 */
    memset(sstr, 0, out_len+1);
    strcpy(sstr, sourcestr);
    AES_cbc_encrypt((unsigned char*)sstr, out, out_len, &aes, (unsigned char*)iv, AES_ENCRYPT);
    /* 这里的长度一定要注意，不能用strlen来获取，加密后的字符串中可能会包含\0 */
    string out2 = base64_encode((unsigned char *)out, out_len);
    free(out);
    free(sstr);

    ofstream myfile;
    		myfile.open("aes.txt", ios::out);
    		myfile.write((char *) out2.c_str(), out2.size());
    		myfile.close();


    return out2;
}

string COpenSSL::aes_decode(const char *crypttext, char *key)
{
    if (strcmp(key, "") == 0)
    {
    	return "";
    }
    int out_len = 0;
    unsigned char iv[AES_BLOCK_SIZE+1] = "6543210987654321";

    string in = base64_decode(crypttext);
    out_len=in.size();
    char *out = (char *) malloc(sizeof(char) * out_len + 1);
    memset(out, 0, out_len + 1);
    AES_KEY aes;
    if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
    {
        return "";
    }

    AES_cbc_encrypt((unsigned char*)in.c_str(), (unsigned char*)out, out_len, &aes, (unsigned char*)iv, AES_DECRYPT);
    //free(in);
    string sRet=out;
    free(out);
    return sRet;
}


bool COpenSSL::testAES(std::string p_sKey, std::string p_sData2Encrypt,
		bool p_bEnc, std::string & p_sEncStr) {

	/*
	 * aes BLOCK HAVE TO BE 16 BIT BLOCK
	 * AES key has to be 16 CHAR
	 */

	std::string sBuffer, sOutBuffer;
	//std::string sKey="1234567812345678";
	unsigned char aes_key[16]; //128 bit
	memset(aes_key, 0, 16);

	int nKeyLen = p_sKey.size() <= 16 ? p_sKey.size() : 16;
	memcpy(aes_key, p_sKey.c_str(), nKeyLen);   //Get password inplace
	/* Buffers for Encryption and Decryption */

	unsigned char databuffer[16];
	memset(databuffer, 0, 16);
	unsigned char outbuffer[16];
	memset(outbuffer, 0, 16);

	/* AES-128 bit CBC Encryption */
	AES_KEY enc_key, dec_key;
	if (p_bEnc) {

		if (AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key) < 0) {
			return false;
		}
	} else {
		if (AES_set_decrypt_key(aes_key, sizeof(aes_key) * 8, &dec_key) < 0) {

			return false;
		}

	}

	int32_t nDataLen = 0;

	if (p_bEnc) {
		nDataLen = p_sData2Encrypt.size();
		sBuffer.append((char *) &nDataLen, sizeof(int32_t));
		sBuffer.append(p_sData2Encrypt);
		int nMod = sBuffer.size() % 16;
		if (nMod != 0) {
			sBuffer.append((char *) databuffer, 16 - nMod);

		}

	} else {
		sBuffer = base64_decode(p_sData2Encrypt);
		nDataLen = sBuffer.size();
		if (nDataLen % 16 != 0) {
			TRACE("Wrong Buffer,  Len mod 16 has to be 0\n");
			return false;
		}
	}

	int nDataIndex = 0;
	int nCopySize = 16;
	nDataLen = sBuffer.size();
	//AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits

	while (nDataIndex < nDataLen) {

		memcpy(databuffer, sBuffer.c_str() + nDataIndex, nCopySize);
		if (p_bEnc) {
			AES_ecb_encrypt(databuffer, outbuffer, &enc_key, AES_ENCRYPT);
		} else {
			AES_ecb_encrypt(databuffer, outbuffer, &dec_key, AES_DECRYPT);

		}
		nDataIndex += 16;
		sOutBuffer.append((char *) outbuffer, 16);
	}

	if (p_bEnc) {
		p_sEncStr = base64_encode((unsigned char *) sOutBuffer.c_str(),
				sOutBuffer.size());

		ofstream myfile;
		myfile.open("aes.txt", ios::out);
		myfile.write((char *) p_sEncStr.c_str(), p_sEncStr.size());
		myfile.close();

	} else {
		int32_t nTotalLen = 0;
		memcpy((char *) &nTotalLen, sOutBuffer.c_str(), sizeof(int32_t));

		p_sEncStr.append(sOutBuffer.c_str() + sizeof(int32_t), nTotalLen);
	}

	return true;

	/*

	 AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
	 AES_ecb_encrypt(enc_out, dec_out, &dec_key, AES_DECRYPT);


	 string s(dec_out,p_sData2Encrypt.size());

	 */

}

std::string COpenSSL::RsaDecodeServer(std::string p_sEncrypted) {

	/*unsigned char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
			"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl0PsY15gZiL8XXr0f5zW\n"
			"s3zdrKkvWgqiO7nEnF3AzgULd9VzjqyfnpxIjSgPWdctpXb7alPd1W6K9WkQAGU7\n"
			"KeL2v47L1s7VhU30ovJeFZLVkz+eSdNzqbO1uMB3hn902Rmpx4DWnrOJMIEVzox/\n"
			"8Nhp2F+xVYr+2OY0MLEGuqADM0vUL9nS96Rx2joBhufxCmWkFy4ITANEc63smhN/\n"
			"N6Khncby7J2pAhGXPTb3AFXjNZpL0RxKjCCH2ahBbtQStZe3bRb6JNGNtxVYqmE7\n"
			"V5+y1RuSdldy+PXEwRC9q8ezB02vbrYtzoguv4yCR0mDjus5OhM0HoTsyZv/r1Nw\n"
			"15z0nlJhrUpEn7dpVkfBgECudfa0fGIxAZqlccXXhKA7kX3WNJo1vKpegLtRn96G\n"
			"MzBr/A5VG2oSd9C37i+gWUfOaG1Ed0m1CwwIOlmn95ISSNO13HkBRl/wi98B0/4q\n"
			"tlNOvCtDy35uLqA6MkxawJnxGKJWRbAKQgDkMpuqedmrw8tvbEg716WtgtCYInlW\n"
			"BvtXQtCeBI/LhsDwsyQsLTu+lncEAjnSGuEBeUUR29R7tlSPmnzF1fPqRnlSiMTu\n"
			"PnIDlpWXEja/E4TImA5k3pHWzFhDmZr/xt4l0imeRoD53hcHMEmk1u3Z8bIqTD+W\n"
			"E6LRvIyZ7T+WqNpJPMn56PcCAwEAAQ==\n"
			"-----END PUBLIC KEY-----\n";

			*/

	string sQueryStr1=base64_decode(p_sEncrypted);

	unsigned char encrypted[4098] = { };
	unsigned char decrypted[4098] = { };

	int decrypted_length = public_decrypt((unsigned char *) sQueryStr1.c_str(),
			sQueryStr1.size(), (unsigned char *)m_sServerPubKey.c_str(), decrypted);

	if (decrypted_length == -1) {
		TRACE("Private Decrypt failed ");
	   return "";
	}
	/*TRACE("\nPrivate Decrypted Text =%s\n", decrypted);
	printf("Decrypted Length =%d\n", decrypted_length);
*/
	string s((char *)decrypted,decrypted_length);
	return s;
}

std::string COpenSSL::RsaEncodeServer(std::string p_sEncrypted) {

     	unsigned char encrypted[4098] = { };
		unsigned char decrypted[4098] = { };
	int encrypted_length = public_encrypt((unsigned char *) p_sEncrypted.c_str(),
			p_sEncrypted.size(), (unsigned char *)m_sServerPubKey.c_str(), encrypted);
	if (encrypted_length == -1) {
		TRACE("Public Encrypt failed ");
	    return "";
	}
//	printf("Encrypted length =%d\n", encrypted_length);

	std::string sQueryStr = base64_encode((unsigned char *) encrypted,
			encrypted_length);

	ofstream myfile;
		myfile.open("rsatest.txt", ios::out);
		myfile.write((char *) sQueryStr.c_str(), sQueryStr.size());
		myfile.close();

	return sQueryStr;
}

void COpenSSL::printLastError(char *msg) {
	char * err = (char *)malloc(130);
	;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	TRACE("%s ERROR: %s\n", msg, err);
	free(err);
}

} /* namespace NETCUT_CORE_FUNCTION */
