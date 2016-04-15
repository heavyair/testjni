/*
 * CBase64.h
 *
 *  Created on: Apr 27, 2015
 *      Author: root
 */

#ifndef CBASE64_H_
#define CBASE64_H_

#include <string>

std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);



#endif /* CBASE64_H_ */
