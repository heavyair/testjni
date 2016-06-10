/*
 * CNetcutTool.h
 *
 *  Created on: Dec 21, 2015
 *      Author: root
 */

#ifndef OS_CNETCUTTOOL_H_
#define OS_CNETCUTTOOL_H_
#include <stdarg.h>
#include <cstdio>
#include <string>
#include <list>

#include <string>
#include <sstream>

typedef unsigned int DWORD, *PDWORD, *LPDWORD;


unsigned long _helper_GetMiTime();
void msleep(unsigned long p_nmillisecond); //sleep mili seconds
long int _helper_GetTimeSeconds();
std::string  getMyPath();
std::list<int> getPids(const char* name);
void KillPrevious();


template <typename T>
std::string to_string(T value)
{
    std::ostringstream os ;
    os << value ;
    return os.str() ;
}

#define _DEBUG

#ifdef _DEBUG
bool _trace(char *format, ...);
#define TRACE _trace
#else
#define TRACE false
#endif


/** Returns true on success, or false if there was an error */
bool SetSocketBlockingEnabled(int fd, bool blocking);

#endif /* OS_CNETCUTTOOL_H_ */
