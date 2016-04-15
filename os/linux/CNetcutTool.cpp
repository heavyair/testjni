/*
 * CNetcutTool.cpp
 *
 *  Created on: Dec 21, 2015
 *      Author: root
 */

#include "CNetcutTool.h"
#include <sys/time.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>


#include <iostream>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>

#include <fcntl.h>


#ifdef _DEBUG
bool _trace(char *format, ...)
{
   char buffer[1000];

     va_list args;
     va_start (args, format);
     vsnprintf (buffer,256,format, args);
//     perror (buffer);

   std::clog << buffer << std::flush;
   va_end (args);

   return true;
}
#endif


void msleep(unsigned long p_nmillisecond) {
	if (p_nmillisecond > 1000) {
		int nSleep = p_nmillisecond / 1000;
		sleep(nSleep);
		p_nmillisecond -= nSleep * 1000;
	}
	usleep(p_nmillisecond * 1000);

}

unsigned long _helper_GetMiTime() {

	struct timeval start;
	unsigned long mtime, seconds, useconds;

	gettimeofday(&start, NULL);

	seconds = start.tv_sec;
	useconds = start.tv_usec;

	mtime = ((seconds) * 1000 + useconds / 1000.0) + 0.5;

	return mtime;
}

unsigned long _helper_GetTimeSeconds()
{

	struct timeval start;
	unsigned long mtime, seconds, useconds;

	gettimeofday(&start, NULL);

	seconds = start.tv_sec;

	return seconds;

}
void KillPrevious() {

	int nMypid = getpid();
	std::string sMyPath = getMyPath();
	std::list<int> pids = getPids(sMyPath.c_str());

	for (std::list<int>::iterator it = pids.begin(); it != pids.end(); ++it) {
		int n = *it;

		if (n != nMypid && n > 0) {
			TRACE("Killing Pid %d\n",n);
			kill(n, SIGTERM);
			msleep(50);
			kill(n, SIGKILL);
			}
	}

}
std::list<int> getPids(const char* name) {
	std::list<int> pids;
	DIR* dir;
	struct dirent* ent;
	char* endptr;

	std::string sPathWithSpace = name;
	sPathWithSpace += " ";

	if (!(dir = opendir("/proc"))) {
		perror("can't open /proc");
		return pids;
	}

	while ((ent = readdir(dir)) != NULL) {
		/* if endptr is not a null character, the directory is not
		 * entirely numeric, so ignore it */
		long lpid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != '\0') {
			continue;
		}
		char arg1[20] = { 0 };
		char exepath[4097] = { 0 };
		sprintf(arg1, "/proc/%ld/exe", lpid);
		ssize_t len = readlink(arg1, exepath, 1024);
		if (len == -1)
			continue;
		exepath[len] = '\0';
		std::string spath = std::string(exepath);
		//	TRACE("%d exe path %s\n",lpid,exepath);
		if (spath == name) {
			pids.push_back(lpid);

		}
		if (spath.find(sPathWithSpace) != std::string::npos) {
			pids.push_back(lpid);
		}

	}

	closedir(dir);
	return pids;

}

std::string  getMyPath() {



	char arg1[20] = { 0 };
	char exepath[4097] = { 0 };
	std::string sPath;
	sprintf(arg1, "/proc/%d/exe", getpid());
	readlink(arg1, exepath, 1024);

	std::string fullpath = std::string(exepath);
	size_t found = fullpath.find_last_of(' ');
	if (std::string::npos != found)
		sPath= fullpath.substr(0, found + 1);
	else
		sPath = fullpath;

	return sPath;

}

bool SetSocketBlockingEnabled(int fd, bool blocking)
{
   if (fd < 0) return false;

#ifdef WIN32
   unsigned long mode = blocking ? 0 : 1;
   return (ioctlsocket(fd, FIONBIO, &mode) == 0) ? true : false;
#else

   int flags = fcntl(fd, F_GETFL, 0);
   if (flags < 0) return false;
   flags = blocking ? (flags&~O_NONBLOCK) : (flags|O_NONBLOCK);
   return (fcntl(fd, F_SETFL, flags) == 0) ? true : false;
#endif
}


