/*
    Grapple - A fully featured network layer with a simple interface
    Copyright (C) 2006 Michael Simms

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    Michael Simms
    michael@linuxgamepublishing.com
*/

#include "grapple_configure_substitute.h"

#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "tools.h"


//This is a replacement for usleep which is not in any way ANSI, it does
//the same job.
void microsleep(int usec)
{
#ifdef WIN32
  Sleep(usec / 1000);
#else
  fd_set fds;
  struct timeval tv;
  
  tv.tv_sec=0;
  tv.tv_usec=usec;
  
  FD_ZERO(&fds);

  //Select on no file descriptors, which means it will just wait, until that
  //time is up. Thus sleeping for a microsecond exact time.
  select(FD_SETSIZE,&fds,0,0,&tv);
#endif
  return;
}

void timemark(const char *str)
{
  struct timeval tv;

  gettimeofday(&tv,NULL);
  
  printf("%ld.%06ld %s",tv.tv_sec,tv.tv_usec,str);
}

#ifndef _MSC_VER
inline 
#endif
int grapple_thread_errno()
{
#ifdef HAVE_ERRNO_H
  return errno;
#else
#  warning No valid ERRNO system detected
  return 0;
#endif
}

#ifndef _MSC_VER
inline 
#endif
int grapple_socket_errno()
{
#ifdef WIN32
  return WSAGetLastError();
# else
# ifdef HAVE_ERRNO_H
  return errno;
#else
#  warning No valid ERRNO system detected
  return 0;
# endif
#endif
}


#ifndef HAVE_GETTIMEOFDAY
#define FACTOR 0x19db1ded53e8000

int gettimeofday(struct timeval *tp,void * tz)
{
  FILETIME f;
  ULARGE_INTEGER ifreq;
  LONGLONG res;
  GetSystemTimeAsFileTime(&f);
  ifreq.HighPart = f.dwHighDateTime;
  ifreq.LowPart = f.dwLowDateTime;

  res = ifreq.QuadPart - FACTOR;
  tp->tv_sec = (long)((LONGLONG)res/10000000);
  tp->tv_usec = (long)((LONGLONG)res% 10000000000); // Micro Seonds

  return 0;
}
#endif
