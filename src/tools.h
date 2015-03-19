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

#ifndef TOOLS_H
#define TOOLS_H

#define S_MINUTE 60
#define S_HOUR 3600
#define S_DAY 86400
#define S_WEEK 604800
#define S_MONTH 2419200
#define S_YEAR 31536000

extern void microsleep(int);
extern void timemark(const char *);

#ifdef WIN32
extern int grapple_thread_errno(void);
extern int grapple_socket_errno(void);
#define GRAPPLE_THREAD_ERRNO_IS_EAGAIN (grapple_thread_errno()==EAGAIN)
#define GRAPPLE_SOCKET_ERRNO_IS_EINVAL (grapple_socket_errno()==WSAEINVAL)
#define GRAPPLE_SOCKET_ERRNO_IS_EAGAIN (grapple_socket_errno()==WSAEWOULDBLOCK)
#define GRAPPLE_SOCKET_ERRNO_IS_EMSGSIZE (grapple_socket_errno()==WSAEMSGSIZE)
#define GRAPPLE_SOCKET_ERRNO_IS_EINPROGRESS (grapple_socket_errno()==WSAEINPROGRESS||grapple_socket_errno()==WSAEWOULDBLOCK)
#else
extern inline int grapple_thread_errno(void);
extern inline int grapple_socket_errno(void);
#define GRAPPLE_THREAD_ERRNO_IS_EAGAIN (grapple_thread_errno()==EAGAIN)
#define GRAPPLE_SOCKET_ERRNO_IS_EINVAL (grapple_socket_errno()==EINVAL)
#define GRAPPLE_SOCKET_ERRNO_IS_EAGAIN (grapple_socket_errno()==EAGAIN)
#define GRAPPLE_SOCKET_ERRNO_IS_EMSGSIZE (grapple_socket_errno()==EMSGSIZE)
#define GRAPPLE_SOCKET_ERRNO_IS_EINPROGRESS (grapple_socket_errno()==EINPROGRESS)
#endif

#ifndef HAVE_GETTIMEOFDAY
extern int gettimeofday(struct timeval *tp,void * tz);
#endif

#endif
