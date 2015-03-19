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

#ifndef GRAPPLE_CONFIGURE_SUBSTITUTE_H
#define GRAPPLE_CONFIGURE_SUBSTITUTE_H

//This file is here for systems that dont have the ability to run the
//configure script. It defines the headers they need. The Makefile, for the
//moment, you will need to configure for yourself still

#ifdef WIN32

#define HAVE_WINDOWS_H
#define HAVE_WINSOCK2_H
#define HAVE_WS2TCPIP_H

#define HAVE_SYS_TYPES_H 1
#define HAVE_ERRNO_H 1
#ifndef _MSC_VER
#define HAVE_UNISTD_H 1
#endif
#define HAVE_SIGNAL_H 1

#ifndef _MSC_VER
#define HAVE_GETTIMEOFDAY 1
#endif
#ifndef _MSC_VER
#define HAVE_PTHREAD_H 1
#endif
#ifndef _MSC_VER
#define HAVE_SYS_TIME_H 1
#endif


#endif

#endif
