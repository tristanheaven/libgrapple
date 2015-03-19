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

#ifndef GRAPPLE_LOBBYCLIENT_THREAD_H
#define GRAPPLE_LOBBYCLIENT_THREAD_H

#ifdef HAVE_PTHREAD_H
extern void *grapple_lobbyclient_serverthread_main(void *);
extern void *grapple_lobbyclient_clientthread_main(void *);
#else
extern DWORD WINAPI grapple_lobbyclient_serverthread_main(LPVOID);
extern DWORD WINAPI grapple_lobbyclient_clientthread_main(LPVOID);
#endif

#endif
