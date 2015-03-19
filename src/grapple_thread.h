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

#ifndef GRAPPLE_THREAD_H
#define GRAPPLE_THREAD_H

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

typedef struct 
{
#ifdef HAVE_PTHREAD_H
  pthread_t thread;
#else
  HANDLE thread;
#endif
} grapple_thread;

typedef struct 
{
#ifdef HAVE_PTHREAD_H
  pthread_mutex_t mutex;
  pthread_mutex_t countmutex;
#else
  HANDLE mutex;
  HANDLE countmutex;
#endif
  int lockcount;
  int exlockcount;
} grapple_thread_mutex;

typedef enum
  {
    GRAPPLE_LOCKTYPE_EXCLUSIVE,
    GRAPPLE_LOCKTYPE_SHARED,
  } grapple_mutex_locktype;


#define g2rapple_thread_mutex_lock(a,b) debug_grapple_thread_mutex_lock(a,b,__FILE__,__LINE__)
#define g2rapple_thread_mutex_unlock(a) debug_grapple_thread_mutex_unlock(a,__FILE__,__LINE__)


extern grapple_thread *grapple_thread_create(
#ifdef HAVE_PTHREAD_H
					     void *(*function)(void*),
#else
					     LPTHREAD_START_ROUTINE function,
#endif
					     void *);
int grapple_thread_destroy(grapple_thread *);

extern grapple_thread_mutex *grapple_thread_mutex_init(void);
extern int grapple_thread_mutex_destroy(grapple_thread_mutex *);
extern int grapple_thread_mutex_lock(grapple_thread_mutex *,
				     grapple_mutex_locktype);
extern int grapple_thread_mutex_trylock(grapple_thread_mutex *,
					grapple_mutex_locktype);
extern int grapple_thread_mutex_unlock(grapple_thread_mutex *);


extern int debug_grapple_thread_mutex_lock(grapple_thread_mutex *,
					   grapple_mutex_locktype,
					   const char *,int);
extern int debug_grapple_thread_mutex_unlock(grapple_thread_mutex *,
					     const char *,int);

#endif
