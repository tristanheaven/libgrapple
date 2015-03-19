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

#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "tools.h"

#include "grapple_callback_internal.h"
#include "grapple_callback_dispatcher.h"

/*The callback dispatcher needs a little explaining.
  Messages going to the program can go either as a message to be pulled off
  of a queue, or they can be processed via a callback. A callback is a
  function that runs as soon as the message is obtained.
  Initially the callback ran in the network thread, but a problem arose where
  a callback could take too much time and interfere with network processing.
  So, a separate thread for callback processing was created. This thread
  takes messages and performs callback functions. If the callback functions
  are taking too long, this is then a problem for the end user, not
  grapple, as we are now running them as fast as we can while not
  interfering with the network. Network should never be affected by long
  callbacks.
  An attempt was made to create a new thread for each callback, but that
  proved unworkable as too many threads were created and the system just
  couldnt handle it.
*/

//A callback event is a callback waiting to be handled by the dispatcher.
//The callback system creates them and the dispatcher picks them off the
//list. This function links an event into a list
grapple_callbackevent *grapple_callbackevent_link(grapple_callbackevent *queue,
						  grapple_callbackevent *item)
{
  if (!queue)
    {
      item->next=item;
      item->prev=item;
      return item;
    }

  item->next=queue;
  item->prev=queue->prev;

  item->next->prev=item;
  item->prev->next=item;

  return queue;
}

//Remove a callback event from a list
grapple_callbackevent *grapple_callbackevent_unlink(grapple_callbackevent *queue,
						    grapple_callbackevent *item)
{
  if (queue->next==queue)
    {
      if (queue!=item)
	return queue;

      return NULL;
    }
  
  item->prev->next=item->next;
  item->next->prev=item->prev;

  if (item==queue)
    queue=item->next;

  return queue;
}



//Actually run a callback. As you can see, the user provided function is
//run here, it takes an unknown time to complete
static void grapple_event_dispatch(grapple_callbackevent *event)
{
  (*event->callback)(event->message,event->context);

  return;
}

//The main function for the dispatcher thread.
#ifdef HAVE_PTHREAD_H
static void *grapple_callback_dispatcher_main(void *data)
#else
static DWORD WINAPI grapple_callback_dispatcher_main(LPVOID data)
#endif
{
  grapple_callback_dispatcher *thread;
  grapple_callbackevent *target;

  thread=(grapple_callback_dispatcher *)data;

  if (thread->server)
    {
      //Loop until told to stop
      while (!thread->finished)
	{
	  //We can do this while test safely here, as we are only testing an 
	  //atomic value, and we access the data only after checking it again 
	  //INSIDE the mutex
	  while (!thread->server->event_queue && !thread->finished)
	    {
	      //Nothing to do, so sleep a little till there is something to do
	      microsleep(1000);
	    }
	  
	  while (!thread->finished && thread->server->event_queue)
	    {
	      target=NULL;
	      
	      //Now we have the possibility of data, do the more expensive
	      //lock and test
	      grapple_thread_mutex_lock(thread->server->event_queue_mutex,
					GRAPPLE_LOCKTYPE_EXCLUSIVE);
	      if (thread->server->event_queue)
		{
		  //Remove the event from the queue. We do this so that we can
		  //unlock the queue before running the unknown length user
		  //function. If we ran that in here, we would do so leaving the
		  //thread locked, which would then block the network thread,
		  //making this thread completely pointless
		  target=thread->server->event_queue;
		  thread->server->event_queue=
		    grapple_callbackevent_unlink(thread->server->event_queue,
						 thread->server->event_queue);
		}
	      grapple_thread_mutex_unlock(thread->server->event_queue_mutex);

	      //The mutex is unlocked now, so we can run the user function without
	      //blocking other threads
	      
	      if (target)
		{
		  grapple_event_dispatch(target);
		  free(target);
		}
	    }
	}
    }
  else
    {
      //Loop until told to stop
      while (!thread->finished)
	{
	  //We can do this while test safely here, as we are only testing an 
	  //atomic value, and we access the data only after checking it again 
	  //INSIDE the mutex
	  while (!thread->client->event_queue && !thread->finished)
	    {
	      //Nothing to do, so sleep a little till there is something to do
	      microsleep(1000);
	    }
	  
	  while (!thread->finished && thread->client->event_queue)
	    {
	      target=NULL;
	      
	      //Now we have the possibility of data, do the more expensive
	      //lock and test
	      grapple_thread_mutex_lock(thread->client->event_queue_mutex,
					GRAPPLE_LOCKTYPE_EXCLUSIVE);
	      if (thread->client->event_queue)
		{
		  //Remove the event from the queue. We do this so that we can
		  //unlock the queue before running the unknown length user
		  //function. If we ran that in here, we would do so leaving the
		  //thread locked, which would then block the network thread,
		  //making this thread completely pointless
		  target=thread->client->event_queue;
		  thread->client->event_queue=
		    grapple_callbackevent_unlink(thread->client->event_queue,
						 thread->client->event_queue);
		}
	      grapple_thread_mutex_unlock(thread->client->event_queue_mutex);
	      
	      //The mutex is unlocked now, so we can run the user function without
	      //blocking other threads
	      
	      if (target)
		{
		  grapple_event_dispatch(target);
		  free(target);
		}
	    }
	}
    }

  //Now the thread has finished, try and dispatch all remaining messages
  if (thread->server)
    {
      while (thread->server->event_queue)
	{
	  target=NULL;
	  grapple_thread_mutex_lock(thread->server->event_queue_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  if (thread->server->event_queue)
	    {
	      //Remove the event from the queue. We do this so that we can
	      //unlock the queue before running the unknown length user
	      //function. If we ran that in here, we would do so leaving the
	      //thread locked, which would then block the network thread,
	      //making this thread completely pointless
	      target=thread->server->event_queue;
	      thread->server->event_queue=
		grapple_callbackevent_unlink(thread->server->event_queue,
					     thread->server->event_queue);
	    }
	  grapple_thread_mutex_unlock(thread->server->event_queue_mutex);
	  
	  if (target)
	    {
	      grapple_event_dispatch(target);
	      free(target);
	    }
	}
    }
  else
    {
      while (thread->client->event_queue)
	{
	  target=NULL;
	  grapple_thread_mutex_lock(thread->client->event_queue_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  if (thread->client->event_queue)
	    {
	      //Remove the event from the queue. We do this so that we can
	      //unlock the queue before running the unknown length user
	      //function. If we ran that in here, we would do so leaving the
	      //thread locked, which would then block the network thread,
	      //making this thread completely pointless
	      target=thread->client->event_queue;
	      thread->client->event_queue=
		grapple_callbackevent_unlink(thread->client->event_queue,
					     thread->client->event_queue);
	    }
	  grapple_thread_mutex_unlock(thread->client->event_queue_mutex);
	  
	  if (target)
	    {
	      grapple_event_dispatch(target);
	      free(target);
	    }
	}
    }
  
  //When its done, set the finished value to 2
  thread->finished=2;

  //now wait for the parent to set it to 3, which means the parent knows we
  //are done
  while (thread->finished==2)
    microsleep(10000);

  //Finally free the thread memory

  grapple_thread_destroy(thread->thread);

  free(thread);
  
  //we're done

#ifdef HAVE_PTHREAD_H
  return NULL;
#else
  return 0;
#endif
}

//This function creates the dispatcher thread
grapple_callback_dispatcher *grapple_callback_dispatcher_create(internal_server_data *server,internal_client_data *client)
{
  grapple_callback_dispatcher *returnval;
  int createval;

  returnval=
    (grapple_callback_dispatcher *)calloc(1,sizeof(grapple_callback_dispatcher));

  if (server)
    returnval->server=server;
  else
    returnval->client=client;

  createval=-1;

  returnval->thread=grapple_thread_create(grapple_callback_dispatcher_main,
					  (void *)returnval);
  if (!returnval->thread)
    {
      free(returnval);
      return NULL;
    }

  return returnval;
}
