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
#include <stdlib.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "grapple_callback.h"
#include "grapple_callback_internal.h"
#include "grapple_structs.h"
#include "grapple_message_internal.h"

/*Callbacks are ways to process replies from the network asynchronously.
  A pull method involves users pulling the message from a queue and
  seeing what it says.
  A push method, like this, means that as soon as a message arrives
  it is handled immediately by a handler function.
  Each side has benefits and problems.
  Pulling messages means that you get the messages only when you expect
  them, you know the state of your application, and can predict how the
  message will be processed. On the other hand a message may wait for a short
  time in the queue before you get round to looking at it, so this is slower
  Pushing means that the message is handled immediately, no delay. The problem
  is that you have no idea what your program will be doing when the message
  comes in. You need to handle push messages very very carefully to ensure
  you do not have problems.
*/

//Find the callback for a specific type of message
grapple_callback_list *grapple_callback_get(grapple_callback_list *list,
					    grapple_messagetype type)
{
  grapple_callback_list *scan;

  scan=list;

  while (scan)
    {
      if (scan->type==type)
	//Found it
	return scan;

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  //No callback for this message
  return NULL;
}

//Add a new callback to the list. 
grapple_callback_list *grapple_callback_add(grapple_callback_list *list,
					    grapple_messagetype type,
					    grapple_callback callback,
					    void *context)
{
  grapple_callback_list *target;
  
  //If we already have this callback, replace the values with new ones.
  target=grapple_callback_get(list,type);

  if (target)
    {
      target->callback=callback;
      target->context=context;
      return list;
    }

  //A new callback
  target=(grapple_callback_list *)malloc(sizeof(grapple_callback_list));

  //Link it into the list
  if (list)
    {
      target->next=list;
      target->prev=list->prev;
      target->next->prev=target;
      target->prev->next=target;
    }
  else
    {
      list=target;
      target->next=target;
      target->prev=target;
    }

  target->callback=callback;
  target->context=context;
  target->type=type;
  
  return list;
}

//Remove a callback
grapple_callback_list *grapple_callback_remove(grapple_callback_list *list,
					       grapple_messagetype type)
{
  grapple_callback_list *target;

  //Find the callback  
  target=grapple_callback_get(list,type);

  if (!target)
    {
      //We dont have one anyway
      return list;
    }

  //Remove it from the list
  if (target->next==target)
    list=NULL;
  else if (list==target)
    list=list->next;
      
  target->next->prev=target->prev;
  target->prev->next=target->next;

  //Free the memory
  free(target);

  return list;
}

//Now we have a callback on the server
//Make up a message and then call the dispatcher with the message
int grapple_server_callback_generate(internal_server_data *server,
				     grapple_queue *item)
{
  grapple_callback_list *target;
  grapple_messagetype type;
  grapple_message *message;
  grapple_callbackevent *event;

  //We have no callbacks - shortcut abort
  if (!server->callbackanchor)
    {
      return 0;
    }

  //Find out what type of user message this is
  type=grapple_message_convert_to_usermessage_enum(item->messagetype);

  if (type==GRAPPLE_MSG_NONE)
    {
      //This kind of message cant have a callback, abort
      return 0;
    }


  grapple_thread_mutex_lock(server->callback_mutex,GRAPPLE_LOCKTYPE_SHARED);

  target=grapple_callback_get(server->callbackanchor,type);

  if (!target)
    {
      grapple_thread_mutex_unlock(server->callback_mutex);
      //No callback for this message
      return 0;
    }

  //We have a callback, create a callback event for the dispatcher
  event=(grapple_callbackevent *)malloc(sizeof(grapple_callbackevent));
  
  event->callback=target->callback;
  event->context=target->context;

  grapple_thread_mutex_unlock(server->callback_mutex);

  message=server_convert_message_for_user(item);
  event->message=message;

  //Only add messages to the dispatcher if it isnt finishing (obviously)
  if (server->dispatcher_count && server->thread && !server->threaddestroy)
    {
      grapple_thread_mutex_lock(server->event_queue_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);

      //Link the message into the dispatchers queue
      server->event_queue=
	grapple_callbackevent_link(server->event_queue,event);

      grapple_thread_mutex_unlock(server->event_queue_mutex);
      
      return 1;
    }

  //We couldnt link the message to the dispatcher, so we fail the return

  free(event);

  return 0;
}

//Now we have a callback on the client
//Make up a message and then call the dispatcher with the message
int grapple_client_callback_generate(internal_client_data *client,
				     grapple_queue *item)
{
  grapple_callback_list *target;
  grapple_messagetype type;
  grapple_message *message;
  grapple_callbackevent *event;

  //We have no callbacks - shortcut abort
  if (!client->callbackanchor)
    return 0;

  //Find out what type of user message this is
  type=grapple_message_convert_to_usermessage_enum(item->messagetype);

  if (type==GRAPPLE_MSG_NONE)
    {
      //This kind of message cant have a callback, abort
      return 0;
    }

  grapple_thread_mutex_lock(client->callback_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  target=grapple_callback_get(client->callbackanchor,type);

  if (!target)
    {
      grapple_thread_mutex_unlock(client->callback_mutex);
      //No callback for this message
      return 0;
    }

  //We have a callback, create a callback event for the dispatcher
  event=(grapple_callbackevent *)malloc(sizeof(grapple_callbackevent));
  
  event->callback=target->callback;
  event->context=target->context;

  grapple_thread_mutex_unlock(client->callback_mutex);

  message=client_convert_message_for_user(item);

  event->message=message;


  //Only add messages to the dispatcher if it isnt finishing (obviously)
  if (client->dispatcher_count && client->thread && !client->threaddestroy)
    {
      grapple_thread_mutex_lock(client->event_queue_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);

      //Link the message into the dispatchers queue
      client->event_queue=
	grapple_callbackevent_link(client->event_queue,event);

      grapple_thread_mutex_unlock(client->event_queue_mutex);
      
      return 1;
    }

  //We couldnt link the message to the dispatcher, so we fail the return

  free(event);

  return 0;
}
