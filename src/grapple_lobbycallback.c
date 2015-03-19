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

#include "grapple_lobby_internal.h"
#include "grapple_lobbycallback.h"

//Find the callback for a specific type of message
static grapple_lobbycallback_internal *grapple_lobbycallback_get(grapple_lobbycallback_internal *list,
								 grapple_lobbymessagetype type)
{
  grapple_lobbycallback_internal *scan;

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
grapple_lobbycallback_internal *grapple_lobbycallback_add(grapple_lobbycallback_internal *list,
							  grapple_lobbymessagetype type,
							  grapple_lobbycallback callback,
							  void *context)
{
  grapple_lobbycallback_internal *target;

  //If we already have this callback, replace the values with new ones.
  target=grapple_lobbycallback_get(list,type);

  if (target)
    {
      target->callback=callback;
      target->context=context;
      return list;
    }

  //A new callback
  target=(grapple_lobbycallback_internal *)malloc(sizeof(grapple_lobbycallback_internal));
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

//Process a callback
int grapple_lobby_callback_process(internal_lobby_data *server,
				   grapple_lobbymessage *message)
{
  grapple_lobbycallback_internal *target;
  grapple_lobbycallback callback;
  void *context;

  //If we already have this callback, replace the values with new ones.

  grapple_thread_mutex_lock(server->callback_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  target=grapple_lobbycallback_get(server->callbacks,message->type);

  if (!target)
    {
      grapple_thread_mutex_unlock(server->callback_mutex);

      return 0;
    }

  callback=target->callback;
  context=target->context;

  grapple_thread_mutex_unlock(server->callback_mutex);

  (*callback)(message,context);

  return 1;
}

//Process a callback
int grapple_lobbyclient_callback_process(internal_lobbyclient_data *client,
					 grapple_lobbymessage *message)
{
  grapple_lobbycallback_internal *target;
  grapple_lobbycallback callback;
  void *context;

  //If we already have this callback, replace the values with new ones.

  grapple_thread_mutex_lock(client->callback_mutex,GRAPPLE_LOCKTYPE_SHARED);

  target=grapple_lobbycallback_get(client->callbacks,message->type);

  if (!target)
    {
      grapple_thread_mutex_unlock(client->callback_mutex);

      return 0;
    }

  callback=target->callback;
  context=target->context;

  grapple_thread_mutex_unlock(client->callback_mutex);

  (*callback)(message,context);

  return 1;
}

//Remove a callback
grapple_lobbycallback_internal *grapple_lobbycallback_remove(grapple_lobbycallback_internal *list,
							     grapple_lobbymessagetype type)
{
  grapple_lobbycallback_internal *target;

  //Find the callback  
  target=grapple_lobbycallback_get(list,type);

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

