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

#ifndef GRAPPLE_CALLBACK_INTERNAL_H
#define GRAPPLE_CALLBACK_INTERNAL_H

#include "grapple_structs.h"

typedef struct _grapple_callbackevent
{
  grapple_callback callback;
  void *context;
  grapple_message *message;
  struct _grapple_callbackevent *next;
  struct _grapple_callbackevent *prev;
} grapple_callbackevent;


extern grapple_callbackevent *grapple_callbackevent_link(grapple_callbackevent *,
							 grapple_callbackevent *);

extern grapple_callbackevent *grapple_callbackevent_unlink(grapple_callbackevent *,
							   grapple_callbackevent *);

extern grapple_callback_list *grapple_callback_get(grapple_callback_list *,
						   grapple_messagetype);
extern grapple_callback_list *grapple_callback_add(grapple_callback_list *,
						   grapple_messagetype,
						   grapple_callback,
						   void *);
extern grapple_callback_list *grapple_callback_remove(grapple_callback_list *,
						      grapple_messagetype);

extern int grapple_client_callback_generate(internal_client_data *,
					    grapple_queue *);
extern int grapple_server_callback_generate(internal_server_data *,
					    grapple_queue *);

#endif
