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

#include "grapple_lobbymessage.h"
#include "grapple_lobby_internal.h"

//Obtain a new message struct
grapple_lobbymessage *grapple_lobbymessage_aquire()
{
  return (grapple_lobbymessage *)calloc(1,sizeof(grapple_lobbymessage));
}

//Dispose of a message and all memory associated with it
int grapple_lobbymessage_dispose(grapple_lobbymessage *message)
{
  switch (message->type)
    {
    case GRAPPLE_LOBBYMSG_CHAT:
      if (message->CHAT.message)
	free(message->CHAT.message);
      break;
    case GRAPPLE_LOBBYMSG_ROOMCREATE:    
    case GRAPPLE_LOBBYMSG_ROOMDELETE:
      if (message->ROOM.name)
	free(message->ROOM.name);
      break;
    case GRAPPLE_LOBBYMSG_NEWGAME:
      if (message->GAME.name)
	free(message->GAME.name);
      if (message->GAME.description)
	free(message->GAME.description);
      break;
    case GRAPPLE_LOBBYMSG_USERMSG:
      if (message->USERMSG.data)
	free(message->USERMSG.data);
      break;
    case GRAPPLE_LOBBYMSG_NEWUSER:
      if (message->USER.name)
	free(message->USER.name);
      break;
    case GRAPPLE_LOBBYMSG_GAME_DESCRIPTION:
      if (message->GAME.description)
	free(message->GAME.description);
      break;
    case GRAPPLE_LOBBYMSG_USER_DISCONNECTED:
    case GRAPPLE_LOBBYMSG_ROOMLEAVE:
    case GRAPPLE_LOBBYMSG_ROOMENTER:
    case GRAPPLE_LOBBYMSG_DISCONNECTED:
    case GRAPPLE_LOBBYMSG_DELETEGAME:
    case GRAPPLE_LOBBYMSG_GAME_USERS:
    case GRAPPLE_LOBBYMSG_GAME_MAXUSERS:
    case GRAPPLE_LOBBYMSG_GAME_CLOSED:
    case GRAPPLE_LOBBYMSG_CONNECTION_REFUSED:
    case GRAPPLE_LOBBYMSG_USER_JOINEDGAME:
    case GRAPPLE_LOBBYMSG_USER_LEFTGAME:
      //Nothing to free
      break;
    }

  free(message);

  return 1;
}

//link a lobbymessage into a list of lobymessages
grapple_lobbymessage *grapple_lobbymessage_link(grapple_lobbymessage *list,
						grapple_lobbymessage *item)
{
  if (!list)
    {
      item->next=item;
      item->prev=item;
      return item;
    }

  item->next=list;
  item->prev=list->prev;

  item->next->prev=item;
  item->prev->next=item;

  return list;
}

//Unlink a lobbymessage from a list of lobbymessages
grapple_lobbymessage *grapple_lobbymessage_unlink(grapple_lobbymessage *list,
						  grapple_lobbymessage *item)
{
  if (list->next==list)
    {
      return NULL;
    }

  item->next->prev=item->prev;
  item->prev->next=item->next;

  if (item==list)
    list=item->next;

  return list;
}
