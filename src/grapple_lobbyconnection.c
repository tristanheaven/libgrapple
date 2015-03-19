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
#include <string.h>

#include "grapple_lobby_internal.h"
#include "grapple_lobbyconnection.h"

//Create a lobbyconnection
grapple_lobbyconnection *grapple_lobbyconnection_create()
{
  grapple_lobbyconnection *returnval;
  
  returnval=
    (grapple_lobbyconnection *)calloc(1,sizeof(grapple_lobbyconnection));
  
  return returnval;
}

//Delete a lobbyconnection and all associated memory
int grapple_lobbyconnection_dispose(grapple_lobbyconnection *target)
{
  if (target->name)
    free(target->name);
  free(target);

  return 0;
}

//Link a lobbyconnection into a linked list
grapple_lobbyconnection *grapple_lobbyconnection_link(grapple_lobbyconnection *connection,
						      grapple_lobbyconnection *item)
{
  if (!connection)
    {
      item->next=item;
      item->prev=item;
      return item;
    }

  item->next=connection;
  item->prev=connection->prev;

  item->next->prev=item;
  item->prev->next=item;

  return connection;
}

//Remove a lobbyconnection from a linked list
grapple_lobbyconnection *grapple_lobbyconnection_unlink(grapple_lobbyconnection *connection,
							grapple_lobbyconnection *item)
{
  if (connection->next==connection)
    {
      return NULL;
    }

  item->next->prev=item->prev;
  item->prev->next=item->next;

  if (item==connection)
    connection=item->next;

  return connection;
}

//Locate the connection details of a user by their name
grapple_lobbyconnection *grapple_lobbyconnection_locate_by_name(grapple_lobbyconnection *list,
								const char *name)
{
  grapple_lobbyconnection *scan;
  
  scan=list;

  while (scan)
    {
      if (scan->name && !strcmp(scan->name,name))
	//match
	return scan;

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  return NULL;
}

//Locate someones connection details by their ID
grapple_lobbyconnection *grapple_lobbyconnection_locate_by_id(grapple_lobbyconnection *list,
							      grapple_user id)
{
  grapple_lobbyconnection *scan;
  
  scan=list;

  while (scan)
    {
      if (scan->id==id)
	//Match
	return scan;

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  return NULL;
}
