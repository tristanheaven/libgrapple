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
#include "grapple_lobbygame.h"
#include "grapple_thread.h"
#include "tools.h"

//Create a basic internal game structure
grapple_lobbygame_internal *grapple_lobbygame_internal_create()
{
  grapple_lobbygame_internal *returnval;
  
  returnval=
    (grapple_lobbygame_internal *)calloc(1,sizeof(grapple_lobbygame_internal));
  
  returnval->inuse=grapple_thread_mutex_init();

  return returnval;
}

//Delete a lobbygame_internal and all associated memory
int grapple_lobbygame_internal_dispose(grapple_lobbygame_internal *target)
{
  if (target->session)
    free(target->session);
  if (target->address)
    free(target->address);
  if (target->users)
    free(target->users);
  if (target->description)
    free(target->description);

  grapple_thread_mutex_destroy(target->inuse);

  free(target);

  return 0;
}

//Link a lobbygame_internal into a linked list
grapple_lobbygame_internal *grapple_lobbygame_internal_link(grapple_lobbygame_internal *game,
							    grapple_lobbygame_internal *item)
{
  if (!game)
    {
      item->next=item;
      item->prev=item;
      return item;
    }

  item->next=game;
  item->prev=game->prev;

  item->next->prev=item;
  item->prev->next=item;

  return game;
}

//Remove a lobbygame_internal from a linked list
grapple_lobbygame_internal *grapple_lobbygame_internal_unlink(grapple_lobbygame_internal *game,
							      grapple_lobbygame_internal *item)
{
  if (game->next==game)
    return NULL;

  item->next->prev=item->prev;
  item->prev->next=item->next;

  if (item==game)
    game=item->next;

  return game;
}

static grapple_lobbygame_internal *grapple_lobbygame_internal_get(grapple_thread_mutex *games_mutex,
								  grapple_lobbygame_internal *list,
								  grapple_lobbygameid gameid,
								  grapple_mutex_locktype type)
{
  grapple_lobbygame_internal *scan;
  int finished=0,found;

  while (!finished)
    {
      grapple_thread_mutex_lock(games_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Loop through the clients
      scan=list;

      found=0;
      
      while (scan && !found)
	{
	  if (scan->id==gameid)
	    {
	      if (grapple_thread_mutex_trylock(scan->inuse,
					       type)==0)
		{
		  //Match and return it
		  grapple_thread_mutex_unlock(games_mutex);
		  return scan;
		}

		  //Mark it as found though so we dont exit
	      found=1;
	    }
      
	  scan=scan->next;
	  if (scan==list)
	    scan=NULL;
	}

      grapple_thread_mutex_unlock(games_mutex);

      if (!found)
	//It isnt here, return NULL
	return NULL;
      
      //It is here but in use, sleep a very small amount
      microsleep(1000);
    }

  //We never get here
  return NULL;
}

static grapple_lobbygame_internal *grapple_lobbygame_internal_get_byname(grapple_thread_mutex *games_mutex,
									 grapple_lobbygame_internal *list,
									 const char *name,
									 grapple_mutex_locktype type)
{
  grapple_lobbygame_internal *scan;
  int finished=0,found;
  grapple_lobbygameid gameid;

  while (!finished)
    {
      grapple_thread_mutex_lock(games_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Loop through the clients
      scan=list;

      found=0;
      
      while (scan && !found)
	{
	  grapple_thread_mutex_lock(scan->inuse,GRAPPLE_LOCKTYPE_SHARED);

	  //We have to be locked here to do a strcmp
	  if (scan->session && !strcmp(scan->session,name))
	    {
	      //If we only want shared, we have it
	      if (type==GRAPPLE_LOCKTYPE_SHARED)
		{
		  //Match and return it
		  grapple_thread_mutex_unlock(games_mutex);
		  return scan;
		}
	      gameid=scan->id;

	      grapple_thread_mutex_unlock(scan->inuse);
	      if (grapple_thread_mutex_lock(scan->inuse,type))
		{
		  //We have the right locktype now
		  grapple_thread_mutex_unlock(games_mutex);
		  return scan;
		}
	      //We couldnt get the right locktype but we now know the ID, hand
	      //off to the main finder
	      grapple_thread_mutex_unlock(games_mutex);
	      return grapple_lobbygame_internal_get(games_mutex,list,
						    gameid,type);
	    }

	  grapple_thread_mutex_unlock(scan->inuse);
	  
	  scan=scan->next;
	  if (scan==list)
	    scan=NULL;
	}

      grapple_thread_mutex_unlock(games_mutex);
    }

  return NULL;
}

grapple_lobbygame_internal *grapple_lobbyclient_game_internal_get(internal_lobbyclient_data *lobbyclientdata,
								  grapple_lobbygameid gameid,
								  grapple_mutex_locktype type)
{
  return grapple_lobbygame_internal_get(lobbyclientdata->games_mutex,
					lobbyclientdata->games,
					gameid,type);
}

grapple_lobbygame_internal *grapple_lobbyserver_game_internal_get(internal_lobby_data *lobbydata,
								  grapple_lobbygameid gameid,
								  grapple_mutex_locktype type)
{
  return grapple_lobbygame_internal_get(lobbydata->games_mutex,
					lobbydata->games,
					gameid,type);
}


void grapple_lobbygame_internal_release(grapple_lobbygame_internal *target)
{
  grapple_thread_mutex_unlock(target->inuse);
}

grapple_lobbygame_internal *grapple_lobbyclient_game_internal_get_byname(internal_lobbyclient_data *lobbyclientdata,
									 const char *name,
									 grapple_mutex_locktype type)
{
  return grapple_lobbygame_internal_get_byname(lobbyclientdata->games_mutex,
					       lobbyclientdata->games,
					       name,type);
}

