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
#include <string.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include "grapple_lobby.h"
#include "grapple_lobby_internal.h"
#include "grapple_defines.h"
#include "grapple_error.h"
#include "grapple_server.h"
#include "grapple_thread.h"
#include "grapple_lobbyconnection.h"
#include "grapple_lobbycallback.h"
#include "grapple_lobbyerror.h"
#include "grapple_lobbymessage.h"
#include "grapple_lobbygame.h"
#include "tools.h"

/**************************************************************************
 ** The functions in this file are generally those that are accessible   **
 ** to the end user. Obvious exceptions are those that are static which  **
 ** are just internal utilities.                                         **
 ** Care should be taken to not change the parameters of outward facing  **
 ** functions unless absolutely required                                 **
 **************************************************************************/

//This is a static variable which keeps track of the list of all lobbys
//run by this program. The lobbys are kept in a linked list. This variable
//is global to this file only.
static internal_lobby_data *grapple_lobby_head=NULL;

//And this is the mutex to make this threadsafe
static grapple_thread_mutex *lobby_mutex=NULL;

//Link a lobby to the list
static int internal_lobby_link(internal_lobby_data *data)
{
  grapple_thread_mutex_lock(lobby_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  if (!grapple_lobby_head)
    {
      grapple_lobby_head=data;
      data->next=data;
      data->prev=data;
      grapple_thread_mutex_unlock(lobby_mutex);
      return 1;
    }

  data->next=grapple_lobby_head;
  data->prev=grapple_lobby_head->prev;
  data->next->prev=data;
  data->prev->next=data;

  grapple_lobby_head=data;
  
  grapple_thread_mutex_unlock(lobby_mutex);

  return 1;
}

//Remove a lobby from the linked list
static int internal_lobby_unlink(internal_lobby_data *data)
{
  grapple_thread_mutex_lock(lobby_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  if (data->next==data)
    {
      grapple_lobby_head=NULL;
      grapple_thread_mutex_unlock(lobby_mutex);
      return 1;
    }

  data->next->prev=data->prev;
  data->prev->next=data->next;

  if (data==grapple_lobby_head)
    grapple_lobby_head=data->next;

  grapple_thread_mutex_unlock(lobby_mutex);

  data->next=NULL;
  data->prev=NULL;

  return 1;
}

//Find the lobby from the ID number passed by the user
static internal_lobby_data *internal_lobby_get(grapple_lobby num,
					       grapple_mutex_locktype type)
{
  internal_lobby_data *scan;
  int finished=0,found;

  while (!finished)
    {
      //By default if passed 0, then the oldest lobby is returned
      if (!num)
	{
	  grapple_thread_mutex_lock(lobby_mutex,GRAPPLE_LOCKTYPE_SHARED);

	  if (!grapple_lobby_head)
	    {
	      grapple_thread_mutex_unlock(lobby_mutex);
	      
	      return NULL;
	    }

	  if (grapple_thread_mutex_trylock(grapple_lobby_head->inuse,
					   type)==0)
	    {
	      grapple_thread_mutex_unlock(lobby_mutex);
	      return grapple_lobby_head;
	    }
	  grapple_thread_mutex_unlock(lobby_mutex);
	}
      else
	{
	  grapple_thread_mutex_lock(lobby_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);

	  //Loop through the lobbys
	  scan=grapple_lobby_head;

	  found=0;

	  while (scan && !found)
	    {
	      if (scan->lobbynum==num)
		{
		  if (grapple_thread_mutex_trylock(scan->inuse,
						   type)==0)
		    {
		      //Match and return it
		      grapple_thread_mutex_unlock(lobby_mutex);
		      return scan;
		    }
		  //It is in use, we cant use it yet

		  //Mark it as found though so we dont exit
		  found=1;
		}
      
	      scan=scan->next;
	      if (scan==grapple_lobby_head)
		scan=NULL;
	    }

	  grapple_thread_mutex_unlock(lobby_mutex);

	  if (!found)
	    //It isnt here, return NULL
	    return NULL;

	  //It is here but in use, sleep a very small amount
	  microsleep(1000);
	}
    }

  //We never get here
  return NULL;
}

static void internal_lobby_release(internal_lobby_data *target)
{
  //We dont need to mutex this, we definitely HAVE it, and we are just
  //releasing it, and it wont be referenced again - it cant be deleted like
  //this

  grapple_thread_mutex_unlock(target->inuse);
}

static int init_lobby_mutex(void)
{
  static int done=0;

  if (done==1)
    return 1;
  done=1;

  lobby_mutex=grapple_thread_mutex_init();

  return 1;
}

//Create a new lobby
static internal_lobby_data *lobby_create(void)
{
  static int nextval=1;
  internal_lobby_data *data;
 
  //Create the structure
  data=(internal_lobby_data *)calloc(1,sizeof(internal_lobby_data));

  //Assign it a default ID
  data->lobbynum=nextval++;

  //Set up the mutexes
  data->userlist_mutex=grapple_thread_mutex_init();
  data->message_mutex=grapple_thread_mutex_init();
  data->games_mutex=grapple_thread_mutex_init();
  data->callback_mutex=grapple_thread_mutex_init();
  data->inuse=grapple_thread_mutex_init();

  return data;
}


//User function for initialising the lobby
grapple_lobby grapple_lobby_init(const char *name,const char *version)
{
  internal_lobby_data *data;
  grapple_lobby returnval;

  init_lobby_mutex();

  //Create the internal data
  data=lobby_create();

  data->server=grapple_server_init(name,version);

  returnval=data->lobbynum;

  //Link it into the array of lobbies
  internal_lobby_link(data);

  //Return the client ID - the end user only gets an integer, called a
  //'grapple_lobby'

  return returnval;
}

//Set the port number to connect to
int grapple_lobby_port_set(grapple_lobby lobby,int port)
{
  internal_lobby_data *lobbydata;
  int returnval;

  //Get the lobby data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  //Set this in the grapple data
  returnval=grapple_server_port_set(lobbydata->server,port);

  internal_lobby_release(lobbydata);
  
  return returnval;
}

//Set the IP address to bind to. This is an optional, if not set, then all
//local addresses are bound to
int grapple_lobby_ip_set(grapple_lobby lobby,const char *ip)
{
  internal_lobby_data *lobbydata;
  int returnval;

  //Get the lobby data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_server_ip_set(lobbydata->server,ip);

  internal_lobby_release(lobbydata);

  return returnval;
}

//Set the password needed to connect to the lobby

int grapple_lobby_password_set(grapple_lobby lobby,const char *password)
{
  internal_lobby_data *lobbydata;
  int returnval;

  //Get the lobby data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }
  
  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  //Set this in the grapple data
  returnval=grapple_server_password_set(lobbydata->server,password);

  internal_lobby_release(lobbydata);

  return returnval;
}

int grapple_lobby_passwordhandler_set(grapple_lobby lobby,
				      grapple_password_callback callback,
				      void *context)
{
  internal_lobby_data *lobbydata;
  int returnval;

  //Get the lobby data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  //Set this in the grapple data
  returnval=grapple_server_passwordhandler_set(lobbydata->server,
					       callback,context);

  internal_lobby_release(lobbydata);

  return returnval;
}


int grapple_lobby_connectionhandler_set(grapple_lobby lobby,
					grapple_connection_callback callback,
					void *context)
{
  internal_lobby_data *lobbydata;
  int returnval;

  //Get the lobby data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  //Set this in the grapple data
  returnval=grapple_server_connectionhandler_set(lobbydata->server,
						 callback,context);

  internal_lobby_release(lobbydata);
  
  return returnval;
}

int grapple_lobby_protectionkeypolicy_set(grapple_lobby lobby,
					  grapple_protectionkeypolicy policy)

{
  internal_lobby_data *lobbydata;
  int returnval;

  //Get the lobby data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  //Set this in the grapple data
  returnval=grapple_server_protectionkeypolicy_set(lobbydata->server,
						   policy);

  internal_lobby_release(lobbydata);

  return returnval;
}

int grapple_lobby_encryption_enable(grapple_lobby lobby,
				    const char *private_key,
				    const char *private_key_password,
				    const char *public_key,
				    const char *cert_auth)
{
  internal_lobby_data *lobbydata;
  int returnval;

  //Get the lobby data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  //Set this in the grapple data
  returnval=grapple_server_encryption_enable(lobbydata->server,
					     private_key,
					     private_key_password,
					     public_key,
					     cert_auth);

  internal_lobby_release(lobbydata);

  return returnval;
}

//Check if a room is empty, return 1 if it is
static int grapple_lobby_room_empty(internal_lobby_data *server,
				    grapple_user roomid)
{
  int returnval=0;
  grapple_user *userlist;
  grapple_lobbygame_internal *scan;
  int count;
  
  userlist=grapple_server_groupusers_get(server->server,roomid);
					 

  if (!userlist || !userlist[0])
    if (roomid!=server->mainroom)
      {
	//If the room is now empty, and this ISNT the main room, delete
	//the group (room)

	//also need to check if there are any games running in this room
	grapple_thread_mutex_lock(server->games_mutex,
				  GRAPPLE_LOCKTYPE_SHARED);

	scan=server->games;
	count=0;
	
	while (scan && !count)
	  {
	    if (scan->room==roomid)
	      count=1;
	    scan=scan->next;
	    if (scan==server->games)
	      scan=NULL;
	  }

	grapple_thread_mutex_unlock(server->games_mutex);

	if (!count)
	  returnval=1;
      }

  if (userlist)
    free(userlist);

  return returnval;
}

int grapple_lobby_maxusers_set(grapple_lobby lobby,int maxusers)
{
  internal_lobby_data *lobbydata;
  
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  grapple_server_maxusers_set(lobbydata->server,maxusers);

  internal_lobby_release(lobbydata);

  return GRAPPLE_OK;
}

int grapple_lobby_maxusers_get(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  int returnval;
  
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_server_maxusers_get(lobbydata->server);

  internal_lobby_release(lobbydata);

  return returnval;
}


int grapple_lobby_currentusers_get(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  int returnval;
  
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_server_currentusers_get(lobbydata->server);
  
  internal_lobby_release(lobbydata);

  return returnval;
}

int grapple_lobby_roomlimit_set(grapple_lobby lobby,int max)
{
  internal_lobby_data *lobbydata;
  int returnval;
  
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_server_maxgroups_set(lobbydata->server,max);

  internal_lobby_release(lobbydata);
 
  return returnval;
}

int grapple_lobby_roomlimit_get(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  int returnval;
  
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_server_maxgroups_get(lobbydata->server);

  internal_lobby_release(lobbydata);

  return returnval;
}


//A message is going out to the server end user, prepare it
static int grapple_lobby_process_message(internal_lobby_data *server,
					 grapple_lobbymessage *message)
{
  //handle callbacks, we are in a thread so we can just do it
  if (grapple_lobby_callback_process(server,message))
    {
      return 0;
    }

  //If not a callback, add it to the users message queue
  grapple_thread_mutex_lock(server->message_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  server->messages=grapple_lobbymessage_link(server->messages,message);
  grapple_thread_mutex_unlock(server->message_mutex);
  
  return 0;
}


//The lobby server has been passed a message to delete a game
static int grapple_lobby_process_lobbymsg_delete_game(internal_lobby_data *server,
							grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  char outdata[8];
  grapple_lobbymessage *lobbymessage;

  if (message->USER_MSG.length<8)
    return 0;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);

  gameid=ntohl(val.i);

  //Locate the game
  game=grapple_lobbyserver_game_internal_get(server,gameid,
					     GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //delete the game for the server
  if (game && game->owner==message->USER_MSG.id)
    {
      //Unlink from the list
      grapple_thread_mutex_lock(server->games_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      server->games=grapple_lobbygame_internal_unlink(server->games,game);

      grapple_thread_mutex_unlock(server->games_mutex);

      //Decriment the game counter
      server->gamecount--;
      
      //Its not in the list we can release the mutex now
      grapple_lobbygame_internal_release(game);

      //Send a message to all clients informing them
      val.i=htonl(GRAPPLE_LOBBYMESSAGE_DELETEGAME);
      memcpy(outdata,val.c,4);
	      
      val.i=htonl(game->id);
      memcpy(outdata+4,val.c,4);

      //Send the message
      grapple_server_send(server->server,GRAPPLE_EVERYONE,0,outdata,8);

      //Now send a message to the server itself
      lobbymessage=grapple_lobbymessage_aquire();
      lobbymessage->type=GRAPPLE_LOBBYMSG_DELETEGAME;
      lobbymessage->GAME.id=game->id;

      //Send it to the message processor
      grapple_lobby_process_message(server,lobbymessage);

      //Do NOT delete the room here cos all the users in the game are about
      //to be tossed back into this room. It will NOT be empty at this point

      grapple_lobbygame_internal_dispose(game);
    }
  else if (game)
    {
      grapple_lobbygame_internal_release(game);
    }

  return 0;
}

//The client has sent us a count of how many people are connected to their game
static int grapple_lobby_process_lobbymsg_game_usercount(internal_lobby_data *server,
							 grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  int count;

  if (message->USER_MSG.length<12)
    return 0;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  count=ntohl(val.i);

  //Locate the game
  game=grapple_lobbyserver_game_internal_get(server,gameid,
					     GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Only the owner can send the data
  if (game && game->owner==message->USER_MSG.id)
    {
      //Set the value in the game data
      game->currentusers=count;
      
      grapple_lobbygame_internal_release(game);

      //We can just resend the data, it is all correct as needed
      grapple_server_send(server->server,GRAPPLE_EVERYONE,0,
			  message->USER_MSG.data,12);
    }
  else if (game)
    {
      grapple_lobbygame_internal_release(game);
    }

  return 0;
}

//We have been told how many users at maximum a game can now have
static int grapple_lobby_process_lobbymsg_game_maxusercount(internal_lobby_data *server,
							    grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  int count,loopa;

  if (message->USER_MSG.length<12)
    return 0;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  count=ntohl(val.i);

  game=grapple_lobbyserver_game_internal_get(server,gameid,
					     GRAPPLE_LOCKTYPE_EXCLUSIVE);


  //Only do it if the user is the owner
  if (game && game->owner==message->USER_MSG.id)
    {
      //Set the value
      if (count > game->maxusers)
	{
	  //Increase the buffer for the user list. Never shrink it
	  if (game->users)
	    {
	      game->users=(grapple_user *)realloc(game->users,sizeof(grapple_user *)*(count+1));
	      for (loopa=game->maxusers;loopa < count+1;loopa++)
		{
		  //Set new stuff to 0
		  game->users[loopa]=0;
		}
	    }
	  else
	    game->users=(grapple_user *)calloc(1,sizeof(grapple_user *)*(count+1));
	}
      game->maxusers=count;
      
      grapple_lobbygame_internal_release(game);

      //We can just resend the data, it is all correct as needed
      grapple_server_send(server->server,GRAPPLE_EVERYONE,0,
			  message->USER_MSG.data,12);
    }
  else if (game)
    grapple_lobbygame_internal_release(game);


  return 0;
}

//We have been told the games description has changed
static int grapple_lobby_process_lobbymsg_game_description(internal_lobby_data *server,
							   grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  size_t descriptionlen;

  if (message->USER_MSG.length<8)
    return 0;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  descriptionlen=message->USER_MSG.length-8;

  game=grapple_lobbyserver_game_internal_get(server,gameid,
					     GRAPPLE_LOCKTYPE_EXCLUSIVE);


  //Only do it if the user is the owner
  if (game && game->owner==message->USER_MSG.id)
    {
      //Set the value
      if (game->description)
	free(game->description);
      game->descriptionlen=descriptionlen;

      if (descriptionlen)
	{
	  game->description=(void *)malloc(descriptionlen);
	  memcpy(game->description,(char *)message->USER_MSG.data+8,descriptionlen);
	}
      else
	game->description=NULL;

      
      grapple_lobbygame_internal_release(game);

      //We can just resend the data, it is all correct as needed
      grapple_server_send(server->server,GRAPPLE_EVERYONE,0,
			  message->USER_MSG.data,message->USER_MSG.length);
    }
  else if (game)
    grapple_lobbygame_internal_release(game);


  return 0;
}

//We have been told if the game is open or closed
static int grapple_lobby_process_lobbymsg_game_closed(internal_lobby_data *server,
						      grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  grapple_lobbymessage *lobbymessage;
  int state;

  if (message->USER_MSG.length != 12)
    {
      return 0;
    }

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  state=ntohl(val.i);

  game=grapple_lobbyserver_game_internal_get(server,gameid,
					     GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Only do it if the user is the owner
  if (game && game->owner==message->USER_MSG.id)
    {
      //Set the value
      game->closed=state;
      
      grapple_lobbygame_internal_release(game);

      //We can just resend the data, it is all correct as needed
      grapple_server_send(server->server,GRAPPLE_EVERYONE,0,
			  message->USER_MSG.data,12);

      lobbymessage=grapple_lobbymessage_aquire();
  
      lobbymessage->type=GRAPPLE_LOBBYMSG_GAME_CLOSED;
      lobbymessage->GAME.id=gameid;
      lobbymessage->GAME.closed=state;
      grapple_lobby_process_message(server,lobbymessage);
    }
  else if (game)
    grapple_lobbygame_internal_release(game);

  return 0;
}

//We have been asked to register a game
static int grapple_lobby_process_lobbymsg_register_game(internal_lobby_data *server,
							grapple_message *message)
{
  void *data;
  char *outdata;
  size_t length,outlength,addresslength,sessionlength;
  intchar val;
  size_t offset;
  grapple_lobbygame_internal *game;
  size_t varlength;
  static int gameid=1;
  int localgameid;
  grapple_lobbyconnection *user;
  grapple_lobbymessage *lobbymessage;

  length=message->USER_MSG.length-4;
  data=(char *)message->USER_MSG.data+4;

  if (length < 4)
    return 0;

  //Unpack all the data
  //4 bytes : Session name length
  //        ; Session name
  //4 bytes : Address length
  //        : address (may be 0 bytes)
  //4 bytes : portnumber
  //4 bytes : protocol
  //4 bytes : Maximum number of users
  //4 bytes : Password required (could be 1 byte but lets stick with ints)
  //4 bytes : Length of description
  //        : Description

  //Allocate a new grapple_lobbygame structure

  memcpy(val.c,data,4);
  varlength=ntohl(val.i);

  if (length-4 < varlength)
    {
      return 0;
    }

  game=grapple_lobbygame_internal_create();
  game->session=(char *)malloc(varlength+1);
  memcpy(game->session,(char *)data+4,varlength);
  game->session[varlength]=0;
  offset=varlength+4;

  if (length-offset < 4)
    {
      grapple_lobbygame_internal_dispose(game);
      return 0;
    }
  memcpy(val.c,(char *)data+offset,4);
  varlength=ntohl(val.i);
  offset+=4;

  if (varlength)
    {
      if (length-offset < varlength)
	{
	  grapple_lobbygame_internal_dispose(game);
	  return 0;
	}
      game->address=(char *)malloc(varlength+1);
      memcpy(game->address,(char *)data+offset,varlength);
      game->address[varlength]=0;
      offset+=varlength;
    }

  if (length-offset < 20)
    {
      grapple_lobbygame_internal_dispose(game);
      return 0;
    }
  memcpy(val.c,(char *)data+offset,4);
  game->port=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->protocol=(grapple_protocol)ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->maxusers=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->needpassword=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->descriptionlen=ntohl(val.i);
  offset+=4;

  if (game->descriptionlen > 0)
    {
      if (length-offset < game->descriptionlen)
	{
	  grapple_lobbygame_internal_dispose(game);
	  return 0;
	}
      game->description=(void *)malloc(game->descriptionlen);
      memcpy(game->description,(char *)data+offset,game->descriptionlen);
      offset+=game->descriptionlen;
    }

  game->users=(grapple_user *)calloc(1,sizeof(grapple_user *)*(game->maxusers+1));

  //The game structure is allocated.

  //Now check there is an address. If not, get one
  if (!game->address)
    {
      game->address=grapple_server_client_address_get(server->server,
						      message->USER_MSG.id);

      if (!game->address)
	{
	  //We have NO idea where the request actually came from - this
	  //should never happen, but if it does...

	  outdata=(char *)malloc(8);

	  val.i=htonl(GRAPPLE_LOBBYMESSAGE_YOURGAMEID);
	  memcpy(outdata,val.c,4);
	  
	  val.i=htonl(-1);
	  memcpy(outdata+4,val.c,4);
	  
	  //Sent this message - game ID is -1, to the client - that is a fail
	  grapple_server_send(server->server,message->USER_MSG.id,0,
			      outdata,8);
	  
	  free(outdata);
	  
	  return 0;
	}
    }

  localgameid=gameid++;
  game->id=localgameid;

  //Find the room that the game has been created in
  grapple_thread_mutex_lock(server->userlist_mutex,GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(server->userlist,
					    message->USER_MSG.id);
  if (user)
    {
      game->room=user->currentroom;

      //This sets the users game so we can unlink the game when the user goes
      user->ownsgame=game->id;
    }

  grapple_thread_mutex_unlock(server->userlist_mutex);

  game->owner=message->USER_MSG.id;

  //set the length to be:
  outlength=36; /*Ints for lobbyprotocol, port, protocol, currentusers,
		  maxusers, needpassword , game ID, roomnumber, closed */
  
  sessionlength=strlen(game->session);
  outlength+=(sessionlength+4); //The length of the session plus a length int

  addresslength=strlen(game->address);
  outlength+=(addresslength+4); //The length of the address plus a length int

  outlength+=4;
  outlength+=game->descriptionlen;

  outdata=(char *)malloc(outlength);

  //Now we need to put together the more complicated data packet that is
  //showing the new game to the players.
  //4 bytes : Lobby protocol
  //4 bytes : game ID
  //4 bytes : Session name length
  //        ; Session name
  //4 bytes : Address length
  //        : address
  //4 bytes : portnumber
  //4 bytes : protocol
  //4 bytes : Current number of users
  //4 bytes : Maximum number of users
  //4 bytes : Password required (could be 1 byte but lets stick with ints)
  //4 bytes : Room number
  //4 bytes : description length
  //        : description
  //4 bytes : Closed state

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_REGISTERGAME);
  memcpy(outdata,val.c,4);

  val.i=htonl(game->id);
  memcpy(outdata+4,val.c,4);

  val.i=htonl((long)sessionlength);
  memcpy(outdata+8,val.c,4);

  memcpy(outdata+12,game->session,sessionlength);
  offset=sessionlength+12;

  val.i=htonl((long)addresslength);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  memcpy(outdata+offset,game->address,addresslength);
  offset+=addresslength;
  
  val.i=htonl(game->port);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(game->protocol);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(game->currentusers);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(game->maxusers);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(game->needpassword);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(game->room);
  memcpy(outdata+offset,val.c,4);
  offset+=4;
  
  val.i=htonl((long)game->descriptionlen);
  memcpy(outdata+offset,val.c,4);
  offset+=4;
 
  if (game->descriptionlen)
    {
      memcpy(outdata+offset,game->description,game->descriptionlen);
      offset+=game->descriptionlen;
    }

  val.i=htonl(game->closed);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

 //Link this into the servers list before we tell everyone about it
  grapple_thread_mutex_lock(server->games_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  server->games=grapple_lobbygame_internal_link(server->games,game);

  //Incriment the game counter
  server->gamecount++;
      
  grapple_thread_mutex_unlock(server->games_mutex);

  //Send this message to everyone now, so they can all register the new game
  grapple_server_send(server->server,GRAPPLE_EVERYONE,0,outdata,outlength);

  free(outdata);

  //Now tell the client the new ID of their game
  outdata=(char *)malloc(8);
  
  val.i=htonl(GRAPPLE_LOBBYMESSAGE_YOURGAMEID);
  memcpy(outdata,val.c,4);
  
  val.i=htonl(localgameid);
  memcpy(outdata+4,val.c,4);
  
  grapple_server_send(server->server,message->USER_MSG.id,0,outdata,8);
  
  free(outdata);
  
  //Set up a message to tell the player
  lobbymessage=grapple_lobbymessage_aquire();
  
  lobbymessage->type=GRAPPLE_LOBBYMSG_NEWGAME;
  lobbymessage->GAME.id=game->id;
  lobbymessage->GAME.name=(char *)malloc(strlen(game->session)+1);
  strcpy(lobbymessage->GAME.name,game->session);
  lobbymessage->GAME.maxusers=game->maxusers;
  lobbymessage->GAME.needpassword=game->needpassword;
  //Send it to the message processor
  grapple_lobby_process_message(server,lobbymessage);

  return 0;
}

static int grapple_lobby_process_lobbymsg_usermsg(internal_lobby_data *server,
						  grapple_message *message)
{
  void *data;
  size_t length;
  grapple_lobbymessage *outmessage;

  length=message->USER_MSG.length-4;
  data=(char *)message->USER_MSG.data+4;

  if (length < 1)
    return 0;

  //Decode the message into a lobbymessage

  outmessage=grapple_lobbymessage_aquire();
  
  outmessage->type=GRAPPLE_LOBBYMSG_USERMSG;
  outmessage->USERMSG.id=message->USER_MSG.id;
  outmessage->USERMSG.length=length;
  outmessage->USERMSG.data=malloc(length+1);
  memcpy(outmessage->USERMSG.data,data,length);
  *(((char *)outmessage->USERMSG.data)+length)=0;

  //Send it to the message processor
  grapple_lobby_process_message(server,outmessage);

  return 0;
}

static int grapple_lobby_process_lobbymsg_request_gamelist(internal_lobby_data *server,
							   grapple_message *message)
{
  char *outdata;
  size_t offset,outlength,sessionlength,addresslength;
  int serveronly=0;
  unsigned int loopa;
  grapple_lobbygame_internal *scan;
  intchar val;
  grapple_lobbyconnection *user;

  grapple_thread_mutex_lock(server->userlist_mutex,GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(server->userlist,
					    message->USER_MSG.id);
  if (user)
    serveronly=user->server_only;
  grapple_thread_mutex_unlock(server->userlist_mutex);


  //This message can only mean one thing, so tell the client about all of the
  //games available

  grapple_thread_mutex_lock(server->games_mutex,GRAPPLE_LOCKTYPE_SHARED);
  scan=server->games;

  while (scan)
    {
      //set the length to be:
      outlength=36; /*Ints for lobbyprotocol, port, protocol, currentusers, 
		      maxusers, needpassword , game ID, roomnumber, closed */
      
      sessionlength=strlen(scan->session);
      outlength+=(sessionlength+4); //The length of the session plus a length int
      
      addresslength=strlen(scan->address);
      outlength+=(addresslength+4); //The length of the address plus a length int
      
      outlength+=4;
      outlength+=scan->descriptionlen; //Length of the description

      outdata=(char *)malloc(outlength);
      
      //Now we need to put together the more complicated data packet that is
      //showing the new game to the players.
      //4 bytes : Lobby protocol
      //4 bytes : game ID
      //4 bytes : Session name length
      //        ; Session name
      //4 bytes : Address length
      //        : address
      //4 bytes : portnumber
      //4 bytes : protocol
      //4 bytes : Current number of users
      //4 bytes : Maximum number of users
      //4 bytes : Password required (could be 1 byte but lets stick with ints)
      //4 bytes : Room number
      //4 bytes : Description length
      //        : Description
      //4 bytes : Closed state

      val.i=htonl(GRAPPLE_LOBBYMESSAGE_REGISTERGAME);
      memcpy(outdata,val.c,4);
      
      val.i=htonl(scan->id);
      memcpy(outdata+4,val.c,4);

      val.i=htonl((long)sessionlength);
      memcpy(outdata+8,val.c,4);
      
      memcpy(outdata+12,scan->session,sessionlength);
      offset=sessionlength+12;
      
      val.i=htonl((long)addresslength);
      memcpy(outdata+offset,val.c,4);
      offset+=4;

      if (serveronly)
	{
	  for (loopa=0;loopa < addresslength;loopa++)
	    outdata[offset+loopa]=' ';
	}
      else
	memcpy(outdata+offset,scan->address,addresslength);
      offset+=addresslength;
      
      val.i=htonl(scan->port);
      memcpy(outdata+offset,val.c,4);
      offset+=4;

      val.i=htonl(scan->protocol);
      memcpy(outdata+offset,val.c,4);
      offset+=4;
      
      val.i=htonl(scan->currentusers);
      memcpy(outdata+offset,val.c,4);
      offset+=4;
      
      val.i=htonl(scan->maxusers);
      memcpy(outdata+offset,val.c,4);
      offset+=4;
      
      val.i=htonl(scan->needpassword);
      memcpy(outdata+offset,val.c,4);
      offset+=4;
      
      val.i=htonl(scan->room);
      memcpy(outdata+offset,val.c,4);
      offset+=4;

      val.i=htonl((long)scan->descriptionlen);
      memcpy(outdata+offset,val.c,4);
      offset+=4;

      if (scan->descriptionlen)
	{
	  memcpy(outdata+offset,scan->description,scan->descriptionlen);
	  offset+=scan->descriptionlen;
	}

      val.i=htonl(scan->closed);
      memcpy(outdata+offset,val.c,4);
      offset+=4;
      
      //Send this message to everyone now,so they can all register the new game
      grapple_server_send(server->server,message->USER_MSG.id,
			  0,outdata,outlength);
      
      free(outdata);

      scan=scan->next;
      if (scan==server->games)
	scan=NULL;
    }
  grapple_thread_mutex_unlock(server->games_mutex);

  return 0;
}


static int grapple_lobby_process_lobbymsg_user_joinedgame(internal_lobby_data *server,
							  grapple_message *message)
{
  char outdata[12];
  intchar val;
  void *data;
  grapple_lobbygameid gameid;
  grapple_lobbymessage *lobbymessage;
  int loopa;
  size_t len;
  grapple_lobbygame_internal *game;
  grapple_lobbyconnection *user;

  data=(char *)message->USER_MSG.data+4;
  len=message->USER_MSG.length-4;

  if (len<4)
    return 0;
  memcpy(val.c,data,4);
  
  gameid=ntohl(val.i);

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_USER_JOINEDGAME);
  memcpy(outdata,val.c,4);
      
  val.i=htonl(gameid);
  memcpy(outdata+4,val.c,4);

  val.i=htonl(message->USER_MSG.id);
  memcpy(outdata+8,val.c,4);

  //Send this message to everyone now, so they can all know who has joined a 
  //game
  grapple_server_send(server->server,GRAPPLE_EVERYONE,
		      0,outdata,12);
      
  //Tell the server the message
  lobbymessage=grapple_lobbymessage_aquire();
  
  lobbymessage->type=GRAPPLE_LOBBYMSG_USER_JOINEDGAME;
  lobbymessage->USERGAME.userid=message->USER_MSG.id;
  lobbymessage->USERGAME.gameid=gameid;

  //Send it to the message processor
  grapple_lobby_process_message(server,lobbymessage);


  game=grapple_lobbyserver_game_internal_get(server,gameid,
					     GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (game)
    {
      //This loops looking for the first available user slot
      for (loopa=0;loopa < game->maxusers;loopa++)
	{
	  if (game->users[loopa]==0)
	    {
	      game->users[loopa]=message->USER_MSG.id;
	      loopa=game->maxusers;
	    }
	}

      grapple_lobbygame_internal_release(game);
    }


  //Now get the user and mark them as in the game
  grapple_thread_mutex_lock(server->userlist_mutex,GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(server->userlist,
                                            message->USER_MSG.id);
  if (user)
    user->ingame=gameid;
  grapple_thread_mutex_unlock(server->userlist_mutex);


  return 0;
}

static int grapple_lobby_process_lobbymsg_user_leftgame(internal_lobby_data *server,
							grapple_message *message)
{
  char outdata[12];
  intchar val;
  void *data;
  grapple_lobbygameid gameid;
  grapple_lobbymessage *lobbymessage;
  grapple_lobbygame_internal *game;
  grapple_lobbyconnection *user;
  int loopa;
  size_t len;

  data=(char *)message->USER_MSG.data+4;
  len=message->USER_MSG.length-4;


  if (len<4)
    return 0;
  memcpy(val.c,data,4);
  
  gameid=ntohl(val.i);

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_USER_LEFTGAME);
  memcpy(outdata,val.c,4);
      
  val.i=htonl(gameid);
  memcpy(outdata+4,val.c,4);

  val.i=htonl(message->USER_MSG.id);
  memcpy(outdata+8,val.c,4);

  //Send this message to everyone now, so they can all know who has joined a 
  //game
  grapple_server_send(server->server,GRAPPLE_EVERYONE,
		      0,outdata,12);
      
  //Tell the server the message
  lobbymessage=grapple_lobbymessage_aquire();
  
  lobbymessage->type=GRAPPLE_LOBBYMSG_USER_LEFTGAME;
  lobbymessage->USERGAME.userid=message->USER_MSG.id;
  lobbymessage->USERGAME.gameid=gameid;

  //Send it to the message processor
  grapple_lobby_process_message(server,lobbymessage);
  
  //Now remove this user from the game
  game=grapple_lobbyserver_game_internal_get(server,gameid,
					     GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (game)
    {
      //This loops looking for the first available user slot
      for (loopa=0;loopa < game->maxusers;loopa++)
	{
	  if (game->users[loopa]==message->USER_MSG.id)
	    {
	      game->users[loopa]=0;
	      loopa=game->maxusers;
	    }
	}
      
      grapple_lobbygame_internal_release(game);
    }

  //Now get the user and mark them as not in the game
  grapple_thread_mutex_lock(server->userlist_mutex,GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(server->userlist,
                                            message->USER_MSG.id);
  if (user)
    user->ingame=0;
  grapple_thread_mutex_unlock(server->userlist_mutex);


  return 0;
}

//Client is sending a message to the server
int grapple_lobby_message_send(grapple_lobby lobby,
			       grapple_user target,
			       const void *message,size_t length)
{
  internal_lobby_data *lobbydata;
  char *outdata;
  intchar val;
  
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Make up the packet
  //4 bytes : protocol
  //4 bytes : message length
  //        : message

  outdata=(char *)malloc(length+4);

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_USERMSG);
  memcpy(outdata,val.c,4);

  memcpy(outdata+4,message,length);

  //Send the message to the server
  grapple_server_send(lobbydata->server,target,0,outdata,length+4);

  internal_lobby_release(lobbydata);

  free(outdata);

  return 0;
}

//A generic user message. This is a grapple message containing user data,
//in this case, the data for the lobby protocol
//This gets handed off to protocol handling functions
static int grapple_lobby_process_user_msg(internal_lobby_data *server,
					  grapple_message *message)
{
  grapple_lobbymessagetype_internal type;
  intchar val;

  //User message - break it into its components

  if (message->USER_MSG.length < 4)
    return 0;

  memcpy(val.c,message->USER_MSG.data,4);
  type=(grapple_lobbymessagetype_internal)ntohl(val.i);

  //Send off to a handler  
  switch (type)
    {
    case GRAPPLE_LOBBYMESSAGE_REGISTERGAME:
      grapple_lobby_process_lobbymsg_register_game(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_DELETEGAME:
      grapple_lobby_process_lobbymsg_delete_game(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_USERCOUNT:
      grapple_lobby_process_lobbymsg_game_usercount(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_MAXUSERCOUNT:
      grapple_lobby_process_lobbymsg_game_maxusercount(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_CLOSED:
      grapple_lobby_process_lobbymsg_game_closed(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_DESCRIPTION:
      grapple_lobby_process_lobbymsg_game_description(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_USERMSG:
      grapple_lobby_process_lobbymsg_usermsg(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_REQUEST_GAMELIST:
      grapple_lobby_process_lobbymsg_request_gamelist(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_USER_JOINEDGAME:
      grapple_lobby_process_lobbymsg_user_joinedgame(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_USER_LEFTGAME:
      grapple_lobby_process_lobbymsg_user_leftgame(server,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_CHAT:
    case GRAPPLE_LOBBYMESSAGE_YOURGAMEID:
      //Never sent to the server
      break;
    }
  
  return 0;
}

//A new user has connected
static int grapple_lobby_process_new_user(internal_lobby_data *server,
					  grapple_message *message)
{
  grapple_lobbyconnection *newuser;
  grapple_lobbymessage *lobbymessage;

  //Create the users local data
  newuser=grapple_lobbyconnection_create();

  newuser->id=message->NEW_USER.id;
  if (message->NEW_USER.name)
    {
      newuser->name=(char *)malloc(strlen(message->NEW_USER.name)+1);
      strcpy(newuser->name,message->NEW_USER.name);
    }

  //Tell the server the message
  lobbymessage=grapple_lobbymessage_aquire();
  
  lobbymessage->type=GRAPPLE_LOBBYMSG_NEWUSER;
  lobbymessage->USER.id=message->NEW_USER.id;
  lobbymessage->USER.name=message->NEW_USER.name;
  message->NEW_USER.name=NULL;

  //Send it to the message processor
  grapple_lobby_process_message(server,lobbymessage);
  //We dont tell the clients, because Grapple will tell them


  //Now the server has been informed of the user, add them to the main room  
  grapple_server_group_add(server->server,server->mainroom,
                           newuser->id,NULL);
  newuser->currentroom=server->mainroom;

  grapple_thread_mutex_lock(server->userlist_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  server->userlist=grapple_lobbyconnection_link(server->userlist,newuser);
  grapple_thread_mutex_unlock(server->userlist_mutex);

  return 0;
}


//The user has added themself to a group - they have entered a room
static int grapple_lobby_process_group_add(internal_lobby_data *server,
					      grapple_message *message)
{
  grapple_lobbyconnection *user;


  //Change their current room in the user data
  grapple_thread_mutex_lock(server->userlist_mutex,GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(server->userlist,
					    message->GROUP.memberid);
  if (user)
    user->currentroom=message->GROUP.groupid;
  grapple_thread_mutex_unlock(server->userlist_mutex);

  return 0;
}


//The user has removed themself from a group - they have left a room
static int grapple_lobby_process_group_remove(internal_lobby_data *server,
					      grapple_message *message)
{
  //If the room is now empty, delete the room
  if (grapple_lobby_room_empty(server,message->GROUP.groupid))
    grapple_server_group_delete(server->server,message->GROUP.groupid);

  return 0;
}

//A user has disconnected - grapple will tell the clients
static int grapple_lobby_process_user_disconnected(internal_lobby_data *server,
					      grapple_message *message)
{
  grapple_lobbyconnection *user;
  grapple_lobbygame_internal *game;
  char outdata[8];
  intchar val;
  int loopa;
  grapple_lobbymessage *lobbymessage;

  grapple_thread_mutex_lock(server->userlist_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Find the users details
  user=grapple_lobbyconnection_locate_by_id(server->userlist,
					    message->USER_DISCONNECTED.id);
					 
  if (user)
    {
      //Remove them from the list
      server->userlist=grapple_lobbyconnection_unlink(server->userlist,user);

      grapple_thread_mutex_unlock(server->userlist_mutex);
      
      //Remove them from their room (group)
      grapple_server_group_remove(server->server,user->currentroom,
				  user->id);

      //Check the room - is it now empty?

      //We dont do this if the user is in a game, because the users in the
      //game will be bailed out into the room when the game ends, so the room
      //needs to still be here
      if (!user->ownsgame)
	{
	  if (grapple_lobby_room_empty(server,user->currentroom))
	    grapple_server_group_delete(server->server,user->currentroom);
	}
      else
	{
	  //Find the users game and remove it
	  game=grapple_lobbyserver_game_internal_get(server,user->ownsgame,
						     GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  
	  if (game)
	    {
	      grapple_thread_mutex_lock(server->games_mutex,
					GRAPPLE_LOCKTYPE_EXCLUSIVE);
	      server->games=grapple_lobbygame_internal_unlink(server->games,game);
	      grapple_thread_mutex_unlock(server->games_mutex);
	      
	      grapple_lobbygame_internal_release(game);

	      //Let everyone know that this game is gone now
	      val.i=htonl(GRAPPLE_LOBBYMESSAGE_DELETEGAME);
	      memcpy(outdata,val.c,4);
	      
	      val.i=htonl(user->ownsgame);
	      memcpy(outdata+4,val.c,4);
	      
	      grapple_server_send(server->server,GRAPPLE_EVERYONE,0,
				  outdata,8);
	      
	      //Now send a message to the server itself
	      lobbymessage=grapple_lobbymessage_aquire();
	      lobbymessage->type=GRAPPLE_LOBBYMSG_DELETEGAME;
	      lobbymessage->GAME.id=game->id;
	      
	      //Send it to the message processor
	      grapple_lobby_process_message(server,lobbymessage);
	      
	      grapple_lobbygame_internal_dispose(game);
	      
	      user->ownsgame=0;
	    }
	} 


      if (user->ingame)
	{
	  //Now remove this user from any game they may be part of
	  //Find the game
	  game=grapple_lobbyserver_game_internal_get(server,user->ingame,
						     GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  if (game)
	    {
	      //This loops looking for the first available user slot
	      for (loopa=0;loopa < game->maxusers;loopa++)
		{
		  if (game->users[loopa]==message->USER_MSG.id)
		    {
		      game->users[loopa]=0;
		      loopa=game->maxusers;
		    }
		}
	      
	      grapple_lobbygame_internal_release(game);
	    }
	}

      //Dispose of the user
      grapple_lobbyconnection_dispose(user);
    }
  else
    grapple_thread_mutex_unlock(server->userlist_mutex);
  
  //Tell the server the message
  lobbymessage=grapple_lobbymessage_aquire();

  lobbymessage->type=GRAPPLE_LOBBYMSG_USER_DISCONNECTED;
  lobbymessage->USER.id=message->USER_DISCONNECTED.id;

  //Send it to the message processor
  grapple_lobby_process_message(server,lobbymessage);

  return 0;
}

//A generic callback to handle all grapple messages that come through from the
//network
static int grapple_lobby_generic_callback(grapple_message *message,
					  void *context)
{
  internal_lobby_data *server;

  server=(internal_lobby_data *)context;

  //Hand off the message based on what it is
  switch (message->type)
    {
    case GRAPPLE_MSG_NEW_USER:
      grapple_lobby_process_new_user(server,message);
      break;
    case GRAPPLE_MSG_GROUP_REMOVE:
      grapple_lobby_process_group_remove(server,message);
      break;
    case GRAPPLE_MSG_GROUP_ADD:
      grapple_lobby_process_group_add(server,message);
      break;
    case GRAPPLE_MSG_USER_DISCONNECTED:
      grapple_lobby_process_user_disconnected(server,message);
      break;
    case GRAPPLE_MSG_USER_MSG:
      grapple_lobby_process_user_msg(server,message);
      break;
    case GRAPPLE_MSG_GROUP_CREATE:
    case GRAPPLE_MSG_GROUP_DELETE:
    case GRAPPLE_MSG_CONFIRM_RECEIVED:
    case GRAPPLE_MSG_CONFIRM_TIMEOUT:
    case GRAPPLE_MSG_SESSION_NAME:
    case GRAPPLE_MSG_USER_NAME:
    case GRAPPLE_MSG_PING:
      //Dont care about these ones
      break;
    case GRAPPLE_MSG_NEW_USER_ME:
    case GRAPPLE_MSG_YOU_ARE_HOST:
    case GRAPPLE_MSG_SERVER_DISCONNECTED:
    case GRAPPLE_MSG_CONNECTION_REFUSED:
    case GRAPPLE_MSG_GAME_DESCRIPTION:
      //These never come to the server
      break;
    case GRAPPLE_MSG_NONE:
      //Never received, default NULL value
      break;
    }
  
  grapple_message_dispose(message);

  return 0;
}


//Start the lobby
int grapple_lobby_start(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  int returnval;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Check the lobbys minimum defaults are set
  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return GRAPPLE_FAILED;
    }

  //Set the servers network details
  grapple_server_protocol_set(lobbydata->server,GRAPPLE_PROTOCOL_TCP);
  grapple_server_session_set(lobbydata->server,"Grapple Lobby");
  grapple_server_namepolicy_set(lobbydata->server,GRAPPLE_NAMEPOLICY_UNIQUE);
  grapple_server_callback_setall(lobbydata->server,
				 grapple_lobby_generic_callback,
				 (void *)lobbydata);

  //Start the server
  returnval=grapple_server_start(lobbydata->server);

  if (returnval!=GRAPPLE_OK)
    {
      internal_lobby_release(lobbydata);
      return returnval;
    }


  //Set up the room as the mainroom
  lobbydata->mainroom=grapple_server_group_create(lobbydata->server,
						  GRAPPLE_LOBBY_ENTRY_ROOM,
						  NULL);
  
  internal_lobby_release(lobbydata);

  return GRAPPLE_OK;
}


//Destroy the lobby
int grapple_lobby_destroy(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  grapple_lobbygame_internal *gametarget;
  grapple_lobbyconnection *connection;
  grapple_lobbymessage *message;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //remove it from the list
  internal_lobby_unlink(lobbydata);

  internal_lobby_release(lobbydata);

  //Destroy the grapple layer
  if (lobbydata->server)
    grapple_server_destroy(lobbydata->server);

  //Delete connected games
  grapple_thread_mutex_lock(lobbydata->games_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  while (lobbydata->games)
    {
      gametarget=lobbydata->games;

      lobbydata->games=grapple_lobbygame_internal_unlink(lobbydata->games,lobbydata->games);

      grapple_thread_mutex_lock(gametarget->inuse,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      //Now just unlock it, we have exclusive ownership, and nobody 
      //else can get it cos its not in the list any more
      grapple_thread_mutex_unlock(gametarget->inuse);

      grapple_lobbygame_internal_dispose(gametarget);
    }
  grapple_thread_mutex_unlock(lobbydata->games_mutex);


  //Unlink all the users
  grapple_thread_mutex_lock(lobbydata->userlist_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  while (lobbydata->userlist)
    {
      connection=lobbydata->userlist;
      lobbydata->userlist=grapple_lobbyconnection_unlink(lobbydata->userlist,
						    lobbydata->userlist);
      grapple_lobbyconnection_dispose(connection);
    }
  grapple_thread_mutex_unlock(lobbydata->userlist_mutex);

  //Unlink all the remaining incoming messages
  grapple_thread_mutex_lock(lobbydata->message_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  while (lobbydata->messages)
    {
      message=lobbydata->messages;
      lobbydata->messages=grapple_lobbymessage_unlink(lobbydata->messages,
						 lobbydata->messages);
      grapple_lobbymessage_dispose(message);
    }
  grapple_thread_mutex_unlock(lobbydata->message_mutex);

  //Delete the mutexes
  grapple_thread_mutex_destroy(lobbydata->userlist_mutex);
  grapple_thread_mutex_destroy(lobbydata->message_mutex);
  grapple_thread_mutex_destroy(lobbydata->games_mutex);
  grapple_thread_mutex_destroy(lobbydata->callback_mutex);
  grapple_thread_mutex_destroy(lobbydata->inuse);

  free(lobbydata);

  return GRAPPLE_OK;
}

//Set a callback. Callbacks are so that instead of needing to poll for
//messages, a callback can be set so that the messages are handled immediately
int grapple_lobby_callback_set(grapple_lobby lobby,
			       grapple_lobbymessagetype message,
			       grapple_lobbycallback callback,
			       void *context)
{
  internal_lobby_data *lobbydata;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(lobbydata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Add the callback to the list of callbacks
  lobbydata->callbacks=grapple_lobbycallback_add(lobbydata->callbacks,
						 message,callback,context);

  grapple_thread_mutex_unlock(lobbydata->callback_mutex);

  internal_lobby_release(lobbydata);

  return GRAPPLE_OK;
}

//Set ALL callbacks to the function requested
int grapple_lobby_callback_setall(grapple_lobby server,
				  grapple_lobbycallback callback,
				  void *context)
{
  //Set one using the function above
  if (grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_ROOMLEAVE,
				 callback,context)==GRAPPLE_FAILED)
    return GRAPPLE_FAILED;
  
  //if one is ok, they all should be
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_ROOMENTER,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_ROOMCREATE,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_ROOMDELETE,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_CHAT,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_DISCONNECTED,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_NEWGAME,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_DELETEGAME,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_GAME_MAXUSERS,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_GAME_USERS,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_GAME_CLOSED,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_USERMSG,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_NEWUSER,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_CONNECTION_REFUSED,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_USER_DISCONNECTED,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_USER_JOINEDGAME,
			     callback,context);
  grapple_lobby_callback_set(server,GRAPPLE_LOBBYMSG_USER_LEFTGAME,
			     callback,context);

  return GRAPPLE_OK;
}

//Remove a callback
int grapple_lobby_callback_unset(grapple_lobby lobby,
				 grapple_lobbymessagetype message)
{
  internal_lobby_data *lobbydata;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(lobbydata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Remove the callback
  lobbydata->callbacks=grapple_lobbycallback_remove(lobbydata->callbacks,
						    message);

  grapple_thread_mutex_unlock(lobbydata->callback_mutex);

  internal_lobby_release(lobbydata);

  return GRAPPLE_OK;
}

//Get the last error
grapple_error grapple_lobby_error_get(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  grapple_error returnval;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      return grapple_lobbyerror_get();
    }

  returnval=grapple_server_error_get(lobbydata->server);

  internal_lobby_release(lobbydata);

  return returnval;
}

grapple_lobbygameid *grapple_lobby_gamelist_get(grapple_lobby lobby,
						grapple_lobbyroomid roomid)
{
  internal_lobby_data *lobbydata;
  grapple_lobbygameid *returnval;
  grapple_lobbygame_internal *scan;
  int loopa;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  grapple_thread_mutex_lock(lobbydata->games_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  returnval=(grapple_lobbygameid *)malloc(sizeof(grapple_lobbygameid)*(lobbydata->gamecount+1));

  scan=lobbydata->games;
  loopa=0;
	
  while (scan)
    {
      if (!roomid || scan->room==roomid)
	returnval[loopa++]=scan->id;
      scan=scan->next;
      if (scan==lobbydata->games)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(lobbydata->games_mutex);

  returnval[loopa]=0;

  internal_lobby_release(lobbydata);

  return returnval;
}


grapple_user *grapple_lobby_game_users_get(grapple_lobby lobby,
					   grapple_lobbygameid gameid)
{
  internal_lobby_data *lobbydata;
  int loopa,out;
  grapple_user *returnval=NULL;
  grapple_lobbygame_internal *game;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  game=grapple_lobbyserver_game_internal_get(lobbydata,gameid,
					     GRAPPLE_LOCKTYPE_SHARED);
  if (game)
    {
      //We have the game, lock the userlist
      returnval=(grapple_user *)calloc(1,sizeof(grapple_user)*(game->maxusers+1));
      out=0;
      //This loops looking for the first available user slot
      for (loopa=0;loopa < game->maxusers;loopa++)
	{
	  if (game->users[loopa])
	    {
	      returnval[out++]=game->users[loopa];
	    }
	}
      
      grapple_lobbygame_internal_release(game);
    }
  

  internal_lobby_release(lobbydata);

  return returnval;
}

grapple_user *grapple_lobby_users_get(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  grapple_user *returnval=NULL;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return NULL;
    }

  returnval=grapple_server_userlist_get(lobbydata->server);

  internal_lobby_release(lobbydata);

  return returnval;
}

char *grapple_lobby_user_name_get(grapple_lobby lobby,
				  grapple_user target)
{
  internal_lobby_data *lobbydata;
  char *returnval=NULL;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return NULL;
    }

  returnval=grapple_server_user_name_get(lobbydata->server,target);

  internal_lobby_release(lobbydata);

  return returnval;
}

int grapple_lobby_user_server_only_set(grapple_lobby lobby,grapple_user userid)
{
  internal_lobby_data *lobbydata;
  grapple_lobbyconnection *user;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }


  grapple_thread_mutex_lock(lobbydata->userlist_mutex,GRAPPLE_LOCKTYPE_SHARED);

  user=grapple_lobbyconnection_locate_by_id(lobbydata->userlist,userid);

  if (user)
    user->server_only=1;

  grapple_thread_mutex_unlock(lobbydata->userlist_mutex);

  internal_lobby_release(lobbydata);

  return 1;
}

int grapple_lobby_user_server_only_get(grapple_lobby lobby,grapple_user userid)
{
  internal_lobby_data *lobbydata;
  grapple_lobbyconnection *user;
  int rv=0;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  grapple_thread_mutex_lock(lobbydata->userlist_mutex,GRAPPLE_LOCKTYPE_SHARED);

  user=grapple_lobbyconnection_locate_by_id(lobbydata->userlist,userid);

  if (user)
    rv=user->server_only;

  grapple_thread_mutex_unlock(lobbydata->userlist_mutex);

  internal_lobby_release(lobbydata);

  return rv;
}

grapple_certificate *grapple_lobby_user_certificate_get(grapple_lobby lobby,
							grapple_user user)
{
  internal_lobby_data *lobbydata;
  grapple_certificate *rv=NULL;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  rv=grapple_server_user_certificate_get(lobbydata->server,user);

  internal_lobby_release(lobbydata);

  return rv;
}

int grapple_lobby_disconnect_client(grapple_lobby lobby,
				    grapple_user user)
{
  internal_lobby_data *lobbydata;
  int rv=0;

  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }
  
  rv=grapple_server_disconnect_client(lobbydata->server,user);

  internal_lobby_release(lobbydata);

  return rv;
}

//Get the top message from the list of messages for the clients attention
grapple_lobbymessage *grapple_lobby_message_pull(grapple_lobby lobby)
{
  internal_lobby_data *lobbydata;
  grapple_lobbymessage *message;

 //Get the lobbyclient data
  lobbydata=internal_lobby_get(lobby,GRAPPLE_LOCKTYPE_SHARED);

  if (!lobbydata)
    return NULL;

  if (!lobbydata->server)
    {
      internal_lobby_release(lobbydata);
      return NULL;
    }

  if (!lobbydata->messages)
    {
      internal_lobby_release(lobbydata);
      return NULL;
    }

  //Get the message at the top of the queue
  grapple_thread_mutex_lock(lobbydata->message_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  message=lobbydata->messages;

  //Unlink it from the message list
  lobbydata->messages=grapple_lobbymessage_unlink(lobbydata->messages,message);
  grapple_thread_mutex_unlock(lobbydata->message_mutex);

  internal_lobby_release(lobbydata);

  message->next=NULL;
  message->prev=NULL;

  return message;
}

