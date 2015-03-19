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
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "grapple_lobby.h"
#include "grapple_lobbyclient.h"
#include "grapple_lobby_internal.h"
#include "grapple_defines.h"
#include "grapple_error.h"
#include "grapple_client.h"
#include "grapple_thread.h"
#include "grapple_server.h"
#include "tools.h"
#include "grapple_lobbyconnection.h"
#include "grapple_lobbyerror.h"
#include "grapple_lobbymessage.h"
#include "grapple_lobbygame.h"
#include "grapple_lobbycallback.h"
#include "grapple_lobbyclient_thread.h"

/**************************************************************************
 ** The functions in this file are generally those that are accessible   **
 ** to the end user. Obvious exceptions are those that are static which  **
 ** are just internal utilities.                                         **
 ** Care should be taken to not change the parameters of outward facing  **
 ** functions unless absolutely required                                 **
 **************************************************************************/

//This is a static variable which keeps track of the list of all lobbyclients
//run by this program. The lobbyclients are kept in a linked list. This 
//variable is global to this file only.
static internal_lobbyclient_data *grapple_lobbyclient_head=NULL;

//And this is the mutex to make this threadsafe
static grapple_thread_mutex *lobbyclient_mutex;

//Link a lobbyclient to the list
static int internal_lobbyclient_link(internal_lobbyclient_data *data)
{
  grapple_thread_mutex_lock(lobbyclient_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  if (!grapple_lobbyclient_head)
    {
      grapple_lobbyclient_head=data;
      data->next=data;
      data->prev=data;
      grapple_thread_mutex_unlock(lobbyclient_mutex);
      return 1;
    }

  data->next=grapple_lobbyclient_head;
  data->prev=grapple_lobbyclient_head->prev;
  data->next->prev=data;
  data->prev->next=data;

  grapple_lobbyclient_head=data;
  
  grapple_thread_mutex_unlock(lobbyclient_mutex);

  return 1;
}

//Remove a lobbyclient from the linked list
static int internal_lobbyclient_unlink(internal_lobbyclient_data *data)
{
  grapple_thread_mutex_lock(lobbyclient_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (data->next==data)
    {
      grapple_lobbyclient_head=NULL;
      grapple_thread_mutex_unlock(lobbyclient_mutex);
      return 1;
    }

  data->next->prev=data->prev;
  data->prev->next=data->next;

  if (data==grapple_lobbyclient_head)
    grapple_lobbyclient_head=data->next;

  grapple_thread_mutex_unlock(lobbyclient_mutex);

  data->next=NULL;
  data->prev=NULL;

  return 1;
}

//Find the lobbyclient from the ID number passed by the user
static internal_lobbyclient_data *internal_lobbyclient_get(grapple_lobbyclient num)
{
  internal_lobbyclient_data *scan;
  
  int finished=0,found;

  while (!finished)
    {
      //By default if passed 0, then the oldest lobbyclient is returned
      if (!num)
	{
	  grapple_thread_mutex_lock(lobbyclient_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);

	  if (!grapple_lobbyclient_head)
	    {
	      grapple_thread_mutex_unlock(lobbyclient_mutex);
	      
	      return NULL;
	    }

	  if (grapple_thread_mutex_trylock(grapple_lobbyclient_head->inuse,
					   GRAPPLE_LOCKTYPE_EXCLUSIVE)==0)
	    {
	      grapple_thread_mutex_unlock(lobbyclient_mutex);
	      return grapple_lobbyclient_head;
	    }

	  if (grapple_lobbyclient_head->threaddestroy)
	    {
	      //It is in the process of being destroyed, we cant use it
	      //and in all likelyhood we are trying to call it
	      //from inside the dispatcher
	      grapple_thread_mutex_unlock(lobbyclient_mutex);
	      return NULL;
	    }

	  grapple_thread_mutex_unlock(lobbyclient_mutex);
	}
      else
	{
	  grapple_thread_mutex_lock(lobbyclient_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);

	  //Loop through the lobbyclients
	  scan=grapple_lobbyclient_head;

	  found=0;

	  while (scan && !found)
	    {
	      if (scan->lobbyclientnum==num)
		{
		  if (grapple_thread_mutex_trylock(scan->inuse,
						   GRAPPLE_LOCKTYPE_EXCLUSIVE)==0)
		    {
		      //Match and return it
		      grapple_thread_mutex_unlock(lobbyclient_mutex);
		      return scan;
		    }
		  //It is in use, we cant use it yet

		  if (scan->threaddestroy)
		    {
		      //It is in the process of being destroyed, we cant use it
		      //and in all likelyhood we are trying to call it
		      //from inside the dispatcher
		      grapple_thread_mutex_unlock(lobbyclient_mutex);
		      return NULL;
		    }

		  //Mark it as found though so we dont exit
		  found=1;
		}
      
	      scan=scan->next;
	      if (scan==grapple_lobbyclient_head)
		scan=NULL;
	    }

	  grapple_thread_mutex_unlock(lobbyclient_mutex);

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

static void internal_lobbyclient_release(internal_lobbyclient_data *target)
{
  //We dont need to mutex this, we definitely HAVE it, and we are just
  //releasing it, and it wont be referenced again - it cant be deleted like
  //this

  grapple_thread_mutex_unlock(target->inuse);
}

static void grapple_lobbyclient_error_set(internal_lobbyclient_data *lobbyclientdata,
					  grapple_error error)
{
  lobbyclientdata->last_error=error;
}

static int init_lobbyclient_mutex(void)
{
  static int done=0;

  if (done==1)
    return 1;
  done=1;

  lobbyclient_mutex=grapple_thread_mutex_init();

  return 1;
}

//Create a new lobbyclient
static internal_lobbyclient_data *lobbyclient_create(void)
{
  static int nextval=256;
  internal_lobbyclient_data *lobbyclientdata;

  //Create the structure
  lobbyclientdata=(internal_lobbyclient_data *)calloc(1,sizeof(internal_lobbyclient_data));

  //Assign it a default ID
  lobbyclientdata->lobbyclientnum=nextval++;

  //Set up the mutexes
  lobbyclientdata->userlist_mutex=grapple_thread_mutex_init();
  lobbyclientdata->message_mutex=grapple_thread_mutex_init();
  lobbyclientdata->games_mutex=grapple_thread_mutex_init();
  lobbyclientdata->callback_mutex=grapple_thread_mutex_init();
  lobbyclientdata->inuse=grapple_thread_mutex_init();

  return lobbyclientdata;
}


//User function for initialising the lobbyclient
grapple_lobbyclient grapple_lobbyclient_init(const char *name,const char *version)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbyclient returnval;

  init_lobbyclient_mutex();

  //Create the internal data
  lobbyclientdata=lobbyclient_create();

  lobbyclientdata->client=grapple_client_init(name,version);

  returnval=lobbyclientdata->lobbyclientnum;

  //Link it into the array of lobbies
  internal_lobbyclient_link(lobbyclientdata);

  //Return the client ID - the end user only gets an integer, called a
  //'grapple_lobbyclient'

  return returnval;
}

//Set the port number to connect to
int grapple_lobbyclient_port_set(grapple_lobbyclient lobbyclient,int port)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Set this in grapple
  returnval=grapple_client_port_set(lobbyclientdata->client,port);
  
  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Set the IP address to bind to. This is an optional, if not set, then all
//local addresses are bound to
int grapple_lobbyclient_address_set(grapple_lobbyclient lobbyclient,
				    const char *address)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_NOT_INITIALISED);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_client_address_set(lobbyclientdata->client,address);

  internal_lobbyclient_release(lobbyclientdata);
  
  return returnval;
}


//Set the name of the user.
int grapple_lobbyclient_name_set(grapple_lobbyclient lobbyclient,
				 const char *name)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Connectstatus is a lobby value used to show how connected we are
  if (lobbyclientdata->connectstatus==GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_CONNECTED)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  if (lobbyclientdata->name)
    free(lobbyclientdata->name);

  lobbyclientdata->name=(char *)malloc(strlen(name)+1);
  strcpy(lobbyclientdata->name,name);

  returnval=grapple_client_name_set(lobbyclientdata->client,name);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

int grapple_lobbyclient_encryption_enable(grapple_lobbyclient lobbyclient,
					  const char *private_key,
					  const char *private_key_password,
					  const char *public_key,
					  const char *cert_auth)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_client_encryption_enable(lobbyclientdata->client,
					     private_key,
					     private_key_password,
					     public_key,
					     cert_auth);

  internal_lobbyclient_release(lobbyclientdata);
  
  return returnval;
}


//Set the user's game key.
int grapple_lobbyclient_protectionkey_set(grapple_lobbyclient lobbyclient,
					  const char *protectionkey)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Connectstatus is a lobby value used to show how connected we are
  if (lobbyclientdata->connectstatus==GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_CONNECTED)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_client_protectionkey_set(lobbyclientdata->client,protectionkey);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Set the password of the user.
int grapple_lobbyclient_password_set(grapple_lobbyclient lobbyclient,
				     const char *password)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Connectstatus is a lobby value used to show how connected we are
  if (lobbyclientdata->connectstatus!=GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_DISCONNECTED)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  if (lobbyclientdata->password)
    free(lobbyclientdata->password);

  lobbyclientdata->password=(char *)malloc(strlen(password)+1);
  strcpy(lobbyclientdata->password,password);

  returnval=grapple_client_password_set(lobbyclientdata->client,password);

  internal_lobbyclient_release(lobbyclientdata);
  
  return returnval;
}

char *grapple_lobbyclient_name_get(grapple_lobbyclient lobbyclient,
				   grapple_user userid)
{
  internal_lobbyclient_data *lobbyclientdata;
  char *returnval;

  //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  returnval=grapple_client_name_get(lobbyclientdata->client,userid);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Get the top message from the list of messages for the clients attention
grapple_lobbymessage *grapple_lobbyclient_message_pull(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbymessage *message;

 //Get the lobbyclient data
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbyclientdata->messages)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_NO_MESSAGES);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  //Get the message at the top of the queue
  grapple_thread_mutex_lock(lobbyclientdata->message_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  message=lobbyclientdata->messages;

  //Unlink it from the message list
  lobbyclientdata->messages=grapple_lobbymessage_unlink(lobbyclientdata->messages,message);
  grapple_thread_mutex_unlock(lobbyclientdata->message_mutex);

  internal_lobbyclient_release(lobbyclientdata);

  message->next=NULL;
  message->prev=NULL;

  return message;
}

//A message is going out to the end user, prepare it
static int grapple_lobbyclient_process_message(internal_lobbyclient_data *lobbyclientdata,
					       grapple_lobbymessage *message)
{
  //handle callbacks, we are in a thread so we can just do it
  if (grapple_lobbyclient_callback_process(lobbyclientdata,message))
    {
      return 0;
    }

  //If not a callback, add it to the users message queue
  grapple_thread_mutex_lock(lobbyclientdata->message_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  lobbyclientdata->messages=grapple_lobbymessage_link(lobbyclientdata->messages,message);

  grapple_thread_mutex_unlock(lobbyclientdata->message_mutex);
  
  return 0;
}

//Received a chat message from another user
static int grapple_lobbyclient_process_lobbymsg_chat(internal_lobbyclient_data *lobbyclientdata,
						     grapple_message *message)
{
  void *data;
  size_t length;
  grapple_lobbymessage *outmessage;

  length=message->USER_MSG.length-4;
  data=(char *)message->USER_MSG.data+4;

  if (length ==0)
    return 0;

  //Decode the message into a lobbymessage

  outmessage=grapple_lobbymessage_aquire();
  
  outmessage->type=GRAPPLE_LOBBYMSG_CHAT;
  outmessage->CHAT.id=message->USER_MSG.id;
  outmessage->CHAT.length=length;
  outmessage->CHAT.message=(char *)malloc(length+1);
  memcpy(outmessage->CHAT.message,data,length);
  outmessage->CHAT.message[length]=0;

  //Send it to the outbound message processor
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//Received a chat message from another user
static int grapple_lobbyclient_process_lobbymsg_usermsg(internal_lobbyclient_data *lobbyclientdata,
							grapple_message *message)
{
  void *data;
  size_t length;
  grapple_lobbymessage *outmessage;

  length=message->USER_MSG.length-4;
  data=(char *)message->USER_MSG.data+4;

  if (length < 4)
    return 0;

  //Decode the message into a lobbymessage

  outmessage=grapple_lobbymessage_aquire();
  
  outmessage->type=GRAPPLE_LOBBYMSG_USERMSG;
  outmessage->USERMSG.id=message->USER_MSG.id;
  outmessage->USERMSG.length=length;
  outmessage->USERMSG.data=malloc(length+1);
  memcpy(outmessage->USERMSG.data,data,length);
  *(((char *)outmessage->USERMSG.data)+length)=0;

  //Send it to the outbound message processor
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//A game has been registered
static int grapple_lobbyclient_process_lobbymsg_registergame(internal_lobbyclient_data *lobbyclientdata,
							      grapple_message *message)
{
  void *data;
  size_t length;
  int varlength;
  grapple_lobbymessage *outmessage=NULL;
  size_t offset;
  intchar val;
  grapple_lobbygame_internal *game,*gamescan;

  length=message->USER_MSG.length-4;
  data=(char *)message->USER_MSG.data+4;

  if (length < 4)
    return 0;

  //A new game is now being registered. We need to deconstruct the complex 
  //data packet

  game=grapple_lobbygame_internal_create();

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

  memcpy(val.c,data,4);
  game->id=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  varlength=ntohl(val.i);

  game->session=(char *)malloc(varlength+1);
  memcpy(game->session,(char *)data+8,varlength);
  game->session[varlength]=0;
  offset=varlength+8;

  memcpy(val.c,(char *)data+offset,4);
  varlength=ntohl(val.i);
  offset+=4;

  game->address=(char *)malloc(varlength+1);
  memcpy(game->address,(char *)data+offset,varlength);
  game->address[varlength]=0;
  offset+=varlength;

  memcpy(val.c,(char *)data+offset,4);
  game->port=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->protocol=(grapple_protocol)ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->currentusers=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->maxusers=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->needpassword=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->room=ntohl(val.i);
  offset+=4;

  memcpy(val.c,(char *)data+offset,4);
  game->descriptionlen=ntohl(val.i);
  offset+=4;

  if (game->descriptionlen)
    {
      game->description=(char *)malloc(game->descriptionlen);
      memcpy(game->description,(char *)data+offset,game->descriptionlen);
      offset+=game->descriptionlen;
    }

  memcpy(val.c,(char *)data+offset,4);
  game->closed=ntohl(val.i);
  offset+=4;

  //Check if the game is already there
  gamescan=grapple_lobbyclient_game_internal_get(lobbyclientdata,
						 game->id,
						 GRAPPLE_LOCKTYPE_SHARED);
  if (gamescan)
    {
      grapple_lobbygame_internal_release(gamescan);
      grapple_lobbygame_internal_dispose(game);

      return 0;
    }

  if (game->room==lobbyclientdata->currentroom)
    {
      //Set up a message to tell the player
      outmessage=grapple_lobbymessage_aquire();
      
      outmessage->type=GRAPPLE_LOBBYMSG_NEWGAME;
      outmessage->GAME.id=game->id;
      outmessage->GAME.name=(char *)malloc(strlen(game->session)+1);
      strcpy(outmessage->GAME.name,game->session);
      outmessage->GAME.currentusers=game->currentusers;
      outmessage->GAME.maxusers=game->maxusers;
      outmessage->GAME.closed=game->closed;
      outmessage->GAME.needpassword=game->needpassword;
      outmessage->GAME.descriptionlen=game->descriptionlen;
      if (game->descriptionlen)
	{
	  outmessage->GAME.description=(char *)malloc(game->descriptionlen);
	  memcpy(outmessage->GAME.description,game->description,
		 game->descriptionlen);
	}
    }


  //Now link the game into the list
  grapple_thread_mutex_lock(lobbyclientdata->games_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  lobbyclientdata->games=grapple_lobbygame_internal_link(lobbyclientdata->games,game);
  grapple_thread_mutex_unlock(lobbyclientdata->games_mutex);

  if (outmessage)
    //Send the players message to the outbound message processor
    grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//A game has been deleted
static int grapple_lobbyclient_process_lobbymsg_deletegame(internal_lobbyclient_data *lobbyclientdata,
							      grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  grapple_lobbymessage *outmessage=NULL;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);

  gameid=ntohl(val.i);

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
				      gameid,GRAPPLE_LOCKTYPE_EXCLUSIVE);
 
 //Locate the game
  if (game)
    {
      //Unlink it from the game list
      grapple_thread_mutex_lock(lobbyclientdata->games_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      lobbyclientdata->games=grapple_lobbygame_internal_unlink(lobbyclientdata->games,game);
      grapple_thread_mutex_unlock(lobbyclientdata->games_mutex);

      grapple_lobbygame_internal_release(game);

      if (game->room == lobbyclientdata->currentroom)
	{
	  //Set up a message to tell the player
	  outmessage=grapple_lobbymessage_aquire();
	  
	  outmessage->type=GRAPPLE_LOBBYMSG_DELETEGAME;
	  outmessage->GAME.id=game->id;
	  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
	}

      //Delete it, its dead
      grapple_lobbygame_internal_dispose(game);
    }

  return 0;
}

//The server has sent us an ID for the game we have just started
static int grapple_lobbyclient_process_lobbymsg_yourgameid(internal_lobbyclient_data *lobbyclientdata,
							   grapple_message *message)
{
  void *data;
  size_t length;
  intchar val;

  length=message->USER_MSG.length-4;
  data=(char *)message->USER_MSG.data+4;

  if (length < 4)
    return 0;

  //Set the internal game ID
  memcpy(val.c,data,4);
  lobbyclientdata->gameid=ntohl(val.i);

  return 0;
}

//The number of users connected to a game has changed
static int grapple_lobbyclient_process_lobbymsg_game_usercount(internal_lobbyclient_data *lobbyclientdata,
							       grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  int count;
  grapple_lobbymessage *outmessage;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  count=ntohl(val.i);

  //Find the game
  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
				      gameid,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (game)
    {
      //Set its new user value
      game->currentusers=count;
      
      grapple_lobbygame_internal_release(game);

      //Send the data to the user
      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_GAME_USERS;
      outmessage->GAME.id=gameid;
      outmessage->GAME.currentusers=count;
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }

  return 0;
}

//The maximum number of users that can connect to a game has changed
static int grapple_lobbyclient_process_lobbymsg_game_maxusercount(internal_lobbyclient_data *lobbyclientdata,
								  grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  int count;
  grapple_lobbymessage *outmessage;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  count=ntohl(val.i);

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
				      gameid,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (game)
    {
      ////Set the new value
      game->maxusers=count;
      
      grapple_lobbygame_internal_release(game);

      //Tell the user
      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_GAME_MAXUSERS;
      outmessage->GAME.id=gameid;
      outmessage->GAME.maxusers=count;
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }

  return 0;
}

//The games open/closed status has changed
static int grapple_lobbyclient_process_lobbymsg_game_closed(internal_lobbyclient_data *lobbyclientdata,
							    grapple_message *message)
{
  intchar val;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;
  int state;
  grapple_lobbymessage *outmessage;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  state=ntohl(val.i);

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
				      gameid,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (game)
    {
      ////Set the new value
      game->closed=state;
      
      grapple_lobbygame_internal_release(game);

      //Tell the user
      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_GAME_CLOSED;
      outmessage->GAME.id=gameid;
      outmessage->GAME.closed=state;
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }

  return 0;
}

static int grapple_lobbyclient_process_lobbymsg_user_joinedgame(internal_lobbyclient_data *lobbyclientdata,
							    grapple_message *message)
{
  intchar val;
  grapple_lobbymessage *outmessage;

  //Tell the user
  outmessage=grapple_lobbymessage_aquire();
  outmessage->type=GRAPPLE_LOBBYMSG_USER_JOINEDGAME;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  outmessage->USERGAME.gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  outmessage->USERGAME.userid=ntohl(val.i);

  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

static int grapple_lobbyclient_process_lobbymsg_user_leftgame(internal_lobbyclient_data *lobbyclientdata,
							      grapple_message *message)
{
  intchar val;
  grapple_lobbymessage *outmessage;

  //Tell the user
  outmessage=grapple_lobbymessage_aquire();
  outmessage->type=GRAPPLE_LOBBYMSG_USER_LEFTGAME;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  outmessage->USERGAME.gameid=ntohl(val.i);

  memcpy(val.c,(char *)message->USER_MSG.data+8,4);
  outmessage->USERGAME.userid=ntohl(val.i);

  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

static int grapple_lobbyclient_process_lobbymsg_game_description(internal_lobbyclient_data *lobbyclientdata,
								 grapple_message *message)
{
  intchar val;
  grapple_lobbymessage *outmessage;
  grapple_lobbygameid gameid;
  grapple_lobbygame_internal *game;

  memcpy(val.c,(char *)message->USER_MSG.data+4,4);
  gameid=ntohl(val.i);

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
				      gameid,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (game)
    {
      ////Set the new value
      game->descriptionlen=message->USER_MSG.length-8;
      if (game->description)
	free(game->description);

      if (game->descriptionlen)
	{
	  game->description=(char *)malloc(game->descriptionlen);
	  memcpy(game->description,(char *)message->USER_MSG.data+8,
		 game->descriptionlen);
	}
      else
	game->description=NULL;
      
      grapple_lobbygame_internal_release(game);

      //Tell the user
      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_GAME_DESCRIPTION;
      
      outmessage->GAME.id=gameid;
      
      outmessage->GAME.description=(void *)malloc(message->USER_MSG.length-8);
      memcpy(outmessage->GAME.description,(char *)message->USER_MSG.data+8,
	     message->USER_MSG.length-8);
      
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }


  return 0;
}

//A user message has come through. User messages are what are contains the
//lobby specific messages, for the protocol that the lobby uses ontop of
//grapple
static int grapple_lobbyclient_process_user_msg(internal_lobbyclient_data *lobbyclientdata,
						grapple_message *message)
{
  grapple_lobbymessagetype_internal type;
  intchar val;

  //User message - break it into its components

  if (message->USER_MSG.length < 4)
    return 0;

  //Find the type of message
  memcpy(val.c,message->USER_MSG.data,4);
  type=(grapple_lobbymessagetype_internal)ntohl(val.i);

  //Hand off the message to a sub-handler
  switch (type)
    {
    case GRAPPLE_LOBBYMESSAGE_YOURGAMEID:
      grapple_lobbyclient_process_lobbymsg_yourgameid(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_CHAT:
      grapple_lobbyclient_process_lobbymsg_chat(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_REGISTERGAME:
      grapple_lobbyclient_process_lobbymsg_registergame(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_DELETEGAME:
      grapple_lobbyclient_process_lobbymsg_deletegame(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_USERCOUNT:
      grapple_lobbyclient_process_lobbymsg_game_usercount(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_MAXUSERCOUNT:
      grapple_lobbyclient_process_lobbymsg_game_maxusercount(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_CLOSED:
      grapple_lobbyclient_process_lobbymsg_game_closed(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_USERMSG:
      grapple_lobbyclient_process_lobbymsg_usermsg(lobbyclientdata,message);
      break;
    case GRAPPLE_LOBBYMESSAGE_USER_JOINEDGAME:
      grapple_lobbyclient_process_lobbymsg_user_joinedgame(lobbyclientdata,
							   message);
      break;
    case GRAPPLE_LOBBYMESSAGE_USER_LEFTGAME:
      grapple_lobbyclient_process_lobbymsg_user_leftgame(lobbyclientdata,
							 message);
      break;
    case GRAPPLE_LOBBYMESSAGE_GAME_DESCRIPTION:
      grapple_lobbyclient_process_lobbymsg_game_description(lobbyclientdata,
							    message);
      break;
    case GRAPPLE_LOBBYMESSAGE_REQUEST_GAMELIST:
      //Never received by client
      break;
    }
  
  return 0;
}

//A new user has connected
static int grapple_lobbyclient_process_new_user(internal_lobbyclient_data *lobbyclientdata,
						grapple_message *message)
{
  grapple_lobbyconnection *newuser;
  grapple_lobbymessage *outmessage;
  intchar val;

  if (message->NEW_USER.me)
    {
      //If it is us, set our server id
      lobbyclientdata->serverid=message->NEW_USER.id;

      //Set the connectstatus to 'connected'
      lobbyclientdata->connectstatus=GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_CONNECTED;

      //Now request the list of games from the lobby server

      val.i=htonl(GRAPPLE_LOBBYMESSAGE_REQUEST_GAMELIST);

      grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,val.c,4);
    }

  //Create the users local data
  newuser=grapple_lobbyconnection_create();

  newuser->id=message->NEW_USER.id;

  if (message->NEW_USER.name)
    {
      newuser->name=(char*)malloc(strlen(message->NEW_USER.name)+1);
      strcpy(newuser->name,message->NEW_USER.name);
    }

  
  grapple_thread_mutex_lock(lobbyclientdata->userlist_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  //Link it in
  lobbyclientdata->userlist=grapple_lobbyconnection_link(lobbyclientdata->userlist,newuser);
  grapple_thread_mutex_unlock(lobbyclientdata->userlist_mutex);

  //Now send this message to the client

  //Send the message to the user, letting them know of a new connection
  outmessage=grapple_lobbymessage_aquire();
  
  outmessage->type=GRAPPLE_LOBBYMSG_NEWUSER;
  outmessage->USER.id=newuser->id;
  if (message->NEW_USER.name)
    {
      outmessage->USER.name=message->NEW_USER.name;
      message->NEW_USER.name=NULL;
    }

  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//A group has been created. In the lobby a group is associated with a room
static int grapple_lobbyclient_process_group_create(internal_lobbyclient_data *lobbyclientdata,
						    grapple_message *message)
{
  grapple_lobbymessage *outmessage;

  //Dont inform of main room creation, its not required
  if (message->GROUP.groupid == lobbyclientdata->firstroom)
    return 0;

  if (lobbyclientdata->currentroom!=0)
    {
      //Inform the user

      outmessage=grapple_lobbymessage_aquire();
      
      outmessage->type=GRAPPLE_LOBBYMSG_ROOMCREATE;
      
      outmessage->ROOM.roomid=message->GROUP.groupid;
      outmessage->ROOM.name=message->GROUP.name;
      message->GROUP.name=NULL;
      
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }

  return 0;
}

//Someone has joined a group. In effect, they have 'joined the room'
static int grapple_lobbyclient_process_group_add(internal_lobbyclient_data *lobbyclientdata,
						 grapple_message *message)
{
  grapple_lobbymessage *outmessage;

  //If it is us
  if (message->GROUP.memberid == lobbyclientdata->serverid)
    {
      //If it is our first join
      if (lobbyclientdata->currentroom==0)
	{
	  //Note this as the main room
	  lobbyclientdata->firstroom=message->GROUP.groupid;
	}

      //Now set our current room to here
      lobbyclientdata->currentroom=message->GROUP.groupid;
    }
      
  if (message->GROUP.groupid!=lobbyclientdata->currentroom)
    //The message isnt in the room we are in, we dont care
    return 0;

  outmessage=grapple_lobbymessage_aquire();
  
  outmessage->type=GRAPPLE_LOBBYMSG_ROOMENTER;

  outmessage->ROOM.userid=message->GROUP.memberid;

  //Send the message to the user
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//Someone has left a room
static int grapple_lobbyclient_process_group_remove(internal_lobbyclient_data *lobbyclientdata,
						    grapple_message *message)
{
  grapple_lobbymessage *outmessage;

  //If it isnt our room, we dont care
  if (message->GROUP.groupid!=lobbyclientdata->currentroom)
    return 0;

  //Send a message to the user
  outmessage=grapple_lobbymessage_aquire();
  
  outmessage->type=GRAPPLE_LOBBYMSG_ROOMLEAVE;

  outmessage->ROOM.userid=message->GROUP.memberid;

  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//A room has been deleted
static int grapple_lobbyclient_process_group_delete(internal_lobbyclient_data *lobbyclientdata,
						    grapple_message *message)
{
  grapple_lobbymessage *outmessage;

  //Only get room delete messages from the first room
  if (lobbyclientdata->currentroom != lobbyclientdata->firstroom)
    return 0;

  outmessage=grapple_lobbymessage_aquire();
  
  outmessage->type=GRAPPLE_LOBBYMSG_ROOMDELETE;

  outmessage->ROOM.roomid=message->GROUP.groupid;

  outmessage->ROOM.name=message->GROUP.name;
  message->GROUP.name=NULL;

  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//Connection was refused - probably becuse we have a non-unique name
static int grapple_lobbyclient_process_connection_refused(internal_lobbyclient_data *lobbyclientdata,
							  grapple_message *message)
{
  grapple_lobbymessage *outmessage;

  //Set the status - we are in a callback thread here, so in the main
  //thread, the status is being waited on.

  //Set the error depending on why connection is refused

  lobbyclientdata->connectstatus=GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_DISCONNECTED;

  //Send the user a message to let them know
  outmessage=grapple_lobbymessage_aquire();
  outmessage->type=GRAPPLE_LOBBYMSG_CONNECTION_REFUSED;
  outmessage->CONNECTION_REFUSED.reason=message->CONNECTION_REFUSED.reason;
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//A user has disconected
static int grapple_lobbyclient_process_user_disconnected(internal_lobbyclient_data *lobbyclientdata,
							 grapple_message *message)
{
  grapple_lobbyconnection *user;
  grapple_lobbymessage *outmessage;

  grapple_thread_mutex_lock(lobbyclientdata->userlist_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  //Remove them from the userlist
  user=grapple_lobbyconnection_locate_by_id(lobbyclientdata->userlist,
					    message->USER_DISCONNECTED.id);
  if (user)
    lobbyclientdata->userlist=grapple_lobbyconnection_unlink(lobbyclientdata->userlist,user);

  grapple_thread_mutex_unlock(lobbyclientdata->userlist_mutex);


  //Is it us?
  if (message->USER_DISCONNECTED.id==lobbyclientdata->serverid)
    {
      //Let the user know we're disconnected
      if (lobbyclientdata->connectstatus == GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_PENDING)
	lobbyclientdata->connectstatus = GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_REJECTED;

      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_DISCONNECTED;
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }
  else
    {
      //Send a user_disconnected message
      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_USER_DISCONNECTED;
      outmessage->USER.id=message->USER_DISCONNECTED.id;
      
      //send the user the information
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }

  //Get rid of the disconnected user
  if (user)
    grapple_lobbyconnection_dispose(user);

  return 0;
}

//The server has disconnected, this is the whole lobby going
static int grapple_lobbyclient_process_server_disconnected(internal_lobbyclient_data *lobbyclientdata,
							   grapple_message *message)
{
  grapple_lobbymessage *outmessage;

  if (lobbyclientdata->connectstatus == GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_PENDING)
    lobbyclientdata->connectstatus = GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_REJECTED;


  //Send the user a message and let them handle cleanup  
  outmessage=grapple_lobbymessage_aquire();
  outmessage->type=GRAPPLE_LOBBYMSG_DISCONNECTED;
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return 0;
}

//All messages from grapple and sent here as callbacks to be distributed to
//subfinctions
static int grapple_lobbyclient_generic_callback(grapple_message *message,
						void *context)
{
  internal_lobbyclient_data *lobbyclientdata;

  lobbyclientdata=(internal_lobbyclient_data *)context;

  //Send the message to a handler
  switch (message->type)
    {
    case GRAPPLE_MSG_NEW_USER:
    case GRAPPLE_MSG_NEW_USER_ME:
      grapple_lobbyclient_process_new_user(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_USER_MSG:
      grapple_lobbyclient_process_user_msg(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_GROUP_CREATE:
      grapple_lobbyclient_process_group_create(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_GROUP_ADD:
      grapple_lobbyclient_process_group_add(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_GROUP_REMOVE:
      grapple_lobbyclient_process_group_remove(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_GROUP_DELETE:
      grapple_lobbyclient_process_group_delete(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_CONNECTION_REFUSED:
      grapple_lobbyclient_process_connection_refused(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_USER_DISCONNECTED:
      grapple_lobbyclient_process_user_disconnected(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_SERVER_DISCONNECTED:
      grapple_lobbyclient_process_server_disconnected(lobbyclientdata,message);
      break;
    case GRAPPLE_MSG_USER_NAME:
    case GRAPPLE_MSG_SESSION_NAME:
    case GRAPPLE_MSG_CONFIRM_RECEIVED:
    case GRAPPLE_MSG_CONFIRM_TIMEOUT:
    case GRAPPLE_MSG_YOU_ARE_HOST:
    case GRAPPLE_MSG_PING:
    case GRAPPLE_MSG_GAME_DESCRIPTION: //Not used by lobby
      //Dont care about these
      break;
    case GRAPPLE_MSG_NONE:
      //Never received, default NULL value
      break;
    }

  grapple_message_dispose(message);

  return 0;
}

//Start the lobbyclient
int grapple_lobbyclient_start(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval,finished,count;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);


  //Check the lobbyclients minimum defaults are set
  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  ////The name isnt set, cant connect to the lobby without a name
  if (!lobbyclientdata->name)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_NAME_NOT_SET);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Set the grapple details for connecting to the lobby using grapple
  grapple_client_protocol_set(lobbyclientdata->client,GRAPPLE_PROTOCOL_TCP);

  grapple_client_callback_setall(lobbyclientdata->client,
				 grapple_lobbyclient_generic_callback,
				 (void *)lobbyclientdata);


  //now set their connection status to pending
  lobbyclientdata->connectstatus=GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_PENDING;

  //Start the client
  returnval=grapple_client_start(lobbyclientdata->client,GRAPPLE_WAIT);

  if (returnval!=GRAPPLE_OK)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    grapple_client_error_get(lobbyclientdata->client));
      internal_lobbyclient_release(lobbyclientdata);
      return returnval;
    }

  grapple_client_sequential_set(lobbyclientdata->client,GRAPPLE_SEQUENTIAL);

  //Connection status:

  //This will be changed in a callback that is run in the grapple
  //callback thread, so we just wait for it to change
  
  //We have to re-hunt for the data though, as we MUST release the mutex or the
  //other thread cannot load the data, and as we have lost the mutex, we
  //must then re-gain the data safely
  internal_lobbyclient_release(lobbyclientdata);

  finished=0;
  count=0;

  while (!finished)
    {
      lobbyclientdata=internal_lobbyclient_get(lobbyclient);

      //Check the lobbyclients minimum defaults are set
      if (!lobbyclientdata)
	{
	  grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
	  return GRAPPLE_FAILED;
	}

      if (!lobbyclientdata->client)
	{
	  internal_lobbyclient_release(lobbyclientdata);
	  return GRAPPLE_FAILED;
	}

      if (lobbyclientdata->connectstatus == GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_PENDING &&
	 grapple_client_connected(lobbyclientdata->client))
	{
	  //release before the sleep
	  internal_lobbyclient_release(lobbyclientdata);

	  microsleep(10000);
	  count++;
	  if (count>10000)
	    {
	      //Spent over 100 seconds waiting, it cannot take that long
	      //reasonably, bail
	      lobbyclientdata=internal_lobbyclient_get(lobbyclient);
	      if (lobbyclientdata)
		{
		  grapple_lobbyclient_error_set(lobbyclientdata,
						GRAPPLE_ERROR_CANNOT_CONNECT);
		  internal_lobbyclient_release(lobbyclientdata);
		}
	      return GRAPPLE_FAILED;
	    }
	}
      else
	{
	  finished=1;
	  internal_lobbyclient_release(lobbyclientdata);
	}
    }

  //Here we go again with a value affected by a different thread
  finished=0;
  count=0;
  while (!finished)
    {
      lobbyclientdata=internal_lobbyclient_get(lobbyclient);

      //Check the lobbyclients minimum defaults are set
      if (!lobbyclientdata)
	{
	  grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
	  return GRAPPLE_FAILED;
	}

      if (!lobbyclientdata->client)
	{
	  internal_lobbyclient_release(lobbyclientdata);
	  return GRAPPLE_FAILED;
	}

      if (lobbyclientdata->connectstatus!=GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_CONNECTED)
	{
	  internal_lobbyclient_release(lobbyclientdata);
	  finished=1;
	}
      else
	{
	  //Its connected, wait for the room
	  if (lobbyclientdata->firstroom==0)
	    {
	      internal_lobbyclient_release(lobbyclientdata);
	      microsleep(10000);
	      count++;
	      if (count>10000)
		{
		  //Spent over 100 seconds waiting, it cannot take that long
		  //reasonably, bail
		  lobbyclientdata=internal_lobbyclient_get(lobbyclient);
		  if (lobbyclientdata)
		    {
		      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CANNOT_CONNECT);
		      internal_lobbyclient_release(lobbyclientdata);
		    }
		  return GRAPPLE_FAILED;
		}
	    }
	  else
	    {
	      internal_lobbyclient_release(lobbyclientdata);
	      return GRAPPLE_OK;
	    }
	}
    }

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);
  
  //Check the lobbyclients minimum defaults are set
  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }
  
  if (lobbyclientdata->connectstatus==GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_REJECTED)
    {
      //The name wasnt good, abort the connection
      free(lobbyclientdata->name);
      lobbyclientdata->name=NULL;

      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_NAME_NOT_UNIQUE);
      lobbyclientdata->connectstatus=GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_DISCONNECTED;
    }
  else if (lobbyclientdata->connectstatus==GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_DISCONNECTED)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CANNOT_CONNECT);
    }

  //Stop the client, ready to restart when a new name has been picked
  grapple_client_stop(lobbyclientdata->client);

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_FAILED;
}

//Destroy the lobbyclient
int grapple_lobbyclient_destroy(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame_internal *gametarget;
  grapple_lobbyconnection *connection;
  grapple_lobbymessage *message;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //If we have a thread, close it first
  if (lobbyclientdata->thread)
    {
      lobbyclientdata->threaddestroy=1;

      while (lobbyclientdata && lobbyclientdata->threaddestroy)
	{
	  internal_lobbyclient_release(lobbyclientdata);
	  microsleep(10000);
	  lobbyclientdata=internal_lobbyclient_get(lobbyclient);
	}
    }

  //It could have been otherwise destroyed
  if (!lobbyclientdata)
    { 
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //finish the grapple client
  if (lobbyclientdata->client)
    grapple_client_destroy(lobbyclientdata->client);

  //Remove this client from the list of lobby clients
  internal_lobbyclient_unlink(lobbyclientdata);

  internal_lobbyclient_release(lobbyclientdata);

  //Unlink all the games
  grapple_thread_mutex_lock(lobbyclientdata->games_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  while (lobbyclientdata->games)
    {
      gametarget=lobbyclientdata->games;
      lobbyclientdata->games=grapple_lobbygame_internal_unlink(lobbyclientdata->games,lobbyclientdata->games);
      grapple_thread_mutex_lock(gametarget->inuse,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      //Now just unlock it, we have exclusive ownership, and nobody else can
      //get it cos its not in the list any more
      grapple_thread_mutex_unlock(gametarget->inuse);
      grapple_lobbygame_internal_dispose(gametarget);
    }
  grapple_thread_mutex_unlock(lobbyclientdata->games_mutex);

  //Unlink all the users
  grapple_thread_mutex_lock(lobbyclientdata->userlist_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  while (lobbyclientdata->userlist)
    {
      connection=lobbyclientdata->userlist;
      lobbyclientdata->userlist=grapple_lobbyconnection_unlink(lobbyclientdata->userlist,
						    lobbyclientdata->userlist);
      grapple_lobbyconnection_dispose(connection);
    }
  grapple_thread_mutex_unlock(lobbyclientdata->userlist_mutex);

  //Unlink all the remaining incoming messages
  grapple_thread_mutex_lock(lobbyclientdata->message_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  while (lobbyclientdata->messages)
    {
      message=lobbyclientdata->messages;
      lobbyclientdata->messages=grapple_lobbymessage_unlink(lobbyclientdata->messages,
						 lobbyclientdata->messages);
      grapple_lobbymessage_dispose(message);
    }
  grapple_thread_mutex_unlock(lobbyclientdata->message_mutex);

  //Unlink all the remaining callbacks
  grapple_thread_mutex_lock(lobbyclientdata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  while (lobbyclientdata->callbacks)
    {
      lobbyclientdata->callbacks=grapple_lobbycallback_remove(lobbyclientdata->callbacks,
							      lobbyclientdata->callbacks->type);
    }
  grapple_thread_mutex_unlock(lobbyclientdata->callback_mutex);

  grapple_thread_mutex_destroy(lobbyclientdata->callback_mutex);
  grapple_thread_mutex_destroy(lobbyclientdata->userlist_mutex);
  grapple_thread_mutex_destroy(lobbyclientdata->message_mutex);
  grapple_thread_mutex_destroy(lobbyclientdata->games_mutex);
  grapple_thread_mutex_destroy(lobbyclientdata->inuse);

  if (lobbyclientdata->name)
    free(lobbyclientdata->name);

  if (lobbyclientdata->currentroompassword)
    free(lobbyclientdata->currentroompassword);
  
  free(lobbyclientdata);
  
  return GRAPPLE_OK;
}

//Create a room in the lobby. All rooms require someone to be in them,
//so creating a room will also move the user into it.
int grapple_lobbyclient_room_create(grapple_lobbyclient lobbyclient,
				    const char *name,const char *password)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbyconnection *user;
  grapple_user group;
  grapple_lobbymessage *outmessage;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Find if the group is already made
  group=grapple_client_group_from_name(lobbyclientdata->client,name);

  if (!group)
    //Create a group if it isnt there
    group=grapple_client_group_create(lobbyclientdata->client,name,password);

  //Move the player into the group (new room)
  if (grapple_client_group_add(lobbyclientdata->client,group,lobbyclientdata->serverid,password) 
      ==
      GRAPPLE_FAILED)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //If they have a room already
  if (lobbyclientdata->currentroom)
    //Move them out of it
    grapple_client_group_remove(lobbyclientdata->client,lobbyclientdata->currentroom,
                                lobbyclientdata->serverid);

  lobbyclientdata->currentroom=group;

  if (lobbyclientdata->currentroompassword)
    {
      free(lobbyclientdata->currentroompassword);
      lobbyclientdata->currentroompassword=0;
    }

  if (password && *password)
    {
      lobbyclientdata->currentroompassword=(char *)malloc(strlen(password)+1);
      strcpy(lobbyclientdata->currentroompassword,password);
    }

  //Set the current room of the user
  grapple_thread_mutex_lock(lobbyclientdata->userlist_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(lobbyclientdata->userlist,
                                            lobbyclientdata->serverid);
  if (user)
    user->currentroom=lobbyclientdata->currentroom;
  grapple_thread_mutex_unlock(lobbyclientdata->userlist_mutex);
 
  internal_lobbyclient_release(lobbyclientdata);
 
  //Send a room leave message to ourself
  outmessage=grapple_lobbymessage_aquire();
  outmessage->type=GRAPPLE_LOBBYMSG_ROOMENTER;
  outmessage->ROOM.userid=lobbyclientdata->serverid;
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  return GRAPPLE_OK;
}

//Enter an existing room
int grapple_lobbyclient_room_enter(grapple_lobbyclient lobbyclient,
				   grapple_lobbyroomid group,
				   const char *password)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbyconnection *user;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Move the player into the new group (room)
  if (grapple_client_group_add(lobbyclientdata->client,group,lobbyclientdata->serverid,
			       password) == GRAPPLE_FAILED)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Move out of the current room
  if (lobbyclientdata->currentroom)
    grapple_client_group_remove(lobbyclientdata->client,lobbyclientdata->currentroom,
                                lobbyclientdata->serverid);

  lobbyclientdata->currentroom=group;

  if (lobbyclientdata->currentroompassword)
    {
      free(lobbyclientdata->currentroompassword);
      lobbyclientdata->currentroompassword=0;
    }

  if (password && *password)
    {
      lobbyclientdata->currentroompassword=(char *)malloc(strlen(password)+1);
      strcpy(lobbyclientdata->currentroompassword,password);
    }

  grapple_thread_mutex_lock(lobbyclientdata->userlist_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(lobbyclientdata->userlist,
					    lobbyclientdata->serverid);
  if (user)
    user->currentroom=lobbyclientdata->currentroom;
  grapple_thread_mutex_unlock(lobbyclientdata->userlist_mutex);

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}

//Leave a room (return to the main lobby)
int grapple_lobbyclient_room_leave(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbyconnection *user;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //If they are already in the main room, just OK it
  if (lobbyclientdata->firstroom==lobbyclientdata->currentroom)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_OK;
    }

  //Leave the current group, join the main one
  grapple_client_group_remove(lobbyclientdata->client,lobbyclientdata->currentroom,
			      lobbyclientdata->serverid);

  grapple_client_group_add(lobbyclientdata->client,lobbyclientdata->firstroom,
			   lobbyclientdata->serverid,NULL);
  
  lobbyclientdata->currentroom=lobbyclientdata->firstroom;

  //Update the user
  grapple_thread_mutex_lock(lobbyclientdata->userlist_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=grapple_lobbyconnection_locate_by_id(lobbyclientdata->userlist,
					    lobbyclientdata->serverid);
  if (user)
    user->currentroom=lobbyclientdata->currentroom;
  grapple_thread_mutex_unlock(lobbyclientdata->userlist_mutex);

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}

//Leave a room (return to the main lobby)
int grapple_lobbyclient_room_passwordneeded(grapple_lobbyclient lobbyclient,
					    grapple_lobbyroomid roomid)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  returnval=grapple_client_group_passwordneeded(lobbyclientdata->client,roomid);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//send a chat message - a message to everyone in the 'room'
int grapple_lobbyclient_chat(grapple_lobbyclient lobbyclient,
			     const char *message)
{
  internal_lobbyclient_data *lobbyclientdata;
  char *outdata;
  intchar val;
  size_t length;
  
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }


  //Make up the packet
  //4 bytes : protocol
  //4 bytes : message length
  //        : message

  length=strlen(message);

  outdata=(char *)malloc(length+4);

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_CHAT);
  memcpy(outdata,val.c,4);

  memcpy(outdata+4,message,length);

  //Send the message to the current 'room' (group)
  grapple_client_send(lobbyclientdata->client,lobbyclientdata->currentroom,0,outdata,length+4);

  free(outdata);

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}

//Starting a new game via the lobby.
//Here the user passes in a grapple_server that is already running, and the
//lobby extracts the information it requires

grapple_lobbygameid grapple_lobbyclient_game_register(grapple_lobbyclient lobbyclient,
						      grapple_server server)
{
  internal_lobbyclient_data *lobbyclientdata;
  const char *session;
  const char *address;
  int port;
  int maxusers;
  int needpassword;
  grapple_protocol protocol;
  intchar val;
  char *outdata,outdata2[8];
  int finished,count;
  size_t offset,length,sessionlength,addresslength;
  grapple_lobbygameid returnval;
  grapple_lobbymessage *outmessage;
  void *description=NULL;
  size_t descriptionlen=0;
  int rv;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (lobbyclientdata->gameid || lobbyclientdata->ingame)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  //We have been passed a running server - lets find out if it has all the
  //requirements for a lobby game set.
  if (!grapple_server_running(server))
    { 
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_SERVER_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
   }

  port=grapple_server_port_get(server);
  if (!port)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_PORT_NOT_SET);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  protocol=grapple_server_protocol_get(server);
  if (!protocol)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_PROTOCOL_NOT_SET);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  session=grapple_server_session_get(server);
  if (!session)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_SESSION_NOT_SET);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  //This is optional so no fail
  address=grapple_server_ip_get(server);

  maxusers=grapple_server_maxusers_get(server);

  needpassword=grapple_server_password_required(server);

  //We have all the information we need, now we assemble it into one huge
  //outgoing packet

  //set the length to be:
  length=24; //Ints for lobbyprotocol, port, protocol, maxusers, needpassword
    
  sessionlength=strlen(session);
  length+=(sessionlength+4); //The length of the session plus a length int

  if (address && *address)
    {
      addresslength=strlen(address);
      length+=(addresslength+4); //The length of the address plus a length int
    }
  else
    {
      addresslength=0;
      length+=4;
    }
  
  //Now add the length of the description plus a length int
  rv=grapple_server_description_get(server,description,&descriptionlen);

  while (rv==0)
    {
      if (description)
	free(description);
      description=(void *)malloc(descriptionlen);
      rv=grapple_server_description_get(server,
					description,&descriptionlen);
    }
  
  length+=(descriptionlen+4);
  
  outdata=(char *)malloc(length);

  //Now copy the data into the buffer
  
  //4 bytes : Lobby protocol
  //4 bytes : Session name length
  //        ; Session name
  //4 bytes : Address length
  //        : address (may be 0 bytes)
  //4 bytes : portnumber
  //4 bytes : protocol
  //4 bytes : Maximum number of users
  //4 bytes : Password required (could be 1 byte but lets stick with ints)
  //4 bytes : Description length
  //        : description

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_REGISTERGAME);
  memcpy(outdata,val.c,4);

  val.i=htonl((long)sessionlength);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,session,sessionlength);
  offset=sessionlength+8;

  val.i=htonl((long)addresslength);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  if (addresslength)
    {
      memcpy(outdata+offset,address,addresslength);
      offset+=addresslength;
    }

  val.i=htonl(port);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(protocol);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(maxusers);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl(needpassword);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  val.i=htonl((long)descriptionlen);
  memcpy(outdata+offset,val.c,4);
  offset+=4;

  if (descriptionlen > 0)
    {
      memcpy(outdata+offset,description,descriptionlen);
      offset+=descriptionlen;
    }

  lobbyclientdata->gameid=0;

  //We have the data!
  //Send it to the server
  grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,outdata,length);

  free(outdata);

  //Now wait for this game to appear on the list

  //This is changed via the grapple callback thread so will change
  //while we wait for it

  //We DO have to allow the other threads to obtain the mutex however
  //so we release here and then keep re-finding the data
  internal_lobbyclient_release(lobbyclientdata);

  finished=0;
  count=0;

  while (!finished)
    {
      lobbyclientdata=internal_lobbyclient_get(lobbyclient);

      if (!lobbyclientdata)
	{
	  grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
	  return 0;
	}

      if (lobbyclientdata->gameid==0)
	{
	  internal_lobbyclient_release(lobbyclientdata);
	  microsleep(10000);
	  count++;
	  if (count>10000)
	    {
	      //Spent over 100 seconds waiting, it cannot take that long
	      //reasonably, bail
	      return 0;
	    }
	}
      else
	{
	  internal_lobbyclient_release(lobbyclientdata);
	  finished=1;
	}
    }

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  //Set to -1 means the game creation failed
  if (lobbyclientdata->gameid==-1)
    {
      lobbyclientdata->gameid=0;
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  //start up the subthread that monitors the game and keeps sending messages
  //to the lobby server about number of users etc
  lobbyclientdata->runninggame=server;
  lobbyclientdata->threaddestroy=0;

  //Move the client into the game itself
  lobbyclientdata->ingame=lobbyclientdata->gameid;

  //If they have a room already
  if (lobbyclientdata->currentroom)
    {
      //Move them out of it
      grapple_client_group_remove(lobbyclientdata->client,lobbyclientdata->currentroom,
				  lobbyclientdata->serverid);

      //Send a room leave message to ourself
      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_ROOMLEAVE;
      outmessage->ROOM.userid=lobbyclientdata->serverid;
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }


  fflush(stdout);
  lobbyclientdata->thread=grapple_thread_create(grapple_lobbyclient_serverthread_main,
						(void *)lobbyclientdata);
  if (!lobbyclientdata->thread)
    return 0;

  returnval=lobbyclientdata->gameid;

  //Let the server know that we have joined the game

  //Make up the packet
  //4 bytes : protocol
  //4 bytes : game

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_USER_JOINEDGAME);
  memcpy(outdata2,val.c,4);

  val.i=htonl(lobbyclientdata->gameid);
  memcpy(outdata2+4,val.c,4);

  //Send the message to the server
  grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,outdata2,8);

  internal_lobbyclient_release(lobbyclientdata);

  //Send the client the ID of the game
  return returnval;
}

//Stop running a game on the lobby
int grapple_lobbyclient_game_unregister(grapple_lobbyclient lobbyclient)
{
  char outdata[8];
  internal_lobbyclient_data *lobbyclientdata;
  intchar val;
  grapple_lobbymessage *outmessage;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //If the client isnt running a game, just nod and return
  if (!lobbyclientdata->gameid)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_OK;
    }

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_USER_LEFTGAME);
  memcpy(outdata,val.c,4);

  val.i=htonl(lobbyclientdata->gameid);
  memcpy(outdata+4,val.c,4);

  //Send the message to the server
  grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,outdata,8);

  //If they have a room already
  if (lobbyclientdata->currentroom)
    {
    //Move them back into it
      if (!grapple_client_group_add(lobbyclientdata->client,
				    lobbyclientdata->currentroom,
				    lobbyclientdata->serverid,
				    lobbyclientdata->currentroompassword))
	{
	  //We couldnt move them into their old room, move them into the
	  //main room
	  grapple_client_group_add(lobbyclientdata->client,
				   lobbyclientdata->firstroom,
				   lobbyclientdata->serverid,NULL);
	  lobbyclientdata->currentroom=lobbyclientdata->firstroom;
	}
    }
  else
    {
      grapple_client_group_add(lobbyclientdata->client,
			       lobbyclientdata->firstroom,
			       lobbyclientdata->serverid,NULL);
      lobbyclientdata->currentroom=lobbyclientdata->firstroom;
    }

  //Send a room enter message to ourself
  outmessage=grapple_lobbymessage_aquire();
  outmessage->type=GRAPPLE_LOBBYMSG_ROOMENTER;
  outmessage->ROOM.userid=lobbyclientdata->serverid;
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);

  //Send a message to the server to delete this game
  val.i=htonl(GRAPPLE_LOBBYMESSAGE_DELETEGAME);
  memcpy(outdata,val.c,4);

  val.i=htonl(lobbyclientdata->gameid);
  memcpy(outdata+4,val.c,4);
  
  grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,outdata,8);

  //Reset all game variables
  lobbyclientdata->gameid=0;
  lobbyclientdata->ingame=0;
  lobbyclientdata->runninggame=0;

  //Shutdown the game thread
  if (lobbyclientdata->thread)
    {
      lobbyclientdata->threaddestroy=1;

      //Wait for the thread to finish
      while (lobbyclientdata->threaddestroy)
	microsleep(10000);
    }

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}


//Join a game - we are passed a client which just needs to know where to go
int grapple_lobbyclient_game_join(grapple_lobbyclient lobbyclient,
				  grapple_lobbygameid gameid,
				  grapple_client newclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame_internal *game;
  int returnval;
  char outdata[8],*tmpname;
  intchar val;
  grapple_lobbymessage *outmessage;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Only join one at a time
  if (lobbyclientdata->ingame)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }
  
  //Find the game
  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
				      gameid,GRAPPLE_LOCKTYPE_SHARED);

  if (!game)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_NO_SUCH_GAME);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  if (grapple_client_connected(newclient))
    {
      grapple_lobbygame_internal_release(game);
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_CONNECTED); 
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Set the details on the client we have been passed
  grapple_client_address_set(newclient,game->address);
  grapple_client_port_set(newclient,game->port);
  grapple_client_protocol_set(newclient,game->protocol);

  grapple_lobbygame_internal_release(game);

  tmpname=grapple_client_name_get(newclient,grapple_client_serverid_get(newclient));
  if (tmpname)
    free(tmpname);
  else
    grapple_client_name_set(newclient,lobbyclientdata->name);

  //Actually connect the client and return the return value
  returnval=grapple_client_start(newclient,GRAPPLE_WAIT);

  if (returnval!=GRAPPLE_OK)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CANNOT_CONNECT); 
      internal_lobbyclient_release(lobbyclientdata);
      return returnval;
    }

  lobbyclientdata->joinedgame=newclient;

  //start up the subthread that monitors the game sends message to the lobby
  //if the client disconnects
  lobbyclientdata->threaddestroy=0;

  //Move the client into the game itself
  lobbyclientdata->ingame=gameid;

  //If they have a room already
  if (lobbyclientdata->currentroom)
    {
      //Move them out of it
      grapple_client_group_remove(lobbyclientdata->client,
				  lobbyclientdata->currentroom,
				  lobbyclientdata->serverid);

      //Send a room leave message to ourself
      outmessage=grapple_lobbymessage_aquire();
      outmessage->type=GRAPPLE_LOBBYMSG_ROOMLEAVE;
      outmessage->ROOM.userid=lobbyclientdata->serverid;
      grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
    }


  lobbyclientdata->thread=grapple_thread_create(grapple_lobbyclient_clientthread_main,
						(void *)lobbyclientdata);

  if (!lobbyclientdata->thread)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_INSUFFICIENT_SPACE); 
      
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  //Let the server know that we have joined the game

  //Make up the packet
  //4 bytes : protocol
  //4 bytes : game

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_USER_JOINEDGAME);
  memcpy(outdata,val.c,4);

  val.i=htonl(gameid);
  memcpy(outdata+4,val.c,4);

  //Send the message to the server
  grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,outdata,8);

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}

//Client has told us they have left the game
int grapple_lobbyclient_game_leave(grapple_lobbyclient lobbyclient,
				   grapple_client oldclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;
  intchar val;
  char outdata[8];
  grapple_lobbygameid gameid;
  grapple_lobbymessage *outmessage;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //They werent in one anyway!
  if (!lobbyclientdata->ingame)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_OK;
    }

  lobbyclientdata->joinedgame=0;

  //Just reset the ingame flag  
  gameid=lobbyclientdata->ingame;
  lobbyclientdata->ingame=0;

  //If they have a room already

  if (lobbyclientdata->currentroom)
    {
      //Move them back into it
      if (!grapple_client_group_add(lobbyclientdata->client,
				    lobbyclientdata->currentroom,
				    lobbyclientdata->serverid,
				    lobbyclientdata->currentroompassword))
	{
	  //We couldnt move them into their old room, move them into the
	  //main room
	  grapple_client_group_add(lobbyclientdata->client,
				   lobbyclientdata->firstroom,
				   lobbyclientdata->serverid,NULL);
	  lobbyclientdata->currentroom=lobbyclientdata->firstroom;
	}
    }
  else
    {
      grapple_client_group_add(lobbyclientdata->client,
			       lobbyclientdata->firstroom,
			       lobbyclientdata->serverid,NULL);
      lobbyclientdata->currentroom=lobbyclientdata->firstroom;
    }

  //Send a room enter message to ourself
  outmessage=grapple_lobbymessage_aquire();
  outmessage->type=GRAPPLE_LOBBYMSG_ROOMENTER;
  outmessage->ROOM.userid=lobbyclientdata->serverid;
  grapple_lobbyclient_process_message(lobbyclientdata,outmessage);
  
  //Shutdown the game thread
  if (lobbyclientdata->thread)
    {
      lobbyclientdata->threaddestroy=1;

      //Wait for the thread to finish
      while (lobbyclientdata->threaddestroy)
	microsleep(10000);
    }

  returnval=grapple_client_stop(oldclient);

  val.i=htonl(GRAPPLE_LOBBYMESSAGE_USER_LEFTGAME);
  memcpy(outdata,val.c,4);

  val.i=htonl(gameid);
  memcpy(outdata+4,val.c,4);

  //Send the message to the server
  grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,outdata,8);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Client is sending a message to the server
int grapple_lobbyclient_message_send(grapple_lobbyclient lobbyclient,
				     const void *message,size_t length)
{
  internal_lobbyclient_data *lobbyclientdata;
  char *outdata;
  intchar val;
  
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
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
  grapple_client_send(lobbyclientdata->client,GRAPPLE_SERVER,0,
		      outdata,length+4);

  internal_lobbyclient_release(lobbyclientdata);

  free(outdata);

  return GRAPPLE_OK;
}

//Get the list of all rooms
grapple_lobbyroomid *grapple_lobbyclient_roomlist_get(grapple_lobbyclient
						      lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  int loopa,offset;
  grapple_lobbyroomid *returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  if (!lobbyclientdata->firstroom)
    {
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  //Use the lowlevel grapple function for the list of groups
  returnval=grapple_client_grouplist_get(lobbyclientdata->client);

  if (returnval)
    {
      loopa=0;
      offset=0;
      
      while (returnval[loopa])
	{
	  if (offset)
	    returnval[loopa]=returnval[loopa+1];
	  else
	    {
	      if (returnval[loopa]==lobbyclientdata->firstroom)
		{
		  returnval[loopa]=returnval[loopa+1];
		  offset=1;
		}
	    }
	  loopa++;
	}
    }

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Find the name of a room
char *grapple_lobbyclient_roomname_get(grapple_lobbyclient lobbyclient,
				       grapple_lobbyroomid roomid)
{
  internal_lobbyclient_data *lobbyclientdata;
  char *returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  //Use the lowlevel grapple function for the name of a group
  returnval=grapple_client_groupname_get(lobbyclientdata->client,roomid);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

grapple_lobbyroomid grapple_lobbyclient_roomid_get(grapple_lobbyclient lobbyclient,
						     const char *name)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbyroomid returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  //Use the lowlevel grapple function for the name of a group
  returnval=grapple_client_group_from_name(lobbyclientdata->client,name);
  internal_lobbyclient_release(lobbyclientdata);
  return returnval;
}

//Users in a room
grapple_user *grapple_lobbyclient_roomusers_get(grapple_lobbyclient lobbyclient,
						grapple_lobbyroomid roomid)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_user *returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  //Use the lowlevel grapple function to find users in a group
  returnval=grapple_client_groupusers_get(lobbyclientdata->client,roomid);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Find a list of games in this room
grapple_lobbygameid *grapple_lobbyclient_gamelist_get(grapple_lobbyclient lobbyclient,
						      grapple_lobbyroomid roomid)
{
  internal_lobbyclient_data *lobbyclientdata;
  int count;
  grapple_lobbygameid *gamelist;
  grapple_lobbygame_internal *scan;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }


  //First count the number of games
  grapple_thread_mutex_lock(lobbyclientdata->games_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=lobbyclientdata->games;
  count=0;

  while (scan)
    {
      if (scan->room == roomid)
	//Only the ones in this room
	count++;

      scan=scan->next;
      if (scan==lobbyclientdata->games)
	scan=NULL;
    }

  if (!count)
    {
      grapple_thread_mutex_unlock(lobbyclientdata->games_mutex);
      //There werent any
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  //Allocate the memory based on the count
  gamelist=
    (grapple_lobbygameid *)malloc((count+1)*sizeof(grapple_lobbygameid));

  scan=lobbyclientdata->games;
  count=0;

  while (scan)
    {
      if (scan->room == roomid)
	//Set the value into the array
	gamelist[count++]=scan->id;

      scan=scan->next;
      if (scan==lobbyclientdata->games)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(lobbyclientdata->games_mutex);
  
  internal_lobbyclient_release(lobbyclientdata);

  //NULL the end of the array
  gamelist[count]=0;

  return gamelist;
}

//Find the details of a game, put them into a game structure
grapple_lobbygame *grapple_lobbyclient_game_get(grapple_lobbyclient lobbyclient,
						grapple_lobbygameid gameid)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame *returnval=NULL;
  grapple_lobbygame_internal *game;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
                                      gameid,GRAPPLE_LOCKTYPE_SHARED);

  if (!game)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_NO_SUCH_GAME);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  //Set up the retrun structure
  returnval=(grapple_lobbygame *)calloc(1,sizeof(grapple_lobbygame));
  
  returnval->gameid=game->id;
  returnval->currentusers=game->currentusers;
  returnval->maxusers=game->maxusers;
  returnval->needpassword=game->needpassword;
  returnval->room=game->room;
  returnval->closed=game->closed;
  
  returnval->name=(char *)malloc(strlen(game->session)+1);
  strcpy(returnval->name,game->session);
  
  returnval->descriptionlen=game->descriptionlen;
  if (game->descriptionlen)
    {
      returnval->description=malloc(game->descriptionlen);
      memcpy(returnval->description,game->description,game->descriptionlen);
    }
  
  grapple_lobbygame_internal_release(game);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Get rid of a set of game details passed to the user, freeing all memory
int grapple_lobbyclient_game_dispose(grapple_lobbygame *target)
{
  if (target->name)
    free(target->name);
  if (target->description)
    free(target->description);

  free(target);

  return GRAPPLE_OK;
}

//Set a callback. Callbacks are so that instead of needing to poll for
//messages, a callback can be set so that the messages are handled immediately
int grapple_lobbyclient_callback_set(grapple_lobbyclient lobbyclient,
				     grapple_lobbymessagetype message,
				     grapple_lobbycallback callback,
				     void *context)
{
  internal_lobbyclient_data *lobbyclientdata;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(lobbyclientdata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Add the callback to the list of callbacks
  lobbyclientdata->callbacks=
    grapple_lobbycallback_add(lobbyclientdata->callbacks,
			      message,callback,context);

  grapple_thread_mutex_unlock(lobbyclientdata->callback_mutex);

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}

//Set ALL callbacks to the function requested
int grapple_lobbyclient_callback_setall(grapple_lobbyclient client,
					grapple_lobbycallback callback,
					void *context)
{
  //Set one using the function above
  if (grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_ROOMLEAVE,
				       callback,context)==GRAPPLE_FAILED)
    return GRAPPLE_FAILED;

  //if one is ok, they all should be
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_ROOMENTER,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_ROOMCREATE,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_ROOMDELETE,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_CHAT,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_DISCONNECTED,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_NEWGAME,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_DELETEGAME,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_GAME_MAXUSERS,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_GAME_USERS,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_GAME_CLOSED,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_USERMSG,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_NEWUSER,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_CONNECTION_REFUSED,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_USER_DISCONNECTED,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_USER_JOINEDGAME,
				   callback,context);
  grapple_lobbyclient_callback_set(client,GRAPPLE_LOBBYMSG_USER_LEFTGAME,
				   callback,context);

  return GRAPPLE_OK;
}

//Remove a callback
int grapple_lobbyclient_callback_unset(grapple_lobbyclient lobbyclient,
				       grapple_lobbymessagetype message)
{
  internal_lobbyclient_data *lobbyclientdata;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(lobbyclientdata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Remove the callback
  lobbyclientdata->callbacks=
    grapple_lobbycallback_remove(lobbyclientdata->callbacks,
				 message);

  grapple_thread_mutex_unlock(lobbyclientdata->callback_mutex);

  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}

grapple_lobbyroomid grapple_lobbyclient_currentroomid_get(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbyroomid returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  returnval=lobbyclientdata->currentroom;
  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Get the last error
grapple_error grapple_lobbyclient_error_get(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_error returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_NO_ERROR);
      return GRAPPLE_ERROR_NOT_INITIALISED;
    }

  returnval=lobbyclientdata->last_error;

  //Now wipe the last error
  lobbyclientdata->last_error=GRAPPLE_NO_ERROR;

  if (returnval==GRAPPLE_NO_ERROR && lobbyclientdata->client)
    returnval=grapple_client_error_get(lobbyclientdata->client);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

int grapple_lobbyclient_connected(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  returnval=grapple_client_connected(lobbyclientdata->client);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

//Find the name of a room
char *grapple_lobbyclient_gamesession_get(grapple_lobbyclient lobbyclient,
				       grapple_lobbygameid gameid)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame_internal *game;
  char *returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  //Use the lowlevel grapple function for the name of a group

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
                                      gameid,GRAPPLE_LOCKTYPE_SHARED);

  if (!game)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_NO_SUCH_GAME);
      internal_lobbyclient_release(lobbyclientdata);
      return NULL;
    }

  returnval=(char *)malloc(strlen(game->session)+1);
  strcpy(returnval,game->session);

  grapple_lobbygame_internal_release(game);

  internal_lobbyclient_release(lobbyclientdata);
  
  return returnval;
}

grapple_lobbygameid grapple_lobbyclient_gameid_get(grapple_lobbyclient lobbyclient,
						   const char *name)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygameid returnval;
  grapple_lobbygame_internal *game;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  game=grapple_lobbyclient_game_internal_get_byname(lobbyclientdata,
						    name,
						    GRAPPLE_LOCKTYPE_SHARED);
  if (!game)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_NO_SUCH_GAME);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }


  returnval=game->id;
  grapple_lobbygame_internal_release(game);

  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

int grapple_lobbyclient_game_maxusers_get(grapple_lobbyclient lobbyclient,
					  grapple_lobbygameid gameid)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame_internal *game;
  int returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
                                      gameid,GRAPPLE_LOCKTYPE_SHARED);
  returnval=game->maxusers;

  grapple_lobbygame_internal_release(game);
  
  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

int grapple_lobbyclient_game_currentusers_get(grapple_lobbyclient lobbyclient,
					      grapple_lobbygameid gameid)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame_internal *game;
  int returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
                                      gameid,GRAPPLE_LOCKTYPE_SHARED);
  if (!game)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_NO_SUCH_GAME);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  returnval=game->currentusers;

  grapple_lobbygame_internal_release(game);
  
  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}

int grapple_lobbyclient_game_closed_get(grapple_lobbyclient lobbyclient,
					grapple_lobbygameid gameid)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame_internal *game;
  int returnval;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
                                      gameid,GRAPPLE_LOCKTYPE_SHARED);

  if (!game)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_NO_SUCH_GAME);
      internal_lobbyclient_release(lobbyclientdata);
      return 0;
    }

  returnval=game->closed;

  grapple_lobbygame_internal_release(game);

  
  internal_lobbyclient_release(lobbyclientdata);
  return returnval;
}

int grapple_lobbyclient_game_description_get(grapple_lobbyclient lobbyclient,
					     grapple_lobbygameid gameid,
					     void *buf,size_t *len)
{
  internal_lobbyclient_data *lobbyclientdata;
  grapple_lobbygame_internal *game;

  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  game=grapple_lobbyclient_game_internal_get(lobbyclientdata,
                                      gameid,GRAPPLE_LOCKTYPE_SHARED);

  if (!game)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,
				    GRAPPLE_ERROR_NO_SUCH_GAME);
      internal_lobbyclient_release(lobbyclientdata);
      return GRAPPLE_FAILED;
    }

  if (*len < game->descriptionlen)
    {
      if (*len>0)
	grapple_lobbyclient_error_set(lobbyclientdata,
				      GRAPPLE_ERROR_INSUFFICIENT_SPACE);
      *len=game->descriptionlen;
      grapple_lobbygame_internal_release(game);
      internal_lobbyclient_release(lobbyclientdata);
      if (*len==0)
	return GRAPPLE_OK;
      return GRAPPLE_FAILED;
    }

  *len=game->descriptionlen;

  if (game->descriptionlen > 0)
    memcpy(buf,game->description,game->descriptionlen);

  grapple_lobbygame_internal_release(game);
  internal_lobbyclient_release(lobbyclientdata);

  return GRAPPLE_OK;
}

int grapple_lobbyclient_id_get(grapple_lobbyclient lobbyclient)
{
  internal_lobbyclient_data *lobbyclientdata;
  int returnval;

  //They want our ID
  lobbyclientdata=internal_lobbyclient_get(lobbyclient);

  if (!lobbyclientdata)
    {
      grapple_lobbyerror_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return -1;
    }

  if (!lobbyclientdata->client)
    {
      grapple_lobbyclient_error_set(lobbyclientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_lobbyclient_release(lobbyclientdata);
      return -1;
    }

  returnval=grapple_client_serverid_get(lobbyclientdata->client);
  internal_lobbyclient_release(lobbyclientdata);

  return returnval;
}
