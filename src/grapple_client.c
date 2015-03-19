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
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "grapple_defines.h"
#include "grapple_callback.h"
#include "grapple_callback_internal.h"
#include "grapple_client.h"
#include "grapple_client_internal.h"
#include "grapple_client_thread.h"
#include "grapple_comms_api.h"
#include "grapple_queue.h"
#include "grapple_error_internal.h"
#include "grapple_message_internal.h"
#include "grapple_internal.h"
#include "grapple_group.h"
#include "grapple_group_internal.h"
#include "grapple_connection.h"
#include "grapple_variable.h"
#include "grapple_certificate.h"
#include "prototypes.h"
#include "tools.h"
#include "grapple_callback_dispatcher.h"

/**************************************************************************
 ** The functions in this file are generally those that are accessible   **
 ** to the end user. Obvious exceptions are those that are static which  **
 ** are just internal utilities.                                         **
 ** Care should be taken to not change the parameters of outward facing  **
 ** functions unless absolutely required                                 **
 **************************************************************************/

//This is a static variable which keeps track of the list of all clients
//run by this program. The clients are kept in a linked list. This variable
//is global to this file only.
static internal_client_data *grapple_client_head=NULL;

//And this is the mutex to make this threadsafe
static grapple_thread_mutex *client_mutex=NULL;

//Link a client into the list
static int internal_client_link(internal_client_data *clientdata)
{
  grapple_thread_mutex_lock(client_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!grapple_client_head)
    {
      grapple_client_head=clientdata;
      clientdata->next=clientdata;
      clientdata->prev=clientdata;
      grapple_thread_mutex_unlock(client_mutex);
      return 1;
    }

  clientdata->next=grapple_client_head;
  clientdata->prev=grapple_client_head->prev;
  clientdata->next->prev=clientdata;
  clientdata->prev->next=clientdata;

  grapple_client_head=clientdata;
  
  grapple_thread_mutex_unlock(client_mutex);

  return 1;
}

//Remove a client from the linked list
static int internal_client_unlink(internal_client_data *clientdata)
{
  grapple_thread_mutex_lock(client_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (clientdata->next==clientdata)
    {
      grapple_client_head=NULL;
      grapple_thread_mutex_unlock(client_mutex);
      return 1;
    }

  clientdata->next->prev=clientdata->prev;
  clientdata->prev->next=clientdata->next;

  if (clientdata==grapple_client_head)
    grapple_client_head=clientdata->next;

  grapple_thread_mutex_unlock(client_mutex);

  //This is outside the list now so can be done unmutexed
  clientdata->next=NULL;
  clientdata->prev=NULL;

  return 1;
}

//Find the client from the ID number passed by the user
static internal_client_data *internal_client_get(grapple_client num,
						 grapple_mutex_locktype type)
{
  internal_client_data *scan;
  int finished=0,found;

  while (!finished)
    {
      //By default if passed 0, then the oldest client is returned
      if (!num)
	{
	  grapple_thread_mutex_lock(client_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);

	  if (!grapple_client_head)
	    {
	      grapple_thread_mutex_unlock(client_mutex);
	      
	      return NULL;
	    }

	  if (grapple_thread_mutex_trylock(grapple_client_head->inuse,
					   type)==0)
	    {
	      grapple_thread_mutex_unlock(client_mutex);
	      return grapple_client_head;
	    }

	  if (grapple_client_head->threaddestroy)
	    {
	      //It is in the process of being destroyed, we cant use it
	      //and in all likelyhood we are trying to call it
	      //from inside the dispatcher
	      grapple_thread_mutex_unlock(client_mutex);
	      return NULL;
	    }

	  grapple_thread_mutex_unlock(client_mutex);
	}
      else
	{
	  grapple_thread_mutex_lock(client_mutex,GRAPPLE_LOCKTYPE_SHARED);
	  //Loop through the clients
	  scan=grapple_client_head;

	  found=0;

	  while (scan && !found)
	    {
	      if (scan->clientnum==num)
		{
		  if (grapple_thread_mutex_trylock(scan->inuse,
						   type)==0)
		    {
		      //Match and return it
		      grapple_thread_mutex_unlock(client_mutex);
		      return scan;
		    }
		  //It is in use, we cant use it yet

		  if (scan->threaddestroy)
		    {
		      //It is in the process of being destroyed, we cant use it
		      //and in all likelyhood we are trying to call it
		      //from inside the dispatcher
		      grapple_thread_mutex_unlock(client_mutex);
		      return NULL;
		    }

		  //Mark it as found though so we dont exit
		  found=1;
		}
      
	      scan=scan->next;
	      if (scan==grapple_client_head)
		scan=NULL;
	    }
	  grapple_thread_mutex_unlock(client_mutex);

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

static void internal_client_release(internal_client_data *target)
{
  //We dont need to mutex this, we definitely HAVE it, and we are just
  //releasing it, and it wont be referenced again - it cant be deleted like
  //this

  grapple_thread_mutex_unlock(target->inuse);
}

//Create a new client
static internal_client_data *client_create(void)
{
  static int nextval=256; /*A unique value for the clients ID. This will be
			    changed by the server, but is a good unique start*/
  internal_client_data *clientdata;

  //Create the structure
  clientdata=(internal_client_data *)calloc(1,sizeof(internal_client_data));

  //Assign it some default values
  clientdata->clientnum=nextval++;
  clientdata->serverid=GRAPPLE_USER_UNKNOWN;

  //This sets it so that the client, by default, is notified of other clients
  clientdata->notify=GRAPPLE_NOTIFY_STATE_ON;

  //Create the mutexes we'll need
  clientdata->message_in_mutex=grapple_thread_mutex_init();
  clientdata->message_out_mutex=grapple_thread_mutex_init();
  clientdata->connection_mutex=grapple_thread_mutex_init();
  clientdata->group_mutex=grapple_thread_mutex_init();
  clientdata->failover_mutex=grapple_thread_mutex_init();
  clientdata->callback_mutex=grapple_thread_mutex_init();
  clientdata->internal_mutex=grapple_thread_mutex_init();
  clientdata->dispatcher_mutex=grapple_thread_mutex_init();
  clientdata->event_queue_mutex=grapple_thread_mutex_init();

  clientdata->inuse=grapple_thread_mutex_init();

  //Create the variable hash. If you have a LOT of variables, you may
  //want to change this number to speedup looking. The same change should
  //be made in grapple_server.c
  clientdata->variables=grapple_variable_hash_init(27);

  return clientdata;
}

static int init_client_mutex(void)
{
  if (!client_mutex)
    client_mutex=grapple_thread_mutex_init();

  return 1;
}


//User function for initialising the client
grapple_client grapple_client_init(const char *name,const char *version)
{
  internal_client_data *clientdata;
  grapple_client returnval;

  init_client_mutex();

  //Create the internal data
  clientdata=client_create();

  //Assign the user supplied values
  clientdata->productname=(char *)malloc(strlen(name)+1);

  strcpy(clientdata->productname,name);

  clientdata->productversion=(char *)malloc(strlen(version)+1);
  strcpy(clientdata->productversion,version);

  //Return the client ID - the end user only gets an integer, called a
  //'grapple_client'

  clientdata->sequential=1;

  //Link it into the array of clients  
  returnval=clientdata->clientnum;

  internal_client_link(clientdata);

  return returnval;
}

//Set the address to connect to
int grapple_client_address_set(grapple_client client,const char *address)
{
  internal_client_data *clientdata;

  //Locate the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Cant set this if we're connected already
  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }


  //If we set it to NULL, then use localhost
  if (!address || !*address)
    {
      address="127.0.0.1";
    }

  if (clientdata->address)
    free(clientdata->address);

  //Set the value into the client
  clientdata->address=(char *)malloc(strlen(address)+1);
  strcpy(clientdata->address,address);

  internal_client_release(clientdata);

  //OK
  return GRAPPLE_OK;
}


//Set the port number to connect to
int grapple_client_port_set(grapple_client client,int port)
{
  internal_client_data *clientdata;

  //Get the client data
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Set the port
  clientdata->port=port;

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Set the port number to connect from
int grapple_client_sourceport_set(grapple_client client,int port)
{
  internal_client_data *clientdata;

  //Get the client data
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Set the port
  clientdata->sourceport=port;

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Set the protocol this connection must use
int grapple_client_protocol_set(grapple_client client,
				grapple_protocol protocol)
{
  internal_client_data *clientdata;

  //Get the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Set the protocol
  clientdata->protocol=protocol;

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Returns the protocol used by this client
grapple_protocol grapple_client_protocol_get(grapple_client client)
{
  internal_client_data *clientdata;
  grapple_protocol protocol;

  //Get the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_PROTOCOL_UNKNOWN;
    }

  //Set the protocol
  protocol=clientdata->protocol;

  internal_client_release(clientdata);

  return protocol;
}

//Sets whether the client is encrypted or not
int grapple_client_encryption_enable(grapple_client client,
				     const char *private_key,
				     const char *private_key_password,
				     const char *public_key,
				     const char *cert_auth)
{
#ifndef SOCK_SSL
  return GRAPPLE_FAILED;
#else
  internal_client_data *clientdata;

  //Get the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Set the protocol
  clientdata->encrypted=1;

  if (clientdata->public_key)
    free(clientdata->public_key);

  if (public_key)
    {
      clientdata->public_key=(char *)malloc(strlen(public_key)+1);
      strcpy(clientdata->public_key,public_key);
    }
  else
    {
      clientdata->public_key=NULL;
    }

  if (clientdata->private_key)
    free(clientdata->private_key);

  if (private_key)
    {
      clientdata->private_key=(char *)malloc(strlen(private_key)+1);
      strcpy(clientdata->private_key,private_key);
    }
  else
    {
      clientdata->private_key=NULL;
    }

  if (clientdata->private_key_password)
    free(clientdata->private_key_password);

  if (private_key_password)
    {
      clientdata->private_key_password=
	(char *)malloc(strlen(private_key_password)+1);
      strcpy(clientdata->private_key_password,private_key_password);
    }
  else
    {
      clientdata->private_key_password=NULL;
    }

  if (clientdata->cert_auth)
    free(clientdata->cert_auth);

  if (cert_auth)
    {
      clientdata->cert_auth=(char *)malloc(strlen(cert_auth)+1);
      strcpy(clientdata->cert_auth,cert_auth);
    }
  else
    {
      clientdata->cert_auth=NULL;
    }

  internal_client_release(clientdata);

  return GRAPPLE_OK;
#endif
}

//Set whether we get notified of the userlist, by default we do
int grapple_client_notified_set(grapple_client client,
				int notify)
{
  internal_client_data *clientdata;

  //Get the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Only do the change if we are actually changing anything
  if (clientdata->notify!=notify)
    {
      clientdata->notify=notify;

      //Tell the server this state, if we are connected, otherwise, just
      //set it internally for use as part of the handshake routine
      if (clientdata->sock)
	c2s_set_notify_state(clientdata,notify);
      
    }
  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Set the password that the client must use to connect to the server
int grapple_client_password_set(grapple_client client,const char *password)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  if (clientdata->password)
    free(clientdata->password);

  clientdata->password=(char *)malloc(strlen(password)+1);
  strcpy(clientdata->password,password);

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

int grapple_client_protectionkey_set(grapple_client client,const char *key)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  if (clientdata->protectionkey)
    free(clientdata->protectionkey);

  if (key && *key)
    {
      clientdata->protectionkey=(char *)malloc(strlen(key)+1);
      strcpy(clientdata->protectionkey,key);
    }
  else
    clientdata->protectionkey=NULL;

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

int grapple_client_start(grapple_client client,int flags)
{
  internal_client_data *clientdata;

  //Find the client data struct
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Already connected?
  if (clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Check all required values are initialised
  if (!clientdata->address)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_ADDRESS_NOT_SET);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  if (!clientdata->port)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_PORT_NOT_SET);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  if (!clientdata->protocol)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_PROTOCOL_NOT_SET);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Start a network connection - either 2 way UDP or TCP
  switch (clientdata->protocol)
    {
    case GRAPPLE_PROTOCOL_UNKNOWN:
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_PROTOCOL_NOT_SET);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
      break;
    case GRAPPLE_PROTOCOL_TCP:
      clientdata->sock=socket_create_inet_tcp_wait(clientdata->address,
						   clientdata->port,1);
      break;
    case GRAPPLE_PROTOCOL_UDP:
      if (clientdata->nattrav_server_hostname)
	{
	  clientdata->sock=
	    socket_create_inet_udp2way_wait_onport_stun(clientdata->address,
							clientdata->port,1,
							clientdata->sourceport,
							clientdata->nattrav_server_hostname,
							clientdata->nattrav_server_port);

	}
      else
	{
	  clientdata->sock=
	    socket_create_inet_udp2way_wait_onport(clientdata->address,
						   clientdata->port,1,
						   clientdata->sourceport);
	}

      clientdata->connecting=1;
      break;
    }

  //The connection couldnt be created.
  if (!clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CANNOT_CONNECT);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //If encrypted, set the encryption data on them
#ifdef SOCK_SSL
  if (clientdata->encrypted && clientdata->protocol==GRAPPLE_PROTOCOL_TCP)
    {
      if (clientdata->private_key)
	socket_set_private_key(clientdata->sock,clientdata->private_key,
			       clientdata->private_key_password);
      if (clientdata->public_key)
	socket_set_public_key(clientdata->sock,clientdata->public_key);
      if (clientdata->cert_auth)
	socket_set_ca(clientdata->sock,clientdata->cert_auth);
      socket_set_encrypted(clientdata->sock);
      while (socket_connected(clientdata->sock) &&
	     !socket_dead(clientdata->sock))
	socket_process(clientdata->sock,10000);
    }
#endif

  //Set this to be sequential for the moment, to ensure the handshake
  //goes in properly
  socket_mode_set(clientdata->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);

  //Start up the wakeup socket. This is a socket that can break into the 
  //long timeout incoming loop, tell it that there is something to do locally
  clientdata->wakesock=socket_create_interrupt();

  //Start the client thread. This thread handles the sockets, processes the 
  //data, and passes data back to the main thread in the form of a message 
  //queue
  grapple_client_thread_start(clientdata);


  //Wait for the connection to complete. This is handled in the thread, so
  //here we just wait for it to happen
  while (clientdata->connecting && clientdata->thread)
    microsleep(1000);

  //If the connection failed...
  if (clientdata->disconnected || !clientdata->thread)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CANNOT_CONNECT);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //The connection was OK - send a handshake
  c2s_handshake(clientdata);

  //If we have a requested name, send the name to the server
  grapple_thread_mutex_lock(clientdata->internal_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  if (clientdata->name_provisional)
    c2s_set_name(clientdata,clientdata->name_provisional);

  grapple_thread_mutex_unlock(clientdata->internal_mutex);

  if (flags & GRAPPLE_WAIT)
    {
      while (!clientdata->serverid && !socket_dead(clientdata->sock))
	microsleep(1000);

      if (socket_dead(clientdata->sock))
	{
	  grapple_client_error_set(clientdata,GRAPPLE_ERROR_CANNOT_CONNECT);
	  internal_client_release(clientdata);
	  return GRAPPLE_FAILED;
	}
    }

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Set whether to try to use a NAT traversal server
int grapple_client_nattrav_address(grapple_client client,
				   const char *hostname,int port)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->sock)
    {
      //We are already started, cannot start nattrav now
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_CONNECTED);
      return GRAPPLE_FAILED;
    }

  //Free the old data if set
  if (clientdata->nattrav_server_hostname)
    free (clientdata->nattrav_server_hostname);

  //Set the new value
  if (hostname)
    {
      clientdata->nattrav_server_hostname=(char *)malloc(strlen(hostname)+1);
      strcpy(clientdata->nattrav_server_hostname,hostname);
    }
  clientdata->nattrav_server_port=port;

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//report whether the client is connected to the server
int grapple_client_connected(grapple_client client)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!clientdata->sock)
    {
      internal_client_release(clientdata);
      return 0;
    }

  if (socket_dead(clientdata->sock))
    {
      internal_client_release(clientdata);
      return 0;
    }

  if (clientdata->serverid)
    {
      internal_client_release(clientdata);
      return 1;
    }

  internal_client_release(clientdata);

  return 0;
}

//Set the name
int grapple_client_name_set(grapple_client client,const char *name)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    { 
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(clientdata->internal_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (clientdata->name_provisional)
    free(clientdata->name_provisional);

  //The value is 'provisional' cos we havent been told by the server we can
  //use this name yet
  clientdata->name_provisional=(char *)malloc(strlen(name)+1);
  strcpy(clientdata->name_provisional,name);

  grapple_thread_mutex_unlock(clientdata->internal_mutex);

  //Tell the server this is the name we want - as long as the server is 
  //connected
  if (clientdata->sock)
    c2s_set_name(clientdata,name);

  internal_client_release(clientdata);

  return GRAPPLE_OK;

}

//Get the name of a client
char *grapple_client_name_get(grapple_client client,grapple_user serverid)
{
  internal_client_data *clientdata;
  char *returnval;
  grapple_connection *user;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  //We are getting ourown pre-auth name
  if (serverid==GRAPPLE_USER_UNKNOWN)
    {
      grapple_thread_mutex_lock(clientdata->internal_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //So check if it has a proivisional name
      if (!clientdata->name_provisional)
	{
	  grapple_thread_mutex_unlock(clientdata->internal_mutex);
	  internal_client_release(clientdata);
	  return NULL;
	}

      //Make a copy of the provisional name - as this can be deleted at any
      //moment
      returnval=(char *)malloc(strlen(clientdata->name_provisional)+1);
      strcpy(returnval,clientdata->name_provisional);
      grapple_thread_mutex_unlock(clientdata->internal_mutex);
      internal_client_release(clientdata);
      return returnval;
    }

  grapple_thread_mutex_lock(clientdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Look for the ID that matches the request
  user=connection_from_serverid(clientdata->userlist,serverid);
  if (!user)
    {
      //No such ID
      grapple_thread_mutex_unlock(clientdata->connection_mutex);
      internal_client_release(clientdata);
      return NULL;
    }

  //Copy this ID's name  
  if (user->name && *user->name)
    {
      returnval=(char *)malloc(strlen(user->name)+1);
      strcpy(returnval,user->name);
    }
  else
    {
      returnval=NULL;
    }

  grapple_thread_mutex_unlock(clientdata->connection_mutex);

  internal_client_release(clientdata);
  
  //return it
  return returnval;
}

//Count the number of outstanding messages in the users incoming queue
int grapple_client_messagecount_get(grapple_client client)
{
  internal_client_data *clientdata;
  int returnval;

  //Find the client data
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  grapple_thread_mutex_lock(clientdata->message_in_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Count the messages
  returnval=grapple_queue_count(clientdata->message_in_queue);

  grapple_thread_mutex_unlock(clientdata->message_in_mutex);

  internal_client_release(clientdata);

  //Return the count
  return returnval;
}

//return true if there are any messages waiting
int grapple_client_messages_waiting(grapple_client client)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (clientdata->message_in_queue)
    {
      internal_client_release(clientdata);
      return 1;
    }
  else
    {
      internal_client_release(clientdata);
      return 0;
    }
}

//Pull the oldest message
grapple_message *grapple_client_message_pull(grapple_client client)
{
  internal_client_data *clientdata;
  grapple_queue *queuedata;
  grapple_message *returnval=NULL;

  //Find the client data
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }
  
  grapple_thread_mutex_lock(clientdata->message_in_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (clientdata->message_in_queue)
    {
      //Remove the oldest message
      queuedata=clientdata->message_in_queue;
      clientdata->message_in_queue=
	queue_unlink(clientdata->message_in_queue,
		     clientdata->message_in_queue);

      grapple_thread_mutex_unlock(clientdata->message_in_mutex);


      /*Now we have the message, clone it into a new form useful for the end
	user*/
      returnval=client_convert_message_for_user(queuedata);

      //Get rid of the queue message      
      queue_struct_dispose(queuedata);
    }
  else
    {
      grapple_thread_mutex_unlock(clientdata->message_in_mutex);
    }

  internal_client_release(clientdata);

  //Return the message  
  return returnval;
}

//This is the function used to send messages by the client to either
//the server or to other clients
grapple_confirmid grapple_client_send(grapple_client client,
				      grapple_user target,
				      int flags,
				      const void *data,size_t datalen)
{
  internal_client_data *clientdata;
  grapple_confirmid thismessageid=0;
  static int staticmessageid=10; /*This gets incrimented for each message
				   that is requiring confirmation*/

  //Find the data
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (flags & GRAPPLE_WAIT)
    flags |= GRAPPLE_CONFIRM;

  //This message requests a confirmation
  if (flags & GRAPPLE_CONFIRM)
    {
      //Set it a message ID
      thismessageid=staticmessageid++;
      flags|=GRAPPLE_RELIABLE;
    }

  switch (target)
    {
    case GRAPPLE_USER_UNKNOWN:
      //The target was the unknown user - cant send to this one
      break;
    case GRAPPLE_SERVER:
      //Sending a message to the server
      c2s_message(clientdata,flags,thismessageid,data,datalen);
      break;
    case GRAPPLE_EVERYONE:
      //Sending a message to ALL players
      c2s_relayallmessage(clientdata,flags,thismessageid,data,datalen);
      break;
    case GRAPPLE_EVERYONEELSE:
      //Sending a message to all OTHER players
      c2s_relayallbutselfmessage(clientdata,flags,thismessageid,data,datalen);
      break;
    default:
      //Sending a message to a specific player
      c2s_relaymessage(clientdata,target,flags,thismessageid,data,datalen);
      break;
    }

  if (flags & GRAPPLE_WAIT)
    {
      clientdata->sendwait=thismessageid;

      while (clientdata->sendwait==thismessageid)
	microsleep(1000);
    }

  internal_client_release(clientdata);

  //Return the message ID - will be 0 if no confirmation was requested
  if (thismessageid)
    return thismessageid;
  return GRAPPLE_OK;
}

//Destroy the client
int grapple_client_destroy(grapple_client client)
{
  internal_client_data *clientdata;
  grapple_queue *target;

  //Find the client to kill
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      //There is no client to kill
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Disconnect the client from the server
  if (clientdata->thread)
    c2s_disconnect(clientdata);

  //Unlink the client from the list of clients
  internal_client_unlink(clientdata);

  internal_client_release(clientdata);

  //Kill the thread
  if (clientdata->thread)
    {
      clientdata->threaddestroy=1;

      grapple_thread_mutex_lock(clientdata->internal_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      if (clientdata->wakesock)
	socket_interrupt(clientdata->wakesock);
      grapple_thread_mutex_unlock(clientdata->internal_mutex);

      //Wait for the thread to go.
      while (clientdata->threaddestroy==1 && clientdata->thread)
	microsleep(1000);
    }

  //Free memory
  if (clientdata->address)
    free(clientdata->address);
  if (clientdata->name_provisional)
    free(clientdata->name_provisional);
  if (clientdata->name)
    free(clientdata->name);
  if (clientdata->session)
    free(clientdata->session);
  if (clientdata->password)
    free(clientdata->password);
  if (clientdata->productname)
    free(clientdata->productname);
  if (clientdata->productversion)
    free(clientdata->productversion);

#ifdef SOCK_SSL
  if (clientdata->cert_auth)
    free(clientdata->cert_auth);
#endif

  //Delete the thread mutexes
  grapple_thread_mutex_destroy(clientdata->message_in_mutex);
  grapple_thread_mutex_destroy(clientdata->message_out_mutex);
  grapple_thread_mutex_destroy(clientdata->connection_mutex);
  grapple_thread_mutex_destroy(clientdata->group_mutex);
  grapple_thread_mutex_destroy(clientdata->failover_mutex);
  grapple_thread_mutex_destroy(clientdata->callback_mutex);
  grapple_thread_mutex_destroy(clientdata->internal_mutex);
  grapple_thread_mutex_destroy(clientdata->dispatcher_mutex);
  grapple_thread_mutex_destroy(clientdata->event_queue_mutex);

  grapple_thread_mutex_destroy(clientdata->inuse);

  //Remove messages in the queue
  while (clientdata->message_in_queue)
    {
      target=clientdata->message_in_queue;
      clientdata->message_in_queue=queue_unlink(clientdata->message_in_queue,
						clientdata->message_in_queue);
      queue_struct_dispose(target);
    }

  //Remove messages in the out queue
  while (clientdata->message_out_queue)
    {
      target=clientdata->message_out_queue;
      clientdata->message_out_queue=queue_unlink(clientdata->message_out_queue,
						clientdata->message_out_queue);
      queue_struct_dispose(target);
    }
  
  //Remove variables
  grapple_variable_hash_dispose(clientdata->variables);

  //Thats it, done.
  free(clientdata);

  return GRAPPLE_OK;
}


//Get an array of connected users
grapple_user *grapple_client_userlist_get(grapple_client client)
{
  internal_client_data *clientdata;
  grapple_user *returnval;

  //Get this client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  //Return the array
  returnval=connection_client_intarray_get(clientdata);

  internal_client_release(clientdata);

  return returnval;
}

//Set a callback. Callbacks are so that instead of needing to poll for
//messages, a callback can be set so that the messages are handled immediately
int grapple_client_callback_set(grapple_client client,
				grapple_messagetype message,
				grapple_callback callback,
				void *context)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (clientdata->dispatcher_count<1)
    {
      internal_client_release(clientdata);
      //Release and relock as dispatchers_set also wants exclusive
      grapple_client_dispatchers_set(client,1);
      clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      //Check its still here
      if (!clientdata)
	{
	  grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
	  return GRAPPLE_FAILED;
	}
    }

  grapple_thread_mutex_lock(clientdata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Add the callback to the list of callbacks
  clientdata->callbackanchor=grapple_callback_add(clientdata->callbackanchor,
						  message,
						  callback,context);

  grapple_thread_mutex_unlock(clientdata->callback_mutex);
  
  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Set ALL callbacks to the function requested
int grapple_client_callback_setall(grapple_client client,
				   grapple_callback callback,
				   void *context)
{
  //Set one using the function above
  if (grapple_client_callback_set(client,GRAPPLE_MSG_NEW_USER,callback,
				  context)==GRAPPLE_FAILED)
    return GRAPPLE_FAILED;

  //if one is ok, they all should be
  grapple_client_callback_set(client,GRAPPLE_MSG_NEW_USER_ME,callback,context);
  grapple_client_callback_set(client,GRAPPLE_MSG_USER_MSG,callback,context);
  grapple_client_callback_set(client,GRAPPLE_MSG_USER_NAME,callback,context);
  grapple_client_callback_set(client,GRAPPLE_MSG_USER_MSG,callback,context);
  grapple_client_callback_set(client,GRAPPLE_MSG_SESSION_NAME,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_USER_DISCONNECTED,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_SERVER_DISCONNECTED,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_CONNECTION_REFUSED,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_PING,callback,context);
  grapple_client_callback_set(client,GRAPPLE_MSG_GROUP_CREATE,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_GROUP_ADD,callback,context);
  grapple_client_callback_set(client,GRAPPLE_MSG_GROUP_REMOVE,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_GROUP_DELETE,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_YOU_ARE_HOST,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_CONFIRM_RECEIVED,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_CONFIRM_TIMEOUT,callback,
			      context);
  grapple_client_callback_set(client,GRAPPLE_MSG_GAME_DESCRIPTION,callback,
			      context);

  return GRAPPLE_OK;
}

//Remove a callback
int grapple_client_callback_unset(grapple_client client,
				   grapple_messagetype message)
{
  internal_client_data *clientdata;

  //Get the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(clientdata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Remove the callback
  clientdata->callbackanchor=grapple_callback_remove(clientdata->callbackanchor,
						     message);

  grapple_thread_mutex_unlock(clientdata->callback_mutex);
  
  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Get the ID of the default client
grapple_client grapple_client_default_get()
{
  internal_client_data *clientdata;
  grapple_client returnval;

  if (!client_mutex)
    return 0;

  //Get the default client
  clientdata=internal_client_get(0,GRAPPLE_LOCKTYPE_SHARED);

  if (clientdata)
    {
      //Return its ID if we have it
      returnval=clientdata->clientnum;

      internal_client_release(clientdata);
    }
  else
    //return 0 (the default anyway) if we dont
    returnval=0;

  
  return returnval;
}


//Enumerate the users. Effectively this means run the passed callback
//function for each user
int grapple_client_enumusers(grapple_client client,
			     grapple_user_enum_callback callback,
			     void *context)
{
  internal_client_data *clientdata;
  int *userarray;
  grapple_user serverid;
  int loopa;
  grapple_connection *user;
  char *tmpname;
  int carry_on=1;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Get the user array
  userarray=grapple_client_userlist_get(client);

  loopa=0;

  //Loop for each user
  while (carry_on && userarray[loopa])
    {
      grapple_thread_mutex_lock(clientdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Find the user
      user=connection_from_serverid(clientdata->userlist,userarray[loopa]);
      if (user)
	{
	  //Set the default values to an unnamed user
	  serverid=user->serverid;
	  tmpname=NULL;
	  if(user->name && *user->name)
	    {
	      //If the user has a name, note that
	      tmpname=(char *)malloc(strlen(user->name)+1);
	      strcpy(tmpname,user->name);
	    }

	  //Unlock the mutex, we are now only using copied data
	  grapple_thread_mutex_unlock(clientdata->connection_mutex);
	  
	  //If the user is valid
	  if (tmpname)
	    {
	      //Run the callback
	      carry_on=(*callback)(serverid,tmpname,0,context);
	      
	      free(tmpname);
	    }
	}
      else
	{
	  //Unlock the mutex
	  grapple_thread_mutex_unlock(clientdata->connection_mutex);
	}
      
      loopa++;
    }

  internal_client_release(clientdata);

  free(userarray);

  return GRAPPLE_OK;
}

//Get the name of the current session
char *grapple_client_session_get(grapple_client client)
{
  internal_client_data *clientdata;
  char *returnval;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  if (!clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_client_release(clientdata);
      return 0;
    }

  //If no session name has been set, return null
  if (!clientdata->session)
    {
      internal_client_release(clientdata);
      return NULL;
    }

  //Allocate memory for the session name, and return it
  returnval=(char *)malloc(strlen(clientdata->session)+1);
  strcpy(returnval,clientdata->session);

  internal_client_release(clientdata);

  return returnval;
}


//Stop (but dont destroy) the client
int grapple_client_stop(grapple_client client)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Disconnect from the server
  if (clientdata->thread)
    {
      c2s_disconnect(clientdata);
      clientdata->threaddestroy=1;

      grapple_thread_mutex_lock(clientdata->internal_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      if (clientdata->wakesock)
	socket_interrupt(clientdata->wakesock);
      grapple_thread_mutex_unlock(clientdata->internal_mutex);

      //Wait for the thread to be destroyed
      while (clientdata->threaddestroy==1 && clientdata->thread)
	microsleep(1000);

      clientdata->threaddestroy=0;
    }

  internal_client_release(clientdata);

  //Leave the rest of the data intact
  return GRAPPLE_OK;
}

//Ping the server, find the round trip time
int grapple_client_ping(grapple_client client)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Send the ping to the server
  c2s_ping(clientdata,++clientdata->pingnumber);

  gettimeofday(&clientdata->pingstart,NULL);

  internal_client_release(clientdata);

  //In the end a ping reply will come back, this will be passed to the user
  
  return GRAPPLE_OK;
}

//Get the last recorded ping time for a specific user
double grapple_client_ping_get(grapple_client client,grapple_user serverid)
{
  internal_client_data *clientdata;
  double returnval=0;
  grapple_connection *user;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  //If we dont know the user, find ourown ping time
  if (serverid==GRAPPLE_USER_UNKNOWN)
    serverid=clientdata->serverid;

  grapple_thread_mutex_lock(clientdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Get the user
  user=connection_from_serverid(clientdata->userlist,serverid);
  if (user)
    {
      //Find that users pingtime
      returnval=user->pingtime;
    }

  grapple_thread_mutex_unlock(clientdata->connection_mutex);

  internal_client_release(clientdata);

  return returnval;
}

//Get the server ID of the client
grapple_user grapple_client_serverid_get(grapple_client client)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_client_release(clientdata);
      return 0;
    }

  //This can only remain USER_UNKNOWN for so long, in the end, it has to change
  while (clientdata->sock && !socket_dead(clientdata->sock) &&
	 clientdata->serverid==GRAPPLE_USER_UNKNOWN)
    {
      microsleep(1000);
    }
  
  internal_client_release(clientdata);

  return clientdata->serverid;
}

//Set that the client is requiring all data to be received sequentially. For
//TCP this doesnt matter. For UDP it forces the client to hold out-of-order
//network packets until earlier ones come in.
int grapple_client_sequential_set(grapple_client client,int value)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (value)
    {
      //Set sequential on
      clientdata->sequential=1;

      //Set it low level to the socket
      if (clientdata->sock)
	socket_mode_set(clientdata->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);
    }
  else
    {
      //Set sequential off
      clientdata->sequential=0;

      //And low level on the socket
      if (clientdata->sock)
	socket_mode_unset(clientdata->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);
    }

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Get the current state of sequential or non-sequential
int grapple_client_sequential_get(grapple_client client)
{
  internal_client_data *clientdata;
  int returnval;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  returnval=clientdata->sequential;

  internal_client_release(clientdata);

  return returnval;
}

//Messages can be sent to groups, not just to users. This function
//returns the ID of a group from the name
grapple_user grapple_client_group_from_name(grapple_client client,const char *name)
{
  internal_client_data *clientdata;
  int returnval;
  internal_grapple_group *scan;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  grapple_thread_mutex_lock(clientdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Loop through all groups
  scan=clientdata->groups;

  while (scan)
    {
      //If the name matches
      if (scan->name && *scan->name && !strcmp(scan->name,name))
	{
	  //return this groups ID
	  returnval=scan->id;
	  grapple_thread_mutex_unlock(clientdata->group_mutex);
	  internal_client_release(clientdata);
	  return returnval;
	}

      scan=scan->next;
      if (scan==clientdata->groups)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(clientdata->group_mutex);

  grapple_client_error_set(clientdata,GRAPPLE_ERROR_NO_SUCH_GROUP);

  internal_client_release(clientdata);

  //No ID to find
  return 0;
}

//create a group. The group is always assigned by the server. To speed things
//up the server pre-assigns each user a group
grapple_user grapple_client_group_create(grapple_client client,
					 const char *name,const char *password)
{
  
  internal_client_data *clientdata;
  int returnval;
  char *cpassword;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  if (!clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_client_release(clientdata);
      return 0;
    }

  //If the server hasnt pre-assigned the group, it will shortly. Wait for
  //it.
  while (clientdata->sock && clientdata->next_group==0)
    microsleep(1000);

  //Note the group ID
  returnval=clientdata->next_group;

  //Remove it from the client
  clientdata->next_group=0;
  //Request a new group ID from the server
  c2s_request_group(clientdata);

  //Now create a group locally, if we can
  cpassword=group_crypt_twice(returnval,password);
  if (GRAPPLE_OK==create_client_group(clientdata,returnval,name,cpassword))
    {
      if (cpassword)
	free(cpassword);
      //Tell the server to create a new group based on the ID we have just obtained
      cpassword=group_crypt(returnval,password);
      c2s_group_create(clientdata,returnval,name,cpassword);
    }
  if (cpassword)
    free(cpassword);

  internal_client_release(clientdata);

  //Return the group ID
  return returnval;
}

//Adding a user to a group. This will mean that any messages sent to the
//group will also be sent to that user
int grapple_client_group_add(grapple_client client,grapple_user group,
			     grapple_user add,const char *password)
{
  internal_client_data *clientdata;
  char *cpassword;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }


  //Add a user to the group by telling the server
  cpassword=group_crypt_twice(group,password);
  if (GRAPPLE_OK==client_group_add(clientdata,group,add,cpassword))
    {
      if (cpassword)
	free(cpassword);

      cpassword=group_crypt(group,password);
      c2s_group_add(clientdata,group,add,cpassword);

      internal_client_release(clientdata);

      return GRAPPLE_OK;
    }
  
  if (cpassword)
    free(cpassword);

  internal_client_release(clientdata);

  return GRAPPLE_FAILED;
}

int grapple_client_group_passwordneeded(grapple_client client,
					grapple_user group)
{
  internal_client_data *clientdata;
  internal_grapple_group *scan;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  grapple_thread_mutex_lock(clientdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=clientdata->groups;

  //Loop through and find the one we need
  while (scan)
    {
      if (scan->id==group)
	{
	  //this is the one
	  if (scan->password && *scan->password)
	    {
	      grapple_thread_mutex_unlock(clientdata->group_mutex);
	      internal_client_release(clientdata);
	      return 1;
	    }
	  grapple_thread_mutex_unlock(clientdata->group_mutex);
	  internal_client_release(clientdata);
	  return 0;
	}
      scan=scan->next;
      if (scan==clientdata->groups)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(clientdata->group_mutex);

  grapple_client_error_set(clientdata,GRAPPLE_ERROR_NO_SUCH_GROUP);

  internal_client_release(clientdata);

  return 0;
}

//Remove a user from a group
int grapple_client_group_remove(grapple_client client,grapple_user group,
				grapple_user removeid)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Now remove the user locally
  if (client_group_remove(clientdata,group,removeid))
    {
      //If successful, remove from the server
      c2s_group_remove(clientdata,group,removeid);

      internal_client_release(clientdata);
      return GRAPPLE_OK;
    }

  internal_client_release(clientdata);
  return GRAPPLE_FAILED;
}

//Delete a group entirely
int grapple_client_group_delete(grapple_client client,grapple_user group)
{
  internal_client_data *clientdata;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!clientdata->sock)
    {
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_CLIENT_NOT_CONNECTED);
      internal_client_release(clientdata);
      return GRAPPLE_FAILED;
    }

  //Delete the group locally
  if (delete_client_group(clientdata,group))
    {
      //If successful, tell the server about it
      c2s_group_delete(clientdata,group);

      internal_client_release(clientdata);
      return GRAPPLE_OK;
    }

  internal_client_release(clientdata);
  return GRAPPLE_FAILED;
}

//Enumerate the users. Effectively this means run the passed callback
//function for each user in the group
int grapple_client_enumgroup(grapple_client client,
			     grapple_user groupid,
			     grapple_user_enum_callback callback,
			     void *context)
{
  internal_client_data *clientdata;
  int *userarray;
  grapple_user serverid;
  int loopa;
  grapple_connection *user;
  char *tmpname;
  int carry_on=1;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Get the user array
  userarray=client_group_unroll(clientdata,groupid);

  loopa=0;

  //Loop for each user
  while (carry_on && userarray[loopa])
    {
      grapple_thread_mutex_lock(clientdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Find the user
      user=connection_from_serverid(clientdata->userlist,userarray[loopa]);
      if (user)
	{
	  //Set the default values to an unnamed user
	  serverid=user->serverid;
	  tmpname=NULL;
	  if(user->name && *user->name)
	    {
	      //If the user has a name, note that
	      tmpname=(char *)malloc(strlen(user->name)+1);
	      strcpy(tmpname,user->name);
	    }

	  //Unlock the mutex, we are now only using copied data
	  grapple_thread_mutex_unlock(clientdata->connection_mutex);
	  
	  //If the user is valid
	  if (serverid != GRAPPLE_USER_UNKNOWN)
	    {
	      //Run the callback
	      carry_on=(*callback)(serverid,tmpname,0,context);
	    }
	  if (tmpname)
	    free(tmpname);
	}
      else
	{
	  //Unlock the mutex
	  grapple_thread_mutex_unlock(clientdata->connection_mutex);
	}
      
      loopa++;
    }

  free(userarray);

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

grapple_user *grapple_client_groupusers_get(grapple_client client,
					    grapple_user groupid)
{
  internal_client_data *clientdata;
  grapple_user *userarray;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  //Get the user array
  userarray=client_group_unroll(clientdata,groupid);

  internal_client_release(clientdata);

  return userarray;
}

//Enumerate the list of groups, running a user function for each group
int grapple_client_enumgrouplist(grapple_client client,
				 grapple_user_enum_callback callback,
				 void *context)
{
  internal_client_data *clientdata;
  int *grouplist;
  grapple_user groupid;
  int count;
  char *tmpname;
  internal_grapple_group *scan;
  int carry_on=1;


  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }


  //The rest of this is pretty inefficient, but it is done this way for a
  //reason. It is done to minimise the lock time on the group mutex,
  //as calling a user function with that mutex locked could be disasterous for
  //performance.

  //Get the group list into an array
  count=0;

  grapple_thread_mutex_lock(clientdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=clientdata->groups;

  //Count them first so we can size the array
  while (scan)
    {
      count++;
      scan=scan->next;
      if (scan==clientdata->groups)
	scan=NULL;
    }
  
  if (!count)
    {
      grapple_thread_mutex_unlock(clientdata->group_mutex);
      internal_client_release(clientdata);
      return GRAPPLE_OK;
    }

  //The array allocation
  grouplist=(int *)malloc(count * (sizeof(int)));
  
  scan=clientdata->groups;
  count=0;

  //Insert the groups into it
  while (scan)
    {
      grouplist[count++]=scan->id;
      scan=scan->next;
      if (scan==clientdata->groups)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(clientdata->group_mutex);

  //We now have the list of groups
  while (carry_on && count>0)
    {
      //Loop backwards through the groups. We make no guarentee of enumeration
      //order
      groupid=grouplist[--count];
      grapple_thread_mutex_lock(clientdata->group_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      scan=group_locate(clientdata->groups,groupid);
      tmpname=NULL;
      if (scan)
	{
	  //If the group has a name, note that
	  if (scan->name && *scan->name)
	    {
	      tmpname=(char *)malloc(strlen(scan->name)+1);
	      strcpy(tmpname,scan->name);
	    }
	}
      //We're finished with the mutex, unlock it
      grapple_thread_mutex_unlock(clientdata->group_mutex);

      if (groupid)
	{
	  //Run the callback
	  carry_on=(*callback)(groupid,tmpname,0,context);
	}

      if (tmpname)
	free(tmpname);
    }

  free(grouplist);

  internal_client_release(clientdata);

  return GRAPPLE_OK;
}

//Get an int array list of groups
grapple_user *grapple_client_grouplist_get(grapple_client client)
{
  internal_client_data *clientdata;
  int *grouplist;
  int count;
  internal_grapple_group *scan;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  //Get the group list into an array
  count=0;
  scan=clientdata->groups;

  grapple_thread_mutex_lock(clientdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Count them first so we can size the array
  while (scan)
    {
      count++;
      scan=scan->next;
      if (scan==clientdata->groups)
	scan=NULL;
    }
  
  if (!count)
    {
      grapple_thread_mutex_unlock(clientdata->group_mutex);
      internal_client_release(clientdata);
      return NULL;
    }

  //The array allocation
  grouplist=(int *)malloc((count+1) * (sizeof(int)));
  
  scan=clientdata->groups;
  count=0;

  //Insert the groups into it
  while (scan)
    {
      grouplist[count++]=scan->id;
      scan=scan->next;
      if (scan==clientdata->groups)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(clientdata->group_mutex);

  grouplist[count]=0;

  internal_client_release(clientdata);

  //We now have the list of groups
  return grouplist;
}

char *grapple_client_groupname_get(grapple_client client,grapple_user groupid)
{
  internal_client_data *clientdata;
  internal_grapple_group *group;
  char *groupname;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  grapple_thread_mutex_lock(clientdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  group=group_locate(clientdata->groups,groupid);

  if (!group)
    {
      grapple_thread_mutex_unlock(clientdata->group_mutex);
      grapple_client_error_set(clientdata,GRAPPLE_ERROR_NO_SUCH_GROUP);
      internal_client_release(clientdata);
      return NULL;
    }


  groupname=(char *)malloc(strlen(group->name)+1);
  strcpy(groupname,group->name);

  grapple_thread_mutex_unlock(clientdata->group_mutex);

  internal_client_release(clientdata);

  return groupname;
}

//Variables, these values are to auto-sync across all users
void grapple_client_intvar_set(grapple_client client,const char *name,int val)
{
  internal_client_data *clientdata;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      //No client
      return;
    }

  //Set the value
  grapple_variable_set_int(clientdata->variables,name,val);

  //Sync this value to the server, and then onto the clients
  grapple_variable_client_sync(clientdata,name);

  //Done with this
  internal_client_release(clientdata);

  return;
}

int grapple_client_intvar_get(grapple_client client,const char *name)
{
  internal_client_data *clientdata;
  int returnval;
  grapple_error err;
  
  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      //No client
      return 0;
    }

  //Get the value
  err=grapple_variable_get_int(clientdata->variables,name,&returnval);
  grapple_client_error_set(clientdata,err);

  internal_client_release(clientdata);

  return returnval;
}

void grapple_client_doublevar_set(grapple_client client,const char *name,
				  double val)
{
  internal_client_data *clientdata;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      //No client
      return;
    }

  //Set the value
  grapple_variable_set_double(clientdata->variables,name,val);

  //Sync this value to the server, and then onto the clients
  grapple_variable_client_sync(clientdata,name);

  //Done with this
  internal_client_release(clientdata);

  return;
}

double grapple_client_doublevar_get(grapple_client client,const char *name)
{
  internal_client_data *clientdata;
  double returnval;
  grapple_error err;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      //No client
      return 0;
    }

  //Get the value
  err=grapple_variable_get_double(clientdata->variables,name,&returnval);
  grapple_client_error_set(clientdata,err);

  //Done with this
  internal_client_release(clientdata);

  return returnval;
}

void grapple_client_datavar_set(grapple_client client,const char *name,
				void *data,size_t len)
{
  internal_client_data *clientdata;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      //No client
      return;
    }

  //Set the value
  grapple_variable_set_data(clientdata->variables,name,data,len);

  //Sync this value to the server, and then onto the clients
  grapple_variable_client_sync(clientdata,name);

  internal_client_release(clientdata);

  return;
}

int grapple_client_datavar_get(grapple_client client,const char *name,
			       void *data,size_t *len)
{
  internal_client_data *clientdata;
  grapple_error err;

  //Find the client
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      //No client
      return GRAPPLE_FAILED;
    }

  //Get the value
  err=grapple_variable_get_data(clientdata->variables,name,data,len);

  grapple_client_error_set(clientdata,err);

  //Done with this
  internal_client_release(clientdata);

  if (err!=GRAPPLE_NO_ERROR)
    return GRAPPLE_FAILED;

  return GRAPPLE_OK;
}

//Get the last error
grapple_error grapple_client_error_get(grapple_client client)
{
  internal_client_data *clientdata;
  grapple_error returnval;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!clientdata)
    {
      grapple_error_get(); //Just to wipe it
      return GRAPPLE_ERROR_NOT_INITIALISED;
    }

  returnval=clientdata->last_error;

  //Now wipe the last error
  clientdata->last_error=GRAPPLE_NO_ERROR;

  internal_client_release(clientdata);

  if (returnval==GRAPPLE_NO_ERROR)
    returnval=grapple_error_get();
  else
    grapple_error_get(); //Just to wipe it

  return returnval;
}

grapple_certificate *grapple_client_certificate_get(grapple_client client)
{
#ifndef SOCK_SSL
  return NULL;
#else

  internal_client_data *clientdata;
  socket_certificate *cert=NULL;
  grapple_certificate *returnval;
  
  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return NULL;
    }

  cert=socket_certificate_get(clientdata->sock);

  //Done with this
  internal_client_release(clientdata);

  if (!cert)
    return NULL;

  //Convert this to a grapple_certificate
  returnval=(grapple_certificate *)calloc(1,sizeof(grapple_certificate));

  returnval->serial=cert->serial;
  returnval->not_before=cert->not_before;
  returnval->not_after=cert->not_after;
  returnval->issuer=cert->issuer;
  returnval->subject=cert->subject;

  free(cert);

  return returnval;
#endif
}

int grapple_client_dispatchers_set(grapple_client client,int num)
{
  internal_client_data *clientdata;
  int loopa;
  int all_done=0;

  clientdata=internal_client_get(client,GRAPPLE_LOCKTYPE_SHARED);

  if (!clientdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  if (!clientdata->thread)
    {
      //We havent started yet, just set the number
      clientdata->dispatcher_count=num;
      internal_client_release(clientdata);
      return GRAPPLE_OK;
    }
  
  grapple_thread_mutex_lock(clientdata->dispatcher_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (num > clientdata->dispatcher_count)
    {
      clientdata->dispatcherlist=(grapple_callback_dispatcher **)realloc(clientdata->dispatcherlist,sizeof(grapple_callback_dispatcher *)*(num+1));
  
      for (loopa=clientdata->dispatcher_count;loopa <num;loopa++)
	clientdata->dispatcherlist[loopa]=grapple_callback_dispatcher_create(0,clientdata);
      clientdata->dispatcherlist[loopa]=NULL;
      clientdata->dispatcher_count=num;
    }
  else if (num < clientdata->dispatcher_count)
    {
      for (loopa=num;loopa < clientdata->dispatcher_count;loopa++)
	clientdata->dispatcherlist[loopa]->finished=1;
      
      all_done=0;
      while (all_done==0)
	{
	  all_done=1;
	  
	  loopa=num;
	  while (all_done && clientdata->dispatcherlist[loopa])
	    {
	      if (clientdata->dispatcherlist[loopa]->finished==1)
		all_done=0;
	      loopa++;
	    }

	  if (!all_done)
	    //They havent all finished hasnt finished
	    microsleep(1000);
	}

      loopa=num;
      while (clientdata->dispatcherlist[loopa])
	{
	  clientdata->dispatcherlist[loopa]->finished=3;
	  clientdata->dispatcherlist[loopa]=NULL;
	  loopa++;
	}
      clientdata->dispatcher_count=num;

    }
  
  grapple_thread_mutex_unlock(clientdata->dispatcher_mutex);
  
  //Done with this
  internal_client_release(clientdata);

  return GRAPPLE_OK;
}
