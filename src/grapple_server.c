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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "grapple_defines.h"
#include "grapple_server.h"
#include "grapple_server_internal.h"
#include "grapple_server_thread.h"
#include "grapple_error_internal.h"
#include "grapple_queue.h"
#include "grapple_message_internal.h"
#include "grapple_connection.h"
#include "grapple_comms_api.h"
#include "grapple_callback.h"
#include "grapple_callback_internal.h"
#include "grapple_group.h"
#include "grapple_group_internal.h"
#include "grapple_internal.h"
#include "grapple_variable.h"
#include "grapple_certificate.h"
#include "socket.h"
#include "tools.h"
#include "prototypes.h"
#include "grapple_callback_dispatcher.h"

/**************************************************************************
 ** The functions in this file are generally those that are accessible   **
 ** to the end user. Obvious exceptions are those that are static which  **
 ** are just internal utilities.                                         **
 ** Care should be taken to not change the parameters of outward facing  **
 ** functions unless absolutely required                                 **
 **************************************************************************/


//This is a static variable which keeps track of the list of all servers
//run by this program. The servers are kept in a linked list. This variable
//is global to this file only.
static internal_server_data *grapple_server_head=NULL;

//And this is the mutex to make this threadsafe
static grapple_thread_mutex *server_mutex=NULL;

//Link a server to the list
static int internal_server_link(internal_server_data *data)
{
  grapple_thread_mutex_lock(server_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  if (!grapple_server_head)
    {
      grapple_server_head=data;
      data->next=data;
      data->prev=data;
      grapple_thread_mutex_unlock(server_mutex);
      return 1;
    }

  data->next=grapple_server_head;
  data->prev=grapple_server_head->prev;
  data->next->prev=data;
  data->prev->next=data;

  grapple_server_head=data;

  grapple_thread_mutex_unlock(server_mutex);
  
  return 1;
}
//Remove a server from the linked list
static int internal_server_unlink(internal_server_data *data)
{
  grapple_thread_mutex_lock(server_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  if (data->next==data)
    {
      grapple_server_head=NULL;
      grapple_thread_mutex_unlock(server_mutex);
      return 1;
    }

  data->next->prev=data->prev;
  data->prev->next=data->next;

  if (data==grapple_server_head)
    grapple_server_head=data->next;

  grapple_thread_mutex_unlock(server_mutex);

  //This is outside the list now so can be done unmutexed
  data->next=NULL;
  data->prev=NULL;

  return 1;
}



static int init_server_mutex(void)
{
  if (!server_mutex)
    server_mutex=grapple_thread_mutex_init();

  return 1;
}

//Find the server from the ID number passed by the user
internal_server_data *internal_server_get(grapple_server num,
					  grapple_mutex_locktype type)

{
  internal_server_data *scan;
  int finished=0,found;

  while (!finished)
    {
      //By default if passed 0, then the oldest server is returned
      if (!num)
	{
	  grapple_thread_mutex_lock(server_mutex,GRAPPLE_LOCKTYPE_SHARED);

	  if (!grapple_server_head)
	    {
	      grapple_thread_mutex_unlock(server_mutex);
	      
	      return NULL;
	    }

	  if (grapple_thread_mutex_trylock(grapple_server_head->inuse,
					   type)==0)
	    {
	      grapple_thread_mutex_unlock(server_mutex);
	      return grapple_server_head;
	    }

	  if (grapple_server_head->threaddestroy)
	    {
	      //It is in the process of being destroyed, we cant use it
	      //and in all likelyhood we are trying to call it
	      //from inside the dispatcher
	      grapple_thread_mutex_unlock(server_mutex);
	      return NULL;
	    }

	  grapple_thread_mutex_unlock(server_mutex);
	}
      else
	{
	  grapple_thread_mutex_lock(server_mutex,GRAPPLE_LOCKTYPE_SHARED);

	  //Loop through the servers
	  scan=grapple_server_head;

	  found=0;

	  while (scan && !found)
	    {
	      if (scan->servernum==num)
		{
		  if (grapple_thread_mutex_trylock(scan->inuse,
						   type)==0)
		    {
		      //Match and return it
		      grapple_thread_mutex_unlock(server_mutex);
		      return scan;
		    }
		  //It is in use, we cant use it yet

		  if (scan->threaddestroy)
		    {
		      //It is in the process of being destroyed, we cant use it
		      //and in all likelyhood we are trying to call it
		      //from inside the dispatcher
		      grapple_thread_mutex_unlock(server_mutex);
		      return NULL;
		    }

		  //Mark it as found though so we dont exit
		  found=1;
		}
      
	      scan=scan->next;
	      if (scan==grapple_server_head)
		scan=NULL;
	    }
	  grapple_thread_mutex_unlock(server_mutex);

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

static void internal_server_release(internal_server_data *target)
{
  //We dont need to mutex this, we definitely HAVE it, and we are just
  //releasing it, and it wont be referenced again - it cant be deleted like
  //this

  grapple_thread_mutex_unlock(target->inuse);
}

//Create a new server
static internal_server_data *server_create(void)
{
  static int nextval=1;
  internal_server_data *serverdata;

  //Create the structure
  serverdata=(internal_server_data *)calloc(1,sizeof(internal_server_data));

  //Assign it a default ID
  serverdata->servernum=nextval++;

  serverdata->connection_mutex=grapple_thread_mutex_init();
  serverdata->group_mutex=grapple_thread_mutex_init();
  serverdata->failover_mutex=grapple_thread_mutex_init();
  serverdata->message_in_mutex=grapple_thread_mutex_init();
  serverdata->callback_mutex=grapple_thread_mutex_init();
  serverdata->confirm_mutex=grapple_thread_mutex_init();
  serverdata->internal_mutex=grapple_thread_mutex_init();
  serverdata->dispatcher_mutex=grapple_thread_mutex_init();
  serverdata->event_queue_mutex=grapple_thread_mutex_init();

  serverdata->inuse=grapple_thread_mutex_init();
  serverdata->notify=GRAPPLE_NOTIFY_STATE_ON;

  serverdata->user_serverid=65536;

  //Create the variable hash. If you have a LOT of variables, you may
  //want to change this number to speedup looking. The same change should
  //be made in grapple_client.c
  serverdata->variables=grapple_variable_hash_init(27);

  return serverdata;
}


//User function for initialising the server
grapple_server grapple_server_init(const char *name,const char *version)
{
  internal_server_data *serverdata;
  grapple_server returnval;

  init_server_mutex();

  //Create the internal data
  serverdata=server_create();

  //Assign the user supplied values
  serverdata->productname=(char *)malloc(strlen(name)+1);
  strcpy(serverdata->productname,name);

  serverdata->productversion=(char *)malloc(strlen(version)+1);
  strcpy(serverdata->productversion,version);

  //Set the default name policy
  serverdata->namepolicy=GRAPPLE_NAMEPOLICY_NONE;

  returnval=serverdata->servernum;

  serverdata->sequential=1;

  //Link it into the array of servers
  internal_server_link(serverdata);

  //Return the server ID - the end user only gets an integer, called a
  //'grapple_server'

  return returnval;
}

//Set whether to try to use a NAT traversal server
int grapple_server_nattrav_address(grapple_server server,
				   const char *hostname,int port)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      //We are already started, cannot start nattrav now
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      return GRAPPLE_FAILED;
    }

  if (serverdata->protocol!=GRAPPLE_PROTOCOL_UDP)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_PROTOCOL_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (serverdata->dummymode)
    {
      internal_server_release(serverdata);
      return GRAPPLE_OK;
    }

  //Free the old data if set
  if (serverdata->nattrav_server_hostname)
    free (serverdata->nattrav_server_hostname);

  //Set the new value
  if (hostname)
    {
      serverdata->nattrav_server_hostname=(char *)malloc(strlen(hostname)+1);
      strcpy(serverdata->nattrav_server_hostname,hostname);
    }
  serverdata->nattrav_server_port=port;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

int grapple_server_set_as_nattrav_server(grapple_server server,
					 const char *server2_host,
					 int server2_port,int port2,
					 int enable_turn)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      //We are already started, cannot start nattrav now
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      return GRAPPLE_FAILED;
    }

  if (serverdata->protocol!=GRAPPLE_PROTOCOL_UDP)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_PROTOCOL_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Free the old data if set
  if (serverdata->nattrav_server2_hostname)
    free (serverdata->nattrav_server2_hostname);

  //Set the new value
  serverdata->nattrav_server2_hostname=(char *)malloc(strlen(server2_host)+1);
  strcpy(serverdata->nattrav_server2_hostname,server2_host);
  serverdata->nattrav_server2_port=server2_port;
  serverdata->nattrav_server_port2=port2;
  serverdata->nattrav_turn_enabled=enable_turn;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Set the port number to connect to
int grapple_server_port_set(grapple_server server,int port)
{
  internal_server_data *serverdata;

  //Get the server data
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Set the port
  serverdata->port=port;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Ask what type of NAT we are using
grapple_nat_type grapple_server_nattrav_type_get(grapple_server server)
{
  internal_server_data *serverdata;
  

  //Get the server data
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_NAT_UNKNOWN;
    }

  switch (socket_inet_udp2way_listener_stun_type_get(serverdata->sock))
    {
    case SOCKET_NAT_TYPE_UNKNOWN:
      internal_server_release(serverdata);
      return GRAPPLE_NAT_UNKNOWN;
      break;
    case SOCKET_NAT_TYPE_NONE:
      internal_server_release(serverdata);
      return GRAPPLE_NAT_OPEN;
      break;
    case SOCKET_NAT_TYPE_FULL_CONE:
      internal_server_release(serverdata);
      return GRAPPLE_NAT_FULL_CONE;
      break;
    case SOCKET_NAT_TYPE_RESTRICTED_CONE:
      internal_server_release(serverdata);
      return GRAPPLE_NAT_HOST_RESTRICTED;
      break;
    case SOCKET_NAT_TYPE_PORT_RESTRICTED_CONE:
      internal_server_release(serverdata);
      return GRAPPLE_NAT_PORT_RESTRICTED;
      break;
    case SOCKET_NAT_TYPE_SYMMETRIC:
    case SOCKET_NAT_TYPE_FW_SYMMETRIC:
      internal_server_release(serverdata);
      return GRAPPLE_NAT_SYMMETRIC;
      break;
    }
    
  internal_server_release(serverdata);
  return GRAPPLE_NAT_UNKNOWN;
}

const char *grapple_server_nattrav_type_string_get(grapple_server server)
{
  grapple_nat_type type;

  type=grapple_server_nattrav_type_get(server);

  switch (type)
    {
    case GRAPPLE_NAT_UNKNOWN:
      return "Unknown NAT type";
      break;
    case GRAPPLE_NAT_OPEN:
      return "Open Internet";
    case GRAPPLE_NAT_FULL_CONE:
      return "Full Cone NAT";
    case GRAPPLE_NAT_PORT_RESTRICTED:
      return "Port Restricted NAT";
    case GRAPPLE_NAT_HOST_RESTRICTED:
      return "Host Restricted NAT";
    case GRAPPLE_NAT_SYMMETRIC:
      return "Symmetric NAT";
    }

  return "Unknown NAT type";
}

//Retrieve the port number
int grapple_server_port_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  //Get the server data
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return 0;
    }

  //Return the port
  returnval=serverdata->port;

  internal_server_release(serverdata);
    
  return returnval;
}

//Set the IP address to bind to. This is an optional, if not set, then all
//local addresses are bound to
int grapple_server_ip_set(grapple_server server,const char *ip)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (ip)
    {
      //Free the old data if set
      if (serverdata->ip)
	free (serverdata->ip);
      
      //Set the new value
      serverdata->ip=(char *)malloc(strlen(ip)+1);
      strcpy(serverdata->ip,ip);
    }

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the IP address we have bound to
const char *grapple_server_ip_get(grapple_server server)
{
  internal_server_data *serverdata;
  const char *returnval;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }
  
  //Send the IP back - this may or may not be NULL
  returnval=serverdata->ip;

  internal_server_release(serverdata);

  return returnval;
}

//Set the user name policy for this server
int grapple_server_namepolicy_set(grapple_server server,
				grapple_namepolicy namepolicy)
{
  internal_server_data *serverdata;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Set the name policy
  serverdata->namepolicy=namepolicy;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the protocol
grapple_namepolicy grapple_server_namepolicy_get(grapple_server server)
{
  internal_server_data *serverdata;
  grapple_namepolicy returnval;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_NAMEPOLICY_NONE;
    }

  //Return the protocol
  returnval=serverdata->namepolicy;

  internal_server_release(serverdata);

  return returnval;
}

//Set the user name policy for this server
int grapple_server_protectionkeypolicy_set(grapple_server server,
					   grapple_protectionkeypolicy protectionkeypolicy)
{
  internal_server_data *serverdata;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Set the name policy
  serverdata->protectionkeypolicy=protectionkeypolicy;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Set the protocol this server must use
int grapple_server_protocol_set(grapple_server server,
				grapple_protocol protocol)
{
  internal_server_data *serverdata;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Set the protocol
  serverdata->protocol=protocol;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the protocol
grapple_protocol grapple_server_protocol_get(grapple_server server)
{
  internal_server_data *serverdata;
  grapple_protocol returnval;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_PROTOCOL_UNKNOWN;
    }

  //Return the protocol
  returnval=serverdata->protocol;

  internal_server_release(serverdata);

  return returnval;
}

//Set the protocol this server must use
int grapple_server_encryption_enable(grapple_server server,
				     const char *private_key,
				     const char *private_key_password,
				     const char *public_key,
				     const char *cert_auth)
{
#ifndef SOCK_SSL
  return GRAPPLE_FAILED;
#else
  internal_server_data *serverdata;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Set the protocol
  serverdata->encrypted=1;

  if (serverdata->public_key)
    free(serverdata->public_key);

  if (public_key)
    {
      serverdata->public_key=(char *)malloc(strlen(public_key)+1);
      strcpy(serverdata->public_key,public_key);
    }
  else
    {
      serverdata->public_key=NULL;
    }

  if (serverdata->private_key)
    free(serverdata->private_key);

  if (private_key)
    {
      serverdata->private_key=(char *)malloc(strlen(private_key)+1);
      strcpy(serverdata->private_key,private_key);
    }
  else
    {
      serverdata->private_key=NULL;
    }

  if (serverdata->private_key_password)
    free(serverdata->private_key_password);

  if (private_key_password)
    {
      serverdata->private_key_password=
	(char *)malloc(strlen(private_key_password)+1);
      strcpy(serverdata->private_key_password,private_key_password);
    }
  else
    {
      serverdata->private_key_password=NULL;
    }

  if (serverdata->cert_auth)
    free(serverdata->cert_auth);

  if (cert_auth)
    {
      serverdata->cert_auth=(char *)malloc(strlen(cert_auth)+1);
      strcpy(serverdata->cert_auth,cert_auth);
    }
  else
    {
      serverdata->cert_auth=NULL;
    }

  internal_server_release(serverdata);

  return GRAPPLE_OK;
#endif
}

//Find out if this server is running
int grapple_server_running(grapple_server server)
{
  internal_server_data *serverdata;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      //No server, not running
      return 0;
    }

  if (serverdata->dummymode)
    {
      internal_server_release(serverdata);
      return 1;
    }

  if (serverdata->sock)
    {
      if (socket_dead(serverdata->sock))
	{
	  internal_server_release(serverdata);
	  return 0;
	}

      internal_server_release(serverdata);
      //Have a live socket, running
      return 1;
    }

  internal_server_release(serverdata);
  //Otherwise, not running
  return 0;
}

//Set the maximum number of users that may connect to the server at any time
int grapple_server_maxusers_set(grapple_server server,int maxusers)
{
  internal_server_data *serverdata;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }


  //Set the value
  serverdata->maxusers=maxusers;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the maximum number of users that may connect to the server at any time
int grapple_server_maxusers_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return 0;
    }

  //Get the value
  returnval=serverdata->maxusers;

  internal_server_release(serverdata);

  return returnval;
}

int grapple_server_currentusers_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return 0;
    }

  //Get the value
  returnval=serverdata->usercount;

  internal_server_release(serverdata);

  return returnval;
}

//Set the maximum number of groups that may be created on this server
int grapple_server_maxgroups_set(grapple_server server,int maxgroups)
{
  internal_server_data *serverdata;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }


  //Set the value
  serverdata->maxgroups=maxgroups;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the maximum number of groups that may be created on this server
int grapple_server_maxgroups_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return 0;
    }

  //Get the value
  returnval=serverdata->maxgroups;

  internal_server_release(serverdata);

  return returnval;
}

//Count the number of outstanding messages in the incoming queue
int grapple_server_messagecount_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  //Find the server data
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(serverdata->message_in_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Count the messages
  returnval=grapple_queue_count(serverdata->message_in_queue);

  grapple_thread_mutex_unlock(serverdata->message_in_mutex);

  internal_server_release(serverdata);

  //Return the count
  return returnval;

}

//return true if there are any messages waiting
int grapple_server_messages_waiting(grapple_server server)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->message_in_queue)
    {
      internal_server_release(serverdata);
      return 1;
    }
  else
    {
      internal_server_release(serverdata);
      return 0;
    }
}

//Start the server
int grapple_server_start(grapple_server server)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Check the servers minimum defaults are set
  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (!serverdata->port)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_PORT_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (!serverdata->protocol)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_PROTOCOL_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (!serverdata->session)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SESSION_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (serverdata->dummymode)
    serverdata->dummymode=0;

  switch (serverdata->protocol)
    {
    case GRAPPLE_PROTOCOL_UNKNOWN:
      break;
    case GRAPPLE_PROTOCOL_TCP:
      //Create a TCP listener socket
      serverdata->sock=socket_create_inet_tcp_listener_on_ip(serverdata->ip,
							     serverdata->port);
      break;
    case GRAPPLE_PROTOCOL_UDP:
      //Create a 2 way UDP listener socket
      serverdata->sock=
	socket_create_inet_udp2way_listener_on_ip(serverdata->ip,
						  serverdata->port);
      break;
    }

  if (!serverdata->sock)
    {
      //The socket couldnt be created
      grapple_server_error_set(serverdata,
			       GRAPPLE_ERROR_SERVER_CANNOT_BIND_SOCKET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //If encrypted, set the encryption data on them
#ifdef SOCK_SSL
  if (serverdata->encrypted && serverdata->protocol==GRAPPLE_PROTOCOL_TCP)
    {
      if (serverdata->private_key)
	socket_set_private_key(serverdata->sock,serverdata->private_key,
			      serverdata->private_key_password);
      if (serverdata->public_key)
	socket_set_public_key(serverdata->sock,serverdata->public_key);
      if (serverdata->cert_auth)
	socket_set_ca(serverdata->sock,serverdata->cert_auth);
      socket_set_encrypted(serverdata->sock);
    }
#endif

  //Become a STUN server if we need to
  if (serverdata->nattrav_server2_hostname)
    {
      socket_inet_udp2way_listener_stun_enable(serverdata->sock,
					       serverdata->nattrav_server2_hostname,
					       serverdata->nattrav_server2_port,
					       serverdata->nattrav_server_port2);
      if (serverdata->nattrav_turn_enabled)
	socket_inet_udp2way_listener_turn_enable(serverdata->sock);
    }
  
  //Set the socket mode to be sequential if required
  if (serverdata->sequential)
    socket_mode_set(serverdata->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);
  else 
    socket_mode_unset(serverdata->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);

  //Start up the wakeup socket. This is a socket that can break into the 
  //long timeout incoming loop, tell it that there is something to do locally
  serverdata->wakesock=socket_create_interrupt();

  //Start the server thread that will handle all the communication
  grapple_server_thread_start(serverdata);

  //STUN this socket if we need to
  if (serverdata->nattrav_server_hostname)
    {
      const char *ip;
	
      socket_inet_udp2way_listener_stun(serverdata->sock,
					serverdata->nattrav_server_hostname,
					serverdata->nattrav_server_port);

      while (!socket_inet_udp2way_listener_stun_complete(serverdata->sock))
	{
	  internal_server_release(serverdata);
	  microsleep(1000);
	  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

	  if (!serverdata)
	    {
	      return GRAPPLE_FAILED;
	    }
	}

      free(serverdata->nattrav_server_hostname);
      serverdata->nattrav_server_hostname=NULL;	  

      ip=socket_host_get(serverdata->sock);
      if (ip)
	{
	  if (serverdata->ip)
	    free(serverdata->ip);

	  serverdata->ip=(char *)malloc(strlen(ip)+1);
	  strcpy(serverdata->ip,ip);
	  
	  serverdata->port=socket_get_port(serverdata->sock);
	}
    }

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}


//Pretend to start the server - this utility is useful for debug purposes
//or for using a fake running server to mask another type of connection
//over grapple
int grapple_server_dummystart(grapple_server server)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Check the servers minimum defaults are set
  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (!serverdata->port)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_PORT_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (!serverdata->port)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_PROTOCOL_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  if (!serverdata->session)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SESSION_NOT_SET);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  serverdata->dummymode=1;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Pull the oldest message
grapple_message *grapple_server_message_pull(grapple_server server)
{
  internal_server_data *serverdata;
  grapple_queue *queuedata;
  grapple_message *returnval=NULL;

  //Find the server data
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return NULL;
    }
  
  grapple_thread_mutex_lock(serverdata->message_in_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  if (serverdata->message_in_queue)
    {
      //Remove the oldest message
      queuedata=serverdata->message_in_queue;
      serverdata->message_in_queue=
	queue_unlink(serverdata->message_in_queue,
		     serverdata->message_in_queue);
      
      grapple_thread_mutex_unlock(serverdata->message_in_mutex);


      /*Now we have the message, clone it into a new form useful for the end
	user*/
      returnval=server_convert_message_for_user(queuedata);
      
      //Get rid of the queue message
      queue_struct_dispose(queuedata);
    }
  else
    {
      grapple_thread_mutex_unlock(serverdata->message_in_mutex);
    }
  
  internal_server_release(serverdata);

  //Return the message
  return returnval;
}

//This is the function used to send messages by the server to either
//the one or more clients, or a group
grapple_confirmid grapple_server_send(grapple_server server,
				      grapple_user serverid,
				      int flags,const void *data,
				      size_t datalen)
{
  internal_server_data *serverdata;
  grapple_connection *target,*scan;
  grapple_confirmid thismessageid=0;
  static int staticmessageid=1; /*This gets incrimented for each message
				  that is requiring confirmation*/
  int *group_data,loopa,count=0;

  //Find the data
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
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

  switch (serverid)
    {
    case GRAPPLE_USER_UNKNOWN:
      //The target was the unknown user - cant send to this one
      break;
    case GRAPPLE_EVERYONE:
      //Sending a message to ALL players
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Loop through all players
      scan=serverdata->userlist;
      while (scan)
	{
	  //Send a message to this one
	  s2c_message(serverdata,scan,flags,thismessageid,data,datalen);

	  //Count the number sent to
	  count++;
	  scan=scan->next;
	  if (scan==serverdata->userlist)
	    scan=0;
	}
      grapple_thread_mutex_unlock(serverdata->connection_mutex);
      break;
    default:
      //Sending to a specific single user or a group
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Locate the user
      target=connection_from_serverid(serverdata->userlist,serverid);
      if (target)
	{
	  //Send to the user
	  s2c_message(serverdata,target,flags,thismessageid,data,datalen);

	  //Count it
	  count++;
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);
	}
      else
	{
	  //Cant find a user with that ID
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);

	  //Try and send to a group instead, as there is no such user
	  grapple_thread_mutex_lock(serverdata->group_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);
	  if (group_locate(serverdata->groups,serverid))
	      {
		//We have a group that matches
		grapple_thread_mutex_unlock(serverdata->group_mutex);

		//Get the mist of all users in the group
		group_data=server_group_unroll(serverdata,serverid);
		
		//Loop through this array of ints
		loopa=0;
		while (group_data[loopa])
		  {
		    grapple_thread_mutex_lock(serverdata->connection_mutex,
					      GRAPPLE_LOCKTYPE_SHARED);
		    
		    //Loop through the users
		    scan=serverdata->userlist;
		    while (scan)
		      {
			if (scan->serverid==group_data[loopa])
			  {
			    //The user is a match
			    //Send the message to them
			    s2c_message(serverdata,scan,flags,thismessageid,
					data,datalen);

			    //Count the send
			    count++;
			    break;
			  }
			
			scan=scan->next;
			if (scan==serverdata->userlist)
			  scan=0;
		      }
		    
		    grapple_thread_mutex_unlock(serverdata->connection_mutex);
		    loopa++;
		  }
		free(group_data);
	      }
	    else
	      {
		//Cant find any match for the user to send to
		grapple_thread_mutex_unlock(serverdata->group_mutex);
		grapple_server_error_set(serverdata,
					 GRAPPLE_ERROR_NO_SUCH_USER);
		internal_server_release(serverdata);
		return GRAPPLE_FAILED;
	      }
	}
      break;
    }

  //If we didnt send to anyone, but they requested a message be sent, we send
  //a confirm message right back to the server queue
  if (count == 0 && flags & GRAPPLE_CONFIRM)
    {
      s2SUQ_confirm_received(serverdata,thismessageid);
    }
  else
    {
      if (flags & GRAPPLE_WAIT)
	{
	  serverdata->sendwait=thismessageid;

	  while (serverdata->sendwait==thismessageid)
	    microsleep(1000);
	}
    }

  internal_server_release(serverdata);

  //Return the message ID
  return thismessageid;
}

//Destroy the server
int grapple_server_destroy(grapple_server server)
{
  internal_server_data *serverdata;
  grapple_queue *target;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Remove it from the list
  internal_server_unlink(serverdata);

  internal_server_release(serverdata);

  //Tell the thread to kill itself
  if (serverdata->thread)
    {
      serverdata->threaddestroy=1;

      grapple_thread_mutex_lock(serverdata->internal_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      if (serverdata->wakesock)
	socket_interrupt(serverdata->wakesock);
      grapple_thread_mutex_unlock(serverdata->internal_mutex);

      while (serverdata->threaddestroy==1 && serverdata->thread)
	microsleep(1000);

      serverdata->threaddestroy=0;
    }

  //Free memory
  if (serverdata->session)
    free(serverdata->session);
  if (serverdata->password)
    free(serverdata->password);
  if (serverdata->productname)
    free(serverdata->productname);
  if (serverdata->productversion)
    free(serverdata->productversion);
  if (serverdata->ip)
    free(serverdata->ip);
  if (serverdata->nattrav_server_hostname)
    free(serverdata->nattrav_server_hostname);
  if (serverdata->nattrav_server2_hostname)
    free(serverdata->nattrav_server2_hostname);
    
#ifdef SOCK_SSL
  if(serverdata->private_key)
    free(serverdata->private_key);
  if(serverdata->public_key)
    free(serverdata->public_key);
#endif

  //Delete the message queue
  while (serverdata->message_in_queue)
    {
      target=serverdata->message_in_queue;
      serverdata->message_in_queue=queue_unlink(serverdata->message_in_queue,
						serverdata->message_in_queue);
      queue_struct_dispose(target);
    }

  //Delete the mutexes
  grapple_thread_mutex_destroy(serverdata->message_in_mutex);
  grapple_thread_mutex_destroy(serverdata->connection_mutex);
  grapple_thread_mutex_destroy(serverdata->group_mutex);
  grapple_thread_mutex_destroy(serverdata->failover_mutex);
  grapple_thread_mutex_destroy(serverdata->callback_mutex);
  grapple_thread_mutex_destroy(serverdata->confirm_mutex);
  grapple_thread_mutex_destroy(serverdata->internal_mutex);
  grapple_thread_mutex_destroy(serverdata->dispatcher_mutex);
  grapple_thread_mutex_destroy(serverdata->event_queue_mutex);

  grapple_thread_mutex_destroy(serverdata->inuse);

  //Free the stored variables  
  grapple_variable_hash_dispose(serverdata->variables);

  //Free the last bit
  free(serverdata);

  return GRAPPLE_OK;
}

//Get an array of ints - the users connected
grapple_user *grapple_server_userlist_get(grapple_server server)
{
  internal_server_data *serverdata;
  grapple_user *returnval;

  //Get the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  //Return the array.
  returnval=connection_server_intarray_get(serverdata);

  internal_server_release(serverdata);

  return returnval;
}

//Set a callback. Callbacks are so that instead of needing to poll for
//messages, a callback can be set so that the messages are handled immediately
int grapple_server_callback_set(grapple_server server,
				grapple_messagetype message,
				grapple_callback callback,
				void *context)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->dispatcher_count<1)
    {
      internal_server_release(serverdata);
      //Release and relock as dispatchers_set also wants exclusive
      grapple_server_dispatchers_set(server,1);
      serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      //Check its still here
      if (!serverdata)
	return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(serverdata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Add the callback to the list of callbacks
  serverdata->callbackanchor=grapple_callback_add(serverdata->callbackanchor,
						  message,callback,context);

  grapple_thread_mutex_unlock(serverdata->callback_mutex);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Set ALL callbacks to the function requested
int grapple_server_callback_setall(grapple_server server,
				   grapple_callback callback,
				   void *context)
{
  //Set one using the function above
  if (grapple_server_callback_set(server,GRAPPLE_MSG_NEW_USER,callback,
				  context)==GRAPPLE_FAILED)
    return GRAPPLE_FAILED;

  //if one is ok, they all should be
  grapple_server_callback_set(server,GRAPPLE_MSG_NEW_USER_ME,callback,context);
  grapple_server_callback_set(server,GRAPPLE_MSG_USER_MSG,callback,context);
  grapple_server_callback_set(server,GRAPPLE_MSG_USER_NAME,callback,context);
  grapple_server_callback_set(server,GRAPPLE_MSG_USER_MSG,callback,context);
  grapple_server_callback_set(server,GRAPPLE_MSG_SESSION_NAME,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_USER_DISCONNECTED,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_SERVER_DISCONNECTED,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_CONNECTION_REFUSED,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_PING,callback,context);
  grapple_server_callback_set(server,GRAPPLE_MSG_GROUP_CREATE,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_GROUP_ADD,callback,context);
  grapple_server_callback_set(server,GRAPPLE_MSG_GROUP_REMOVE,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_GROUP_DELETE,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_YOU_ARE_HOST,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_CONFIRM_RECEIVED,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_CONFIRM_TIMEOUT,callback,
			      context);
  grapple_server_callback_set(server,GRAPPLE_MSG_GAME_DESCRIPTION,callback,
			      context);

  return GRAPPLE_OK;
}

//Remove a callback
int grapple_server_callback_unset(grapple_server server,
				  grapple_messagetype message)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(serverdata->callback_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Remove the callback
  serverdata->callbackanchor=grapple_callback_remove(serverdata->callbackanchor,
						     message);
  
  grapple_thread_mutex_unlock(serverdata->callback_mutex);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the ID of the default server
grapple_server grapple_server_default_get()
{
  internal_server_data *serverdata;
  grapple_server returnval;

  if (!server_mutex)
    return 0;

  serverdata=internal_server_get(0,GRAPPLE_LOCKTYPE_SHARED);

  if (serverdata)
    {
      //Return its ID if we have it
      returnval=serverdata->servernum;

      internal_server_release(serverdata);
    }
  else
    //return 0 (the default anyway) if we dont
    returnval=0;

  return 0;
}

//Set the name of the session. This isnt functional it is cosmetic
int grapple_server_session_set(grapple_server server,const char *session)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->sock)
    {
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_SERVER_CONNECTED);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Remove the old value
  if (serverdata->session)
    free (serverdata->session);

  //Set the new
  serverdata->session=(char *)malloc(strlen(session)+1);
  strcpy(serverdata->session,session);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the name of the session.
const char *grapple_server_session_get(grapple_server server)
{
  internal_server_data *serverdata;
  const char *returnval;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  returnval=serverdata->session;

  internal_server_release(serverdata);

  //NOTE: This is not threadsafe, but the documentation requires the user to
  //ensure that this value is NOT used after the client is destroyed or
  //the value is changed. As such, we do not have to be threadsafe with this
  //value.
  return returnval;
}

//Set the name of the description. This isnt functional it is cosmetic,
//and it differs from sessions in that it can be set at any time, and
//it is capable of storing binary data
int grapple_server_description_set(grapple_server server,const void *data,
				   size_t length)
{
  grapple_connection *scan;

  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Remove the old value
  if (serverdata->description)
    free (serverdata->description);

  //Set the new
  if (length>0)
    {
      serverdata->description=(char *)malloc(length);
      memcpy(serverdata->description,data,length);
    }
  else
    serverdata->description=NULL;
  serverdata->descriptionlen=length;

  //Now tell everyone else

  //loop through the userlist
  scan=serverdata->userlist;
  while (scan)
    {
      //Send the message to them
      s2c_description_change(serverdata,scan,data,
			     length);
      
      scan=scan->next;
      if (scan==serverdata->userlist)
	scan=0;
    }

  //We're done
  internal_server_release(serverdata);
  
  return GRAPPLE_OK;
}

//Get the game description
int grapple_server_description_get(grapple_server server,void *buf,size_t *len)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return -1;
    }

  if (buf==NULL)
    {
      *len=serverdata->descriptionlen;
      if (serverdata->description)
	{
	  internal_server_release(serverdata);
	  return 0;
	}
      else
	{
	  internal_server_release(serverdata);
	  return 1;
	}
    }
    
  if (*len < serverdata->descriptionlen)
    {
      *len=serverdata->descriptionlen;
      internal_server_release(serverdata);
      return 0;
    }

  memcpy(buf,serverdata->description,serverdata->descriptionlen);
  *len=serverdata->descriptionlen;

  internal_server_release(serverdata);

  return 1;
}

//Set the password required to connect.
int grapple_server_password_set(grapple_server server,const char *password)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Free the memory if it is already set
  if (serverdata->password)
    free (serverdata->password);

  //Set the new
  serverdata->password=(char *)malloc(strlen(password)+1);
  strcpy(serverdata->password,password);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Set a password handler to use - for more complex password queries than the
//regular username/password per server system
int grapple_server_passwordhandler_set(grapple_server server,
				       grapple_password_callback handler,
				       void *context)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  serverdata->passwordhandler=handler;
  serverdata->passwordhandlercontext=context;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Set a connection callbackto use - for things like IP bans and the like,
//where we want to manage connections before they finish
int grapple_server_connectionhandler_set(grapple_server server,
					 grapple_connection_callback handler,
					 void *context)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  serverdata->connectioncallbackhandler=handler;
  serverdata->connectioncallbackhandlercontext=context;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}


//Find out if a password is required
int grapple_server_password_required(grapple_server server)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return 0;
    }

  ////If there is a password required - 1
  if (serverdata->password || serverdata->passwordhandler)
    {
      internal_server_release(serverdata);
      return 1;
    }

  internal_server_release(serverdata);
  //No password, return 0
  return 0;
}

//Find if the server is closed to new connections
int grapple_server_closed_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  returnval=serverdata->closed;

  internal_server_release(serverdata);

  //Return the value
  return returnval;
}

//Set the server closed or open. Closed will completely stop any
//users from connecting to the server. The server will reject the handshake
void grapple_server_closed_set(grapple_server server,int state)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return;
    }

  //Set the internal value
  serverdata->closed=state;

  internal_server_release(serverdata);

  return;
}

//Force a client to drop, so the server can kick people off
int grapple_server_disconnect_client(grapple_server server,
				     grapple_user serverid)
{
  grapple_connection *target;
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Find the target
  target=connection_from_serverid(serverdata->userlist,serverid);

  if (!target)
    {
      grapple_thread_mutex_unlock(serverdata->connection_mutex);
      //Cant find that user
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_NO_SUCH_USER);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Send a delete message to the client
  s2c_failover_off(serverdata,target);
  s2c_disconnect(serverdata,target);

  //Set the target to be deleted next round of the server thread
  user_set_delete(serverdata,target);

  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Stop the server - while keeping its data intact to start again
int grapple_server_stop(grapple_server server)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }


  //Stop the thread
  if (serverdata->thread)
    {
      serverdata->threaddestroy=1;

      grapple_thread_mutex_lock(serverdata->internal_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      if (serverdata->wakesock)
	socket_interrupt(serverdata->wakesock);
      grapple_thread_mutex_unlock(serverdata->internal_mutex);

      //Wait for the thread to stop
      while (serverdata->threaddestroy==1 && serverdata->thread)
	microsleep(1000);

      serverdata->threaddestroy=0;
    }

  internal_server_release(serverdata);

  //All done, the server is now ready to restart if required
  return GRAPPLE_OK;
}

//Stop a server running in dummy mode
int grapple_server_dummystop(grapple_server server)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  serverdata->dummymode=0;

  internal_server_release(serverdata);

  //All done, the server is now ready to restart if required
  return GRAPPLE_OK;
}

//Set the server into autoping mode. This will make the server ping all clients
//every frequency seconds.
int grapple_server_autoping(grapple_server server,double frequency)
{
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Set the value
  serverdata->autoping=frequency;

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Manually ping a user
int grapple_server_ping(grapple_server server,grapple_user serverid)
{
  internal_server_data *serverdata;
  grapple_connection *user;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Find the user
  user=connection_from_serverid(serverdata->userlist,serverid);

  if (!user)
    {
      grapple_thread_mutex_unlock(serverdata->connection_mutex);
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_NO_SUCH_USER);
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }


  //Send a ping. A reply will come back from the user in the form of a
  //queue message
  s2c_ping(serverdata,user,++user->pingnumber);

  gettimeofday(&user->pingstart,NULL);
  
  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get the last recorded ping time for a specific user
double grapple_server_ping_get(grapple_server server,grapple_user serverid)
{
  internal_server_data *serverdata;
  grapple_connection *user;
  double returnval;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return 0;
    }

  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  //Get the user
  user=connection_from_serverid(serverdata->userlist,serverid);

  if (!user)
    {
      grapple_thread_mutex_unlock(serverdata->connection_mutex);
      grapple_server_error_set(serverdata,GRAPPLE_ERROR_NO_SUCH_USER);
      internal_server_release(serverdata);
      return 0;
    }

  //Find that users pingtime
  returnval=user->pingtime;

  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  internal_server_release(serverdata);
  return returnval;
}

//Set failover mode on. Failover mode being where the server - if it dies -
//will be replaced by a new server from one fo the clients and all other
//clients will reconnect to the new server
int grapple_server_failover_set(grapple_server server,int value)
{
  internal_server_data *serverdata;
  grapple_connection *scan;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Set failover to be either on or off
  serverdata->failover=value;

  if (!serverdata->sock)
    {
      //This isnt a failure, we just cant tell anyone to failover yet, cos
      //nobody is connected
      internal_server_release(serverdata);
      return 0;
    }

  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);


  //Loop through each connected user  
  scan=serverdata->userlist;
  
  while (scan)
    {
      //Tell each user failover is either on or off
      if (value)
	s2c_failover_on(serverdata,scan);
      else
	{
	  s2c_failover_off(serverdata,scan);
	}
      
      scan=scan->next;
      if (scan==serverdata->userlist)
	scan=0;
    }
  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Returns the failover state of the server
int grapple_server_failover_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  //Locate the server internal data
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  //If we have no server, fail
  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }
  

  //Return the state
  returnval=serverdata->failover;

  internal_server_release(serverdata);
  
  return returnval;
}

//Set whether the server is in sequential mode or not
int grapple_server_sequential_set(grapple_server server,int value)
{
  internal_server_data *serverdata;
  grapple_connection *scan;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (value)
    {
      //Turn sequential on for the server
      serverdata->sequential=1;
      if (serverdata->sock)
	{
	  //Turn it on at the socket level
	  socket_mode_set(serverdata->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);

	  grapple_thread_mutex_lock(serverdata->connection_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);

	  //Loop all users and turn sequential on on the socket at this end
	  scan=serverdata->userlist;
	  while (scan)
	    {
	      scan->sequential=1;
	      if (scan->handshook && scan->sock)
		//Set the socket
		socket_mode_set(scan->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);

	      scan=scan->next;
	      if (scan==serverdata->userlist)
		scan=0;
	    }
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);
	}
    }
  else
    {
      //Turn sequential off for the server
      serverdata->sequential=0;
      if (serverdata->sock)
	{
	  //Turn it off at the socket level
	  socket_mode_unset(serverdata->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);

	  grapple_thread_mutex_lock(serverdata->connection_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);
	  //Loop all users and turn sequential off on the socket at this end
	  scan=serverdata->userlist;
	  while (scan)
	    {
	      scan->sequential=0;
	      if (scan->handshook && scan->sock)
		//Set the socket
		socket_mode_unset(scan->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);

	      scan=scan->next;
	      if (scan==serverdata->userlist)
		scan=0;
	    }
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);
	}
    }

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Find out if we are running sequential or not
int grapple_server_sequential_get(grapple_server server)
{
  internal_server_data *serverdata;
  int returnval;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Simply return the internal value
  returnval=serverdata->sequential;

  internal_server_release(serverdata);
  
  return returnval;
}

//Messages can be sent to groups, not just to users. This function
//returns the ID of a group from the name
grapple_user grapple_server_group_from_name(grapple_server server,const char *name)
{
  internal_server_data *serverdata;
  int returnval;
  internal_grapple_group *scan;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return 0;
    }

  grapple_thread_mutex_lock(serverdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Loop through all groups
  scan=serverdata->groups;

  while (scan)
    {
      //If the name matches
      if (!strcmp(scan->name,name))
	{
          //return this groups ID
	  returnval=scan->id;
	  grapple_thread_mutex_unlock(serverdata->group_mutex);
	  internal_server_release(serverdata);
	  return returnval;
	}

      scan=scan->next;
      if (scan==serverdata->groups)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(serverdata->group_mutex);

  internal_server_release(serverdata);

  //No ID to find

  return 0;
}

//create a group.
grapple_user grapple_server_group_create(grapple_server server,
					 const char *name,const char *password)
{
  //create a group.
  
  internal_server_data *serverdata;
  int returnval;
  grapple_connection *scan;
  char *cpassword;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (serverdata->maxgroups==GRAPPLE_GROUPS_DISABLED || 
      (serverdata->maxgroups >0 && 
       serverdata->groupcount >= serverdata->maxgroups))
    {
      internal_server_release(serverdata);
      return GRAPPLE_FAILED;
    }

  //Find the new ID
  returnval=serverdata->user_serverid++;

  //Create a group locally
  cpassword=group_crypt_twice(returnval,password);
  if (GRAPPLE_OK==create_server_group(serverdata,returnval,name,cpassword))
    {
      //Now go to each client and tell them there is a new group in town
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      
      scan=serverdata->userlist;
      while (scan)
	{
	  //Tell this user
	  s2c_group_create(serverdata,scan,returnval,name,
			   cpassword);
	  
	  scan=scan->next;
	  
	  if (scan==serverdata->userlist)
	    scan=0;
	}
      
      grapple_thread_mutex_unlock(serverdata->connection_mutex);

      if (cpassword)
	free(cpassword);
    }

  internal_server_release(serverdata);

  //Return the ID of the group
  return returnval;
}

//Adding a user to a group. This will mean that any messages sent to the
//group will also be sent to that user
int grapple_server_group_add(grapple_server server,grapple_user group,
			     grapple_user add,const char *password)
{
  internal_server_data *serverdata;
  grapple_connection *scan;
  char *cpassword;
  
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Now add to the group locally
  cpassword=group_crypt_twice(group,password);
  if (GRAPPLE_OK==server_group_add(serverdata,group,add,cpassword))
    {
      //Now go to each client and tell them there is a new member in this group
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      
      scan=serverdata->userlist;
      while (scan)
	{
	  //Send the message
	  s2c_group_add(serverdata,scan,group,add);
	  
	  scan=scan->next;
	  
	  if (scan==serverdata->userlist)
	    scan=0;
	}

      grapple_thread_mutex_unlock(serverdata->connection_mutex);

      if (cpassword)
	free(cpassword);

      internal_server_release(serverdata);
      return GRAPPLE_OK;
    }

  internal_server_release(serverdata);
  return GRAPPLE_FAILED;
}

//Remove a user from a group
int grapple_server_group_remove(grapple_server server,grapple_user group,
				grapple_user removeid)
{
  internal_server_data *serverdata;
  grapple_connection *scan;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Now remove a group member locally
  if (server_group_remove(serverdata,group,removeid))
    {
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Tell all connected users
      scan=serverdata->userlist;
      while (scan)
	{
	  //Send the message to this user
	  s2c_group_remove(serverdata,scan,group,removeid);
	  
	  scan=scan->next;
	  if (scan==serverdata->userlist)
	    scan=0;
	}
      
      grapple_thread_mutex_unlock(serverdata->connection_mutex);

      internal_server_release(serverdata);
      return GRAPPLE_OK;
    }

  internal_server_release(serverdata);

  return GRAPPLE_FAILED;
}

//Delete a group entirely
int grapple_server_group_delete(grapple_server server,grapple_user group)
{
  grapple_connection *scan;
  internal_server_data *serverdata;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Now delete the group locally
  if (delete_server_group(serverdata,group))
    {
      //Now go to each client and tell them 
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      
      scan=serverdata->userlist;
      while (scan)
	{
	  //Tell this user
	  s2c_group_delete(serverdata,scan,group);
	  
	  scan=scan->next;
	  if (scan==serverdata->userlist)
	    scan=0;
	}
      
      grapple_thread_mutex_unlock(serverdata->connection_mutex);

      internal_server_release(serverdata);
      return GRAPPLE_OK;
    }

  internal_server_release(serverdata);

  return GRAPPLE_FAILED;
}

grapple_user *grapple_server_groupusers_get(grapple_server server,
					    grapple_user groupid)
{
  internal_server_data *serverdata;
  grapple_user *userarray;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  //Get the user array
  userarray=server_group_unroll(serverdata,groupid);

  internal_server_release(serverdata);

  return userarray;
}

char *grapple_server_client_address_get(grapple_server server,
					grapple_user target)
{
  internal_server_data *serverdata;
  grapple_connection *user;
  char *returnval=0;
  const char *address;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  //Lock the user list
  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Locate the user
  user=connection_from_serverid(serverdata->userlist,target);

  if (user)
    {
      address=socket_host_get(user->sock);
      returnval=(char *)malloc(strlen(address)+1);
      strcpy(returnval,address);
    }

  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  internal_server_release(serverdata);

  return returnval;
}

//Find the port at this end for the client
int grapple_server_client_sending_port_get(grapple_server server,
					   grapple_user target)
{
  internal_server_data *serverdata;
  grapple_connection *user;
  int returnval=0;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return -1;
    }

  //Lock the user list
  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Locate the user
  user=connection_from_serverid(serverdata->userlist,target);

  if (user)
    {
      returnval=socket_get_sending_port(user->sock);
    }

  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  internal_server_release(serverdata);

  return returnval;
}

//Find the port at the remote end for the client
int grapple_server_client_port_get(grapple_server server,
				   grapple_user target)
{
  internal_server_data *serverdata;
  grapple_connection *user;
  int returnval=0;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return -1;
    }

  //Lock the user list
  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Locate the user
  user=connection_from_serverid(serverdata->userlist,target);

  if (user)
    {
      returnval=socket_get_port(user->sock);
    }

  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  internal_server_release(serverdata);

  return returnval;
}


//Enumerate the users. Effectively this means run the passed callback
//function for each user in the group
int grapple_server_enumgroup(grapple_server server,
			     grapple_user groupid,
			     grapple_user_enum_callback callback,
			     void *context)
{
  internal_server_data *serverdata;
  int *userarray;
  grapple_user serverid;
  int loopa;
  grapple_connection *user;
  char *tmpname;
  int carry_on=1;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Get the user array
  userarray=server_group_unroll(serverdata,groupid);

  loopa=0;

  //Loop for each user
  while (carry_on && userarray[loopa])
    {
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Find the user
      user=connection_from_serverid(serverdata->userlist,userarray[loopa]);
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
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);
	  
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
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);
	}
      
      loopa++;
    }

  free(userarray);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}


//Enumerate the list of groups, running a user function for each group
int grapple_server_enumgrouplist(grapple_server server,
				 grapple_user_enum_callback callback,
				 void *context)
{
  internal_server_data *serverdata;
  int *grouplist;
  grapple_user groupid;
  int count;
  char *tmpname;
  internal_grapple_group *scan;
  int carry_on=1;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }


  //The rest of this is pretty inefficient, but it is done this way for a
  //reason. It is done to minimise the lock time on the group mutex,
  //as calling a user function with that mutex locked could be disasterous for
  //performance.

  //Get the group list into an array
  count=0;
  scan=serverdata->groups;

  grapple_thread_mutex_lock(serverdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Count them first so we can size the array
  while (scan)
    {
      count++;
      scan=scan->next;
      if (scan==serverdata->groups)
	scan=NULL;
    }
  
  if (!count)
    {
      grapple_thread_mutex_unlock(serverdata->group_mutex);
      internal_server_release(serverdata);
      return GRAPPLE_OK;
    }

  //The array allocation
  grouplist=(int *)malloc(count * (sizeof(int)));
  
  scan=serverdata->groups;
  count=0;

  //Insert the groups into it
  while (scan)
    {
      grouplist[count++]=scan->id;
      scan=scan->next;
      if (scan==serverdata->groups)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(serverdata->group_mutex);

  //We now have the list of groups
  while (carry_on && count>0)
    {
      //Loop backwards through the groups. We make no guarentee of enumeration
      //order
      groupid=grouplist[--count];
      grapple_thread_mutex_lock(serverdata->group_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      scan=group_locate(serverdata->groups,groupid);
      tmpname=NULL;
      if (scan)
	{
	  //If the group has a name, note that
	  tmpname=(char *)malloc(strlen(scan->name)+1);
	  strcpy(tmpname,scan->name);
	}
      //We're finished with the mutex, unlock it
      grapple_thread_mutex_unlock(serverdata->group_mutex);

      if (groupid)
	{
	  //Run the callback
	  carry_on=(*callback)(groupid,tmpname,0,context);
	}

      if (tmpname)
	free(tmpname);
    }

  free(grouplist);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Get an int array list of groups
grapple_user *grapple_server_grouplist_get(grapple_server server)
{
  internal_server_data *serverdata;
  int *grouplist;
  int count;
  internal_grapple_group *scan;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  //Get the group list into an array
  count=0;
  scan=serverdata->groups;

  grapple_thread_mutex_lock(serverdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  
  //Count them first so we can size the array
  while (scan)
    {
      count++;
      scan=scan->next;
      if (scan==serverdata->groups)
	scan=NULL;
    }
  
  if (!count)
    {
      grapple_thread_mutex_unlock(serverdata->group_mutex);
      internal_server_release(serverdata);
      return NULL;
    }

  //The array allocation
  grouplist=(int *)malloc((count+1) * (sizeof(int)));
  
  scan=serverdata->groups;
  count=0;

  //Insert the groups into it
  while (scan)
    {
      grouplist[count++]=scan->id;
      scan=scan->next;
      if (scan==serverdata->groups)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(serverdata->group_mutex);

  internal_server_release(serverdata);

  grouplist[count]=0;

  //We now have the list of groups

  return grouplist;
}

//Enumerate the users. Effectively this means run the passed callback
//function for each user
int grapple_server_enumusers(grapple_server server,
			     grapple_user_enum_callback callback,
			     void *context)
{
  internal_server_data *serverdata;
  int *userarray;
  grapple_user serverid;
  int loopa;
  grapple_connection *user;
  char *tmpname;
  int carry_on=1;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Get the user array
  userarray=grapple_server_userlist_get(server);


  loopa=0;

  //Loop for each user
  while (carry_on && userarray[loopa])
    {
      grapple_thread_mutex_lock(serverdata->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Find the user
      user=connection_from_serverid(serverdata->userlist,userarray[loopa]);
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
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);
	  
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
	  grapple_thread_mutex_unlock(serverdata->connection_mutex);
	}
      
      loopa++;
    }

  free(userarray);

  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

char *grapple_server_groupname_get(grapple_server server,grapple_user groupid)
{
  internal_server_data *serverdata;
  internal_grapple_group *group;
  char *groupname;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  grapple_thread_mutex_lock(serverdata->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  group=group_locate(serverdata->groups,groupid);

  if (!group)
    {
      grapple_thread_mutex_unlock(serverdata->group_mutex);
      internal_server_release(serverdata);
      return NULL;
    }

  groupname=(char *)malloc(strlen(group->name)+1);
  strcpy(groupname,group->name);

  grapple_thread_mutex_unlock(serverdata->group_mutex);

  internal_server_release(serverdata);
  return groupname;
}

//Get the last error
grapple_error grapple_server_error_get(grapple_server server)
{
  internal_server_data *serverdata;
  grapple_error returnval;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      grapple_error_get(); //Just to wipe it
      return GRAPPLE_ERROR_NOT_INITIALISED;
    }

  returnval=serverdata->last_error;

  //Now wipe the last error
  serverdata->last_error=GRAPPLE_NO_ERROR;

  internal_server_release(serverdata);

  if (returnval==GRAPPLE_NO_ERROR)
    returnval=grapple_error_get();
  else
    grapple_error_get(); //Just to wipe it

  return returnval;
}

int grapple_server_notified_set(grapple_server server,
				int notify)
{
  internal_server_data *serverdata;

  //Get the client
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  //Only do the change if we are actually changing anything
  serverdata->notify=notify;
  internal_server_release(serverdata);

  return GRAPPLE_OK;
}

//Variables, these values are to auto-sync across all users
void grapple_server_intvar_set(grapple_server server,const char *name,int val)
{
  internal_server_data *serverdata;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      //No server
      return;
    }

  //Set the value
  grapple_variable_set_int(serverdata->variables,name,val);

  //Sync this value to the server, and then onto the servers
  grapple_variable_server_sync(serverdata,name);

  //Done with this
  internal_server_release(serverdata);

  return;
}

int grapple_server_intvar_get(grapple_server server,const char *name)
{
  internal_server_data *serverdata;
  int returnval;
  grapple_error err;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      //No server
      return 0;
    }

  //Get the value
  err=grapple_variable_get_int(serverdata->variables,name,&returnval);
  grapple_server_error_set(serverdata,err);

  internal_server_release(serverdata);

  return returnval;
}

void grapple_server_doublevar_set(grapple_server server,const char *name,double val)
{
  internal_server_data *serverdata;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      //No server
      return;
    }

  //Set the value
  grapple_variable_set_double(serverdata->variables,name,val);

  //Sync this value to the server, and then onto the servers
  grapple_variable_server_sync(serverdata,name);

  //Done with this
  internal_server_release(serverdata);

  return;
}

double grapple_server_doublevar_get(grapple_server server,const char *name)
{
  internal_server_data *serverdata;
  double returnval;
  grapple_error err;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      //No server
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return 0;
    }

  //Get the value
  err=grapple_variable_get_double(serverdata->variables,name,&returnval);
  grapple_server_error_set(serverdata,err);

  //Done with this
  internal_server_release(serverdata);

  return returnval;
}

void grapple_server_datavar_set(grapple_server server,const char *name,
				void *data,size_t len)
{
  internal_server_data *serverdata;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!serverdata)
    {
      //No server
      return;
    }

  //Set the value
  grapple_variable_set_data(serverdata->variables,name,data,len);

  //Sync this value to the server, and then onto the servers
  grapple_variable_server_sync(serverdata,name);

  internal_server_release(serverdata);

  return;
}

int grapple_server_datavar_get(grapple_server server,const char *name,
			       void *data,size_t *len)
{
  internal_server_data *serverdata;
  grapple_error err;

  //Find the server
  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      //No server
      grapple_error_set(GRAPPLE_ERROR_NOT_INITIALISED);
      return GRAPPLE_FAILED;
    }

  //Get the value
  err=grapple_variable_get_data(serverdata->variables,name,data,len);

  grapple_server_error_set(serverdata,err);

  //Done with this
  internal_server_release(serverdata);

  if (err!=GRAPPLE_NO_ERROR)
    return GRAPPLE_FAILED;

  return GRAPPLE_OK;
}

grapple_certificate *grapple_server_user_certificate_get(grapple_server server,
							 grapple_user target)
{
#ifndef SOCK_SSL
  return NULL;
#else

  internal_server_data *serverdata;
  socket_certificate *cert=NULL;
  grapple_certificate *returnval;
  grapple_connection *user;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  //Lock the user list
  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Locate the user
  user=connection_from_serverid(serverdata->userlist,target);

  if (user)
    {
      cert=socket_certificate_get(user->sock);
    }

  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  //Done with this
  internal_server_release(serverdata);

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

char *grapple_server_user_name_get(grapple_server server,
				   grapple_user target)
{
  internal_server_data *serverdata;
  char *returnval=NULL;
  grapple_connection *user;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return NULL;
    }

  //Lock the user list
  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Locate the user
  user=connection_from_serverid(serverdata->userlist,target);

  if (user)
    {
      if (user->name)
	{
	  returnval=(char *)malloc(strlen(user->name)+1);
	  strcpy(returnval,user->name);
	}
    }

  grapple_thread_mutex_unlock(serverdata->connection_mutex);

  //Done with this
  internal_server_release(serverdata);

  return returnval;
}

int grapple_server_dispatchers_set(grapple_server server,int num)
{
  internal_server_data *serverdata;
  int loopa;
  int all_done=0;

  serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_SHARED);

  if (!serverdata)
    {
      return GRAPPLE_FAILED;
    }

  if (!serverdata->thread)
    {
      //We havent started yet, just set the number
      serverdata->dispatcher_count=num;
      internal_server_release(serverdata);
      return GRAPPLE_OK;
    }
  
  grapple_thread_mutex_lock(serverdata->dispatcher_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (num > serverdata->dispatcher_count)
    {
      serverdata->dispatcherlist=(grapple_callback_dispatcher **)realloc(serverdata->dispatcherlist,sizeof(grapple_callback_dispatcher *)*(num+1));
  
      for (loopa=serverdata->dispatcher_count;loopa <num;loopa++)
	{
	  serverdata->dispatcherlist[loopa]=grapple_callback_dispatcher_create(serverdata,0);
	}
      serverdata->dispatcherlist[loopa]=NULL;
      serverdata->dispatcher_count=num;
    }
  else if (num < serverdata->dispatcher_count)
    {
      for (loopa=num;loopa < serverdata->dispatcher_count;loopa++)
	serverdata->dispatcherlist[loopa]->finished=1;
      
      all_done=0;
      while (all_done==0)
	{
	  all_done=1;
	  
	  loopa=num;
	  while (all_done && serverdata->dispatcherlist[loopa])
	    {
	      if (serverdata->dispatcherlist[loopa]->finished==1)
		all_done=0;
	      loopa++;
	    }

	  if (!all_done)
	    //They havent all finished hasnt finished
	    microsleep(1000);
	}

      loopa=num;
      while (serverdata->dispatcherlist[loopa])
	{
	  serverdata->dispatcherlist[loopa]->finished=3;
	  serverdata->dispatcherlist[loopa]=NULL;
	  loopa++;
	}
      serverdata->dispatcher_count=num;

    }
  
  grapple_thread_mutex_unlock(serverdata->dispatcher_mutex);
  
  //Done with this
  internal_server_release(serverdata);

  return GRAPPLE_OK;
}
