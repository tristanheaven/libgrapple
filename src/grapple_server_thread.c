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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "grapple_server_thread.h"
#include "grapple_server_internal.h"
#include "grapple_connection.h"
#include "grapple_comms_api.h"
#include "grapple_internal.h"
#include "grapple_queue.h"
#include "grapple_group.h"
#include "grapple_group_internal.h"
#include "grapple_defines.h"
#include "grapple_failover.h"
#include "grapple_confirm.h"
#include "tools.h"
#include "grapple_callback_internal.h"
#include "grapple_callback_dispatcher.h"
#include "grapple_variable.h"

int user_set_delete(internal_server_data *server,
		    grapple_connection *target)
{
  grapple_connection *scan;
  int groupid;

  if (target->deleted)
    return 1;

  target->deleted=1;

  //delete from all groups now
  while (target->groups)
    {
      groupid=0;
      grapple_thread_mutex_lock(target->group_mutex,GRAPPLE_LOCKTYPE_SHARED);
      if (target->groups)
	groupid=target->groups->id;
      grapple_thread_mutex_unlock(target->group_mutex);
      
      if (groupid)
	{
	  grapple_thread_mutex_lock(server->connection_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);
	  scan=server->userlist;
	  while (scan)
	    {
	      //If it isnt the originator
	      if (scan!=target)
		//Send the message
		s2c_group_remove(server,scan,groupid,
				 target->serverid);
	      
	      scan=scan->next;
	      
	      if (scan==server->userlist)
		scan=0;
	    }

	  grapple_thread_mutex_unlock(server->connection_mutex);

	  s2SUQ_group_remove(server,target,groupid,
			     target->serverid);

	  server_group_remove(server,groupid,
			      target->serverid);
	}
    }

  s2c_inform_disconnect(server,target,target);

  return 1;
}
	  


//This function is called when all handshake parameters have been met, which
//means that the game has correctly identified itself
static void postprocess_handshake_good(internal_server_data *server,  
				       grapple_connection *user)
{
  grapple_connection *scan;
  grapple_failover_host *failoverscan;
  internal_grapple_group *groupscan;
  grapple_group_container *container;
  grapple_queue *message_target;

  //Dont do this twice
  if (user->handshook)
    return;

  //If all handshake stages have been completed
  if (!(user->handshakeflags & HANDSHAKE_FLAG_GRAPPLE_VERSION &&
	user->handshakeflags & HANDSHAKE_FLAG_PRODUCT_NAME &&
	user->handshakeflags & HANDSHAKE_FLAG_PASSWORD &&
	user->handshakeflags & HANDSHAKE_FLAG_PRODUCT_VERSION &&
	user->handshakeflags & HANDSHAKE_FLAG_PROTECTIONKEY))
    {
      //We havent got all we need
      return;
    }

  //Now check we have matched the name policy
  if (!(user->handshakeflags & HANDSHAKE_FLAG_USERNAME))
    {
      switch(server->namepolicy)
	{
	case GRAPPLE_NAMEPOLICY_NONE:
	  //No name required, we're passed
	  user->handshakeflags|=HANDSHAKE_FLAG_USERNAME;
	  break;
	case GRAPPLE_NAMEPOLICY_REQUIRED:
	case GRAPPLE_NAMEPOLICY_UNIQUE:
	  if (!user->name)
	    //Not matched the policy yet
	    return;
	  break;
	}
    }

  switch(server->protectionkeypolicy)
    {
    case GRAPPLE_PROTECTIONKEYPOLICY_NONE:
      //No game key required, we're passed
      break;
    case GRAPPLE_PROTECTIONKEYPOLICY_UNIQUE:
      if (!user->protectionkey)
	//Not matched the policy
	return;
      break;
    }

  if (user->reconnecting)
    {
      grapple_thread_mutex_lock(server->connection_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);

      //Loop through all users
      scan=server->userlist;
      while (scan)
	{
	  if (scan->serverid==user->reconnectserverid)
	    {
	      user->serverid=user->reconnectserverid;
	      server->userlist=connection_unlink(server->userlist,scan);
	      
	      break;
	    }
	  
	  scan=scan->next;
	  
	  if (scan==server->userlist)
	    scan=0;
	}
      
      grapple_thread_mutex_unlock(server->connection_mutex);

      if (scan)
	{
	  grapple_thread_mutex_lock(scan->message_out_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  grapple_thread_mutex_lock(user->message_out_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

	  while (scan->message_out_queue)
	    {
	      message_target=scan->message_out_queue;
	      scan->message_out_queue=queue_unlink(scan->message_out_queue,
						   message_target);
	      user->message_out_queue=queue_link(user->message_out_queue,
						 message_target);
	    }

	  grapple_thread_mutex_unlock(user->message_out_mutex);
	  grapple_thread_mutex_unlock(scan->message_out_mutex);

	  connection_struct_dispose(scan);
	}
    }
  if (!user->reconnecting)
    {
      //If the user is connecting for the first time
      if (server->closed)
	{
	  //If the server is closed, tell the user they cant connect
	  s2c_server_closed(server,user);
	  user_set_delete(server,user);
	  return;
	}
      
      if (server->maxusers>0 && server->usercount==server->maxusers)
	{
	  //If the server is full, tell them user they cant connect
	  s2c_server_full(server,user);
	  user_set_delete(server,user);
	  return;
	}
    }

  if (server->connectioncallbackhandler)
    {
      if (server->connectioncallbackhandler(user->serverid,
					    server->connectioncallbackhandlercontext)==0)
	{
	  s2c_handshake_failed(server,user);
	  user_set_delete(server,user);
	  return;
	}
    }


  //Record that the user has done their handshake, so it doesnt happen again
  user->handshook=1;

  //This is the user, set the users sequential to the requested
  //value now we dont have to worry about sequence
  if (server->sequential)
    {
      user->sequential=1;
      socket_mode_set(user->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);
    }
  else
    { 
      user->sequential=0;
      socket_mode_unset(user->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);
    }
  //Increase the count of connected users
  server->usercount++;

  if (!user->reconnecting)
    {
      //If this is a new connection

      //Send the message to the server that the user has connected
      s2SUQ_user_connected(server,user);

      //Send the session name to the client      
      s2c_session_name(server,user,server->session);

      grapple_thread_mutex_lock(server->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Loop through all users
      scan=server->userlist;
      while (scan)
	{
	  //If this user is connected
	  if (scan->handshook) 
	    {
	      
	      //Tell all users that this user has connected
	      s2c_user_connected(server,scan,user);
	      
	      if (scan!=user)
		{
		  //Now tell this user about all other users that are connected
		  s2c_user_connected(server,user,scan);
		}
	    }
	  
	  scan=scan->next;
	  
	  if (scan==server->userlist)
	    scan=0;
	}
      
      grapple_thread_mutex_unlock(server->connection_mutex);
    }

  //Send the new user a new group ID to use
  s2c_send_nextgroupid(server,user,server->user_serverid++);
  
  if (!user->reconnecting)
    {
      //Send all synchronised variables to the user
      grapple_variable_server_syncall(server,user);
    }

  if (!user->reconnecting)
    {
      //Now if we are running failover
      if (server->failover)
	{
	  //First tell this new one to try and be a failover host
	  s2c_failover_on(server,user);
	  
	  //Now we tell the user a list of everyone who CAN be a failover host
	  grapple_thread_mutex_lock(server->failover_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);
	  
	  failoverscan=server->failoverhosts;
	  
	  while (failoverscan)
	    {
	      s2c_failover_can(server,user,failoverscan->id,
			       failoverscan->address);
	      
	      failoverscan=failoverscan->next;
	      if (failoverscan==server->failoverhosts)
		failoverscan=NULL;
	    }
	  
	  grapple_thread_mutex_unlock(server->failover_mutex);
	}

      //Now tell the new user about all the groups
      grapple_thread_mutex_lock(server->group_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      
      groupscan=server->groups;
      while (groupscan)
	{
	  //Add this groupto the users list of groups now
	  s2c_group_create(server,user,groupscan->id,groupscan->name,
			   groupscan->password);

	  //Now add all the members to this group that are in the servers group
	  container=groupscan->contents;
	  while (container)
	    {
	      s2c_group_add(server,user,groupscan->id,container->id);

	      container=container->next;
	      if (container==groupscan->contents)
		container=NULL;
	    }
	  
	  groupscan=groupscan->next;
	  if (groupscan==server->groups)
	    groupscan=NULL;
	}
      grapple_thread_mutex_unlock(server->group_mutex);
    }

  //The user is done!
  user->reconnecting=0;
}

//The client has sent us their grapple version as part of the handshake
static void process_message_grapple_version(internal_server_data *server,  
					    grapple_connection *user,
					    grapple_messagetype_internal messagetype,
					    void *data,size_t datalen)
{
  //Compare the version passed by the client to the hardcoded version we have
  if (strlen(GRAPPLE_VERSION)!=datalen ||
      memcmp(data,GRAPPLE_VERSION,datalen))
    {
      //Now we have a grapple version mismatch
      s2c_handshake_failed(server,user);
      user_set_delete(server,user);
    }
  else
    {
      //Set the flag to note its done
      user->handshakeflags|=HANDSHAKE_FLAG_GRAPPLE_VERSION;
    }

  postprocess_handshake_good(server,user);

  return;
}

//The client has sent us the name of the game they are playing
static void process_message_product_name(internal_server_data *server,  
					 grapple_connection *user,
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  //Check the server and client are playing the same game
  if (strlen(server->productname)!=datalen ||
      memcmp(data,server->productname,datalen))
    {
      //Now we have a product name mismatch
      s2c_handshake_failed(server,user);
      user_set_delete(server,user);
    }
  else
    {
      //The game matches, add this flag
      user->handshakeflags|=HANDSHAKE_FLAG_PRODUCT_NAME;
    }

  //Finish the connection
  postprocess_handshake_good(server,user);

  //Its ok, so just return
  return;
}

//The client has sent us the version of the game they are playing
static void process_message_product_version(internal_server_data *server,  
					    grapple_connection *user,
					    grapple_messagetype_internal messagetype,
					    void *data,size_t datalen)
{
  //Check the version on the server and client are the same
  if (strlen(server->productversion)!=datalen ||
      memcmp(data,server->productversion,datalen))
    {
      //Now we have a product version mismatch
      s2c_handshake_failed(server,user);
      user_set_delete(server,user);
    }
  else
    {
      //Add the handshake flag
      user->handshakeflags|=HANDSHAKE_FLAG_PRODUCT_VERSION;
    }

  //Complete connection
  postprocess_handshake_good(server,user);
}

//The client has sent us a password to connect
static void process_message_password(internal_server_data *server,  
				     grapple_connection *user,
				     grapple_messagetype_internal messagetype,
				     void *data,size_t datalen)
{
  if (server->passwordhandler)
    {
      char *handlerpassword;

      handlerpassword=(char *)malloc(datalen+1);
      memcpy(handlerpassword,data,datalen);
      handlerpassword[datalen]=0;

      if (!(*server->passwordhandler)(user->name,handlerpassword,
				      server->passwordhandlercontext))
	{
	  s2c_password_failed(server,user);
	  user_set_delete(server,user);
	}
      else
	{
	  //It has passed the custom handler, note the flag
	  user->handshakeflags|=HANDSHAKE_FLAG_PASSWORD;
	}
      
      free(handlerpassword);
    }
  else
    {
      //If the password even exists
      if (server->password && *server->password)
	{
	  //Test if it is the same
	  if (strlen(server->password)!=datalen ||
	      memcmp(data,server->password,datalen))
	    {
	      //Now we have a grapple password mismatch
	      s2c_password_failed(server,user);
	      user_set_delete(server,user);
	    }
	  else
	    {
	      //It is the same, note the flag
	      user->handshakeflags|=HANDSHAKE_FLAG_PASSWORD;
	    }
	}
      else
	{
	  //There is no password, note the flag
	  user->handshakeflags|=HANDSHAKE_FLAG_PASSWORD;
	}
    }

  postprocess_handshake_good(server,user);
}

//The client has sent us some connection data to connect. Set this data into
//the server but do nothing else
static void process_message_protectionkey(internal_server_data *server,  
					  grapple_connection *user,
					  grapple_messagetype_internal messagetype,
					  void *data,size_t datalen)
{
  grapple_connection *scan;
  int unique;

  if (user->protectionkey)
    free(user->protectionkey);

  if (datalen)
    {
      user->protectionkey=(char *)malloc(datalen+1);
      memcpy(user->protectionkey,data,datalen);
      user->protectionkey[datalen]=0;
    }
  else
    user->protectionkey=NULL;

  //If our protectionkey policy is set, we need a unique key
  if (server->protectionkeypolicy==GRAPPLE_PROTECTIONKEYPOLICY_UNIQUE)
    {
      if (!user->protectionkey || !*user->protectionkey)
	unique=0;
      else
	unique=1;
      scan=server->userlist;
      while (scan && unique)
	{
	  if (scan!=user && scan->protectionkey && 
#ifdef WIN32
	      !_stricmp(scan->protectionkey,user->protectionkey)
#else
	      !strcasecmp(scan->protectionkey,user->protectionkey)
#endif
	      )
	    {
	      //It is the same, this is non-unique
	      unique=0;
	    }
	  scan=scan->next;
	  if (scan==server->userlist)
	    scan=NULL;
	}

      if (!unique)
	{
	  //This is a bad name, and now must be disconnected
	  s2c_unique_protectionkey_failed(server,user);
	  user_set_delete(server,user);
	}
    }

  //Here it is either unique, or we dont care
  user->handshakeflags|=HANDSHAKE_FLAG_PROTECTIONKEY;

  return;
}

//The client has sent us their name
static void process_message_user_name(internal_server_data *server,  
				      grapple_connection *user,
				      grapple_messagetype_internal messagetype,
				      void *data,size_t datalen)
{
  grapple_connection *scan;
  int unique;

  //If this user already has a name, clear it
  if (user->name)
    free(user->name);

  //set the name
  user->name=(char *)malloc(datalen+1);
  strncpy(user->name,(char *)data,datalen);
  user->name[datalen]=0;

  //If our name policy is simply to HAVE a name, then we're good
  if (server->namepolicy==GRAPPLE_NAMEPOLICY_REQUIRED)
    user->handshakeflags|=HANDSHAKE_FLAG_USERNAME;
  
  //If the policy is to have a unique name, check it
  else if (server->namepolicy==GRAPPLE_NAMEPOLICY_UNIQUE)
    {
      unique=1;
      scan=server->userlist;
      while (scan && unique)
	{
	  if (scan!=user && 
#ifdef WIN32
	      !_stricmp(scan->name,user->name)
#else
	      !strcasecmp(scan->name,user->name)
#endif
	      )
	    {
	      //It is the same, this is non-unique
	      unique=0;
	    }
	  scan=scan->next;
	  if (scan==server->userlist)
	    scan=NULL;
	}

      if (unique)
	{
	  user->handshakeflags|=HANDSHAKE_FLAG_USERNAME;
	}
      else
	{
	  //This is a bad name, and now must be disconnected
	  s2c_unique_name_failed(server,user);
	  user_set_delete(server,user);
	}
    }

  if (!user->handshook)
    return;

  //Now scan the userlist, show all users the new name

  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  s2SUQ_user_setname(server,user);

  scan=server->userlist;
  while (scan)
    {
      //send the name to this user
      s2c_user_setname(server,scan,user);
      scan=scan->next;
      if (scan==server->userlist)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);
}

//Received a message from the user to the server
static void process_message_user_message(internal_server_data *server,  
					 grapple_connection *user,
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  intchar val;
  int flags,messageid;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;

  //Decode the message to the parts we need/want
  //4 bytes : flags
  //4 bytes : message ID
  //        : message

  //Check we have enough data
  if (datalen<9) //Min of one byte of data
    return;

  memcpy(val.c,data,4);
  flags=val.i;

  memcpy(val.c,(char *)data+4,4);
  messageid=ntohl(val.i);

  //Add a  message to the clients inbound message queue
  s2SUQ_send(server,user->serverid,messagetype,(char *)data+8,datalen-8);

  //Now, if required, send an acknowledgement back to the user
  if (flags & GRAPPLE_CONFIRM)
    s2c_confirm_received(server,user,messageid);

  return;
}

//The user has told us they are disconnecting
static void process_message_user_disconnected(internal_server_data *server,  
					      grapple_connection *user,
					      grapple_messagetype_internal messagetype,
					      void *data,size_t datalen)
{
  //Simply set the delete flag, dont delete them when we are in the middle of
  //processing them, that would break things
  user_set_delete(server,user);

  return;
}

//The client has requested a message to be sent directly to another
//user. This comes via the server as we arent point to point.
static void process_message_relay_to(internal_server_data *server,  
				     grapple_connection *user,
				     grapple_messagetype_internal messagetype,
				     void *data,size_t datalen)
{
  intchar val;
  int target,flags,id;
  grapple_connection *scan;
  int *group_data,loopa,count=0;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;

  //Data layout is:
  // 4 bytes ID of who to send the message to
  // 4 bytes flags
  // 4 bytes message id
  // DATA

  //Check we have enough data
  if (datalen<13) //Min of one byte of data
    return;

  memcpy(val.c,data,4);
  target=ntohl(val.i);
      
  memcpy(val.c,(char *)data+4,4);
  flags=val.i;

  memcpy(val.c,(char *)data+8,4);
  id=ntohl(val.i);

  grapple_thread_mutex_lock(server->group_mutex,GRAPPLE_LOCKTYPE_SHARED);
  if (group_locate(server->groups,target))
    {
      //The message is being sent to a group.

      //Unroll the group and obtain all the group members in an
      //int array
      group_data=server_group_unroll(server,target);

      grapple_thread_mutex_unlock(server->group_mutex);

      //Loop through each user in the int array
      loopa=0;
      while (group_data[loopa])
	{
	  grapple_thread_mutex_lock(server->connection_mutex,
				    GRAPPLE_LOCKTYPE_SHARED);
      
	  //Find that user
	  scan=server->userlist;
	  while (scan)
	    {
	      if (scan->serverid==group_data[loopa])
		{
		  //If this is the user, send them the message
		  s2c_relaymessage(server,scan,user,flags,id,
				   (char *)data+12,datalen-12);

		  //Count the send
		  count++;
		  scan=NULL;
		}
	      else
		scan=scan->next;
	      
	      if (scan==server->userlist)
		scan=0;
	    }
	  
	  grapple_thread_mutex_unlock(server->connection_mutex);
	  loopa++;
	}
      //Finshed with the list of users.
      free(group_data);
    }
  else
    {
      grapple_thread_mutex_unlock(server->group_mutex);
      grapple_thread_mutex_lock(server->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
     
      //It is a message to a single user, find them and send 
      scan=server->userlist;
      while (scan)
	{
	  if (scan->serverid==target)
	    {
	      //Send the message
	      s2c_relaymessage(server,scan,user,flags,id,(char *)data+12,datalen-12);

	      //Count the send
	      count++;
	      scan=NULL;
	    }
	  else
	    scan=scan->next;
	  
	  if (scan==server->userlist)
	    scan=0;
	}
      
      grapple_thread_mutex_unlock(server->connection_mutex);
    }

  //If nobody was sent to in the end, but they want confirmation, then
  //confirm, as the message WAS sent to all users it was supposed to go to
  if (count == 0 && flags & GRAPPLE_CONFIRM)
    s2c_confirm_received(server,user,id);

  return;
}

//The client has requested we relay a message to everyone
static void process_message_relay_all(internal_server_data *server,  
				      grapple_connection *user,
				      grapple_messagetype_internal messagetype,
				      void *data,size_t datalen)
{
  grapple_connection *scan;
  int flags,id,count=0;
  intchar val;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;

  //Data layout is:
  // 4 bytes flags
  // 4 bytes message id
  // DATA

  //Check we have enough data
  if (datalen<9) //Min of one byte of data
    return;

  memcpy(val.c,data,4);
  flags=val.i;

  memcpy(val.c,(char *)data+4,4);
  id=ntohl(val.i);

  grapple_thread_mutex_lock(server->connection_mutex,GRAPPLE_LOCKTYPE_SHARED);

  //Loop through all users
  scan=server->userlist;
  while (scan)
    {
      //Send this user the message
      s2c_relaymessage(server,scan,user,flags,id,(char *)data+8,datalen-8);

      //Count the send
      count++;
      scan=scan->next;

      if (scan==server->userlist)
	scan=0;
    }
  
  grapple_thread_mutex_unlock(server->connection_mutex);
  
  //If nobody was sent to in the end, but they want confirmation, then
  //confirm, as the message WAS sent to all users it was supposed to go to
  if (count == 0 && flags & GRAPPLE_CONFIRM)
    s2c_confirm_received(server,user,id);

  return;
}

//The user wants a message relayed to all OTHER users, so not to themself
static void process_message_relay_all_but_self(internal_server_data *server,  
					       grapple_connection *user,
					       grapple_messagetype_internal messagetype,
					       void *data,size_t datalen)
{
  grapple_connection *scan;
  int flags,id,count=0;
  intchar val;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;

  //Data layout is:
  // 4 bytes flags
  // 4 bytes message id
  // DATA

  //Check we have enough data
  if (datalen<9) //Min of one byte of data
    return;

  memcpy(val.c,data,4);
  flags=val.i;

  memcpy(val.c,(char *)data+4,4);
  id=ntohl(val.i);

  grapple_thread_mutex_lock(server->connection_mutex,GRAPPLE_LOCKTYPE_SHARED);

  //Loop all users
  scan=server->userlist;
  while (scan)
    {
      //Dont send to self
      if (scan->serverid!=user->serverid)
	{
	  //Send the message
	  s2c_relaymessage(server,scan,user,flags,id,(char *)data+8,datalen-8);

	  //Count the send
	  count++;
	}

      scan=scan->next;

      if (scan==server->userlist)
	scan=0;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);
    
  //If nobody was sent to in the end, but they want confirmation, then
  //confirm, as the message WAS sent to all users it was supposed to go to
  if (count == 0 && flags & GRAPPLE_CONFIRM)
    s2c_confirm_received(server,user,id);

  return;
}

//A ping request has been received. This is just a request to reply
//to see how long it takes. We use a ping over the grapple system instead of
//an ICMP ping cos an ICMP ping would only show network latancies not
//issues with the processing of the ping itself
static void process_message_ping(internal_server_data *server,  
				 grapple_connection *user,
				 grapple_messagetype_internal messagetype,
				 void *data,size_t datalen)
{
  intchar val;

  //When we receive a ping, ALL we do is send the same number back - we dont
  //even need to ntohl it as its going back as it came
  if (datalen!=4)
    return;

  memcpy(val.c,data,4);

  //Send the reply
  s2c_pingreply(server,user,val.i);
  
  return;
}

//We have received a reply to a ping we sent out
static void process_message_ping_reply(internal_server_data *server,  
				       grapple_connection *user,
				       grapple_messagetype_internal messagetype,
				       void *data,size_t datalen)
{
  intchar val;
  grapple_connection *scan;

  //When we receive a pingreply, the ping number is already correct
  if (datalen!=4)
    return;

  memcpy(val.c,data,4);

  if (val.i!=user->pingnumber)
    {
      //This ping is returning after the next one is sent,ignore it
      return;
    }

  //Now we see how long the ping took
  gettimeofday(&user->pingend,NULL);
  
  user->pingtime=((user->pingend.tv_sec-user->pingstart.tv_sec)*1000000);
  user->pingtime+=(user->pingend.tv_usec-user->pingstart.tv_usec);

  //Now send a message to the servers message queue
  s2SUQ_send_double(server,user->serverid,messagetype,user->pingtime);

  //Now we send the ping data back to all clients
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Loop through all users
  scan=server->userlist;
  while (scan)
    {
      //Send them the ping data
      s2c_ping_data(server,scan,user);

      scan=scan->next;

      if (scan==server->userlist)
	scan=0;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);
    
  return;
}

//The client has requested a new message group ID to be sent to them
static void process_message_request_next_groupid(internal_server_data *server,  
						 grapple_connection *user,
						 grapple_messagetype_internal messagetype,
						 void *data,size_t datalen)
{
  //This function just sends a new next group ID to the client
  s2c_send_nextgroupid(server,user,server->user_serverid++);
}


//The client has requested that we create a new message group
static void process_message_group_create(internal_server_data *server,  
					 grapple_connection *user,
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  int groupid;
  size_t namelen,passlen,offset;
  intchar val;
  char *outdata;
  char *name,*password,*cpassword;
  grapple_connection *scan;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;


  //The reply to this command is to create the group and then send a message
  //to all clients (except the user that initiated) to create the group.

  //The format of the data is:
  // 4 bytes : Group ID
  // 4 bytes : Group name length
  //         : Group name
  // 4 bytes : Password length
  //         : Password (encrypted once)

  //Check we have enough data
  if (datalen<8)
    return;

  memcpy(val.c,data,4);
  groupid=ntohl(val.i);

  //Now we need to check we are allowed to create the group
  if (server->maxgroups==GRAPPLE_GROUPS_DISABLED || 
      (server->maxgroups >0 && server->groupcount >= server->maxgroups))
    {
      //We arent allowed to create this group, send the client that sent the
      //message a group destroy message
      s2c_group_delete(server,user,groupid);

      return;
    }

  memcpy(val.c,(char *)data+4,4);
  namelen=ntohl(val.i);
  
  //Check we have enough data
  if (namelen==0 || datalen-8<namelen)
    return;

  name=(char *)malloc(namelen+1);
  memcpy(name,(char *)data+8,namelen);
  name[namelen]=0;
  
  offset=namelen+8;

  //Check we have enough data
  if (datalen-offset<4)
    return;
  
  memcpy(val.c,(char *)data+offset,4);
  passlen=ntohl(val.i);
  offset+=4;
  
  if (passlen>0)
    {
      //Check we have enough data
      if (datalen-offset<passlen)
	{
	  free(name);
	  return;
	}
      password=(char *)malloc(passlen+1);
      memcpy(password,(char *)data+offset,passlen);
      password[passlen]=0;
      offset+=passlen;
    }
  else
    password=NULL;
  
  //The password is encrypted once, we require a twice encrypted password to
  //ensure security
  cpassword=group_crypt(groupid,password);

  if (cpassword)
    {
      passlen=strlen(cpassword);
      offset+=passlen;
    }

  outdata=(char *)malloc(offset);

  
  //Switch the group ID from network to host order, and place it back 
  //into the data to send to the servers message queue
  val.i=groupid;
  memcpy(outdata,val.c,4);
  
  //Add the name to the message queue
  val.i=(GRAPPLE_INT_TYPE)namelen;
  memcpy(outdata+4,val.c,4);
  
  memcpy(outdata+8,name,namelen);
  
  val.i=(GRAPPLE_INT_TYPE)passlen;
  memcpy(outdata+8+namelen,val.c,4);
  
  if (passlen)
    memcpy(outdata+12+namelen,cpassword,passlen);
  
  //create a new group in the server
  create_server_group(server,groupid,name,cpassword);

  //Now go to each client and tell them there is a new group
  grapple_thread_mutex_lock(server->connection_mutex,GRAPPLE_LOCKTYPE_SHARED);
  
  scan=server->userlist;
  while (scan)
    {
      //Tell all users except the originator
      if (scan!=user)
	s2c_group_create(server,scan,groupid,name,cpassword);
      
      scan=scan->next;
      
      if (scan==server->userlist)
	scan=0;
    }
  
  grapple_thread_mutex_unlock(server->connection_mutex);
  
  //Now send the message to the servers queue
  s2SUQ_send(server,user->serverid,GRAPPLE_MESSAGE_GROUP_CREATE,
	     outdata,passlen+namelen+12);
  
  free(outdata);
  free(name);
  if (password)
    free(password);
  if (cpassword)
    free(cpassword);
  
  //We're done
}

//The client has requested adding a member to a group
static void process_message_group_add(internal_server_data *server,  
				      grapple_connection *user,
				      grapple_messagetype_internal messagetype,
				      void *data,size_t datalen)
{
  int groupid;
  int contentid;
  char *password=NULL,*cpassword;
  size_t passwordlength;
  intchar val;
  grapple_connection *scan;
  char *outdata;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;

  //The data is:

  // 4 bytes : Group ID
  // 4 bytes : User ID to add
  // 4 bytes : Password length
  //         : Password

  //Check we have enough data
  if (datalen<12)
    return;

  memcpy(val.c,data,4);
  groupid=ntohl(val.i);
  memcpy(val.c,(char *)data+4,4);
  contentid=ntohl(val.i);
  memcpy(val.c,(char *)data+8,4);
  passwordlength=ntohl(val.i);

  if (passwordlength)
    {
  //Check we have enough data
      if (datalen-12<passwordlength)
	return;
      password=(char *)malloc(passwordlength+1);
      memcpy(password,(char *)data+12,passwordlength);
      password[passwordlength]=0;
    }

  //Encrypt the password for a second time
  cpassword=group_crypt(groupid,password);

  //create a new item in the servers group
  if (!server_group_add(server,groupid,contentid,cpassword))
    {
      if (password)
	free(password);

      if (cpassword)
	free(cpassword);

      return;
    }

  //Now go to each client and tell them there is a new member in this group
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=server->userlist;
  while (scan)
    {
      //Send a message, except to the originator who already knows

      if (scan!=user)
	s2c_group_add(server,scan,groupid,contentid);

      scan=scan->next;

      if (scan==server->userlist)
	scan=0;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);

  if (cpassword)
    passwordlength=strlen(cpassword);
  else
    passwordlength=0;

  //Construct the data to send it to the servers queue
  outdata=(char *)malloc(passwordlength+12);

  val.i=groupid;
  memcpy(outdata,val.c,4);

  val.i=contentid;
  memcpy(outdata+4,val.c,4);

  val.i=(GRAPPLE_INT_TYPE)passwordlength;
  memcpy(outdata+8,val.c,4);

  if (passwordlength)
    memcpy(outdata+12,cpassword,passwordlength);

  //Send it to the servers queue
  s2SUQ_send(server,user->serverid,GRAPPLE_MESSAGE_GROUP_ADD,outdata,
	     passwordlength+12);

  free(outdata);

  if (cpassword)
    free(cpassword);

  //We're done
}

//The client has requested we remove a member from a group
static void process_message_group_remove(internal_server_data *server,  
					 grapple_connection *user,
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  int groupid;
  int contentid;
  intchar val;
  grapple_connection *scan;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;

  //4 bytes : Group ID
  //4 bytes : User to remove

  //Check we have enough data
  if (datalen<8)
    return;

  memcpy(val.c,data,4);
  groupid=ntohl(val.i);
  memcpy(val.c,(char *)data+4,4);
  contentid=ntohl(val.i);

  //create a new item in the servers group
  if (!server_group_remove(server,groupid,contentid))
    return;

  //Now go to each client and tell to remove the member from this group
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=server->userlist;
  while (scan)
    {
      //If it isnt the originator
      if (scan!=user)
	//Send the message
	s2c_group_remove(server,scan,groupid,contentid);

      scan=scan->next;

      if (scan==server->userlist)
	scan=0;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);
    
  //Now construct the data for the servers message queue
      
  s2SUQ_group_remove(server,user,groupid,contentid);
}

//The client has requested a complete group delete
static void process_message_group_delete(internal_server_data *server,  
					 grapple_connection *user,
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  int groupid;
  intchar val;
  grapple_connection *scan;
  char *outdata;
  internal_grapple_group *group;
  size_t length;

  //If the user has not completed handshake, dont let them send.
  if (!user->handshook)
    return;

  //4 bytes group ID

  //Check we have enough data
  if (datalen<4)
    return;

  memcpy(val.c,data,4);
  groupid=ntohl(val.i);

  grapple_thread_mutex_lock(server->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  group=group_locate(server->groups,groupid);

  length=strlen(group->name);
  outdata=(char *)malloc(length+4);
  
  val.i=groupid;
  memcpy(outdata,val.c,4);

  memcpy(outdata+4,group->name,length);

  grapple_thread_mutex_unlock(server->group_mutex);

  //Delete it on the server
  if (!delete_server_group(server,groupid))
    {
      free(outdata);
      return;
    }

  //Now go to each client and tell them 
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=server->userlist;
  while (scan)
    {
      //If it isnt the originating client
      if (scan!=user)
	//Send them the message
	s2c_group_delete(server,scan,groupid);

      scan=scan->next;

      if (scan==server->userlist)
	scan=0;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);

  //Send the message to the servers message queue
  s2SUQ_send(server,user->serverid,GRAPPLE_MESSAGE_GROUP_DELETE,
	     outdata,length+4);

  free(outdata);
}

//The client has said they arent able to provide a failover host
static void process_message_failover_cant(internal_server_data *server,  
					  grapple_connection *user,
					  grapple_messagetype_internal messagetype,
					  void *data,size_t datalen)
{
  //This is just a curtesy function, if the client cant failover to it,
  //then we dont actually do anything, we only do something if it CAN
  //failover
}

//The client has said thet think they CAN be a failover host, try and connect
//to their test port
static void process_message_failover_tryme(internal_server_data *server,  
					   grapple_connection *user,
					   grapple_messagetype_internal messagetype,
					   void *data,size_t datalen)
{
  char *address;
  //The client says they can failover - so try and connect to them, see
  //if we can reach them. If we can, they can be a host.
  
  address=user->sock->host;

  if (!address)
    {
      //We dont know where the remote server is! tell it it cant be
      //a failover
      s2c_failover_cant(server,user,0);

      return;
    }

  //Connect to them either with TCP or UDP - as appropriate
  switch (server->protocol)
    {
    case GRAPPLE_PROTOCOL_UNKNOWN:
      break;
    case GRAPPLE_PROTOCOL_TCP:
      user->failoversock=socket_create_inet_tcp_wait(address,server->port,0);
      break;
    case GRAPPLE_PROTOCOL_UDP:
      user->failoversock=socket_create_inet_udp2way_wait(address,
							 server->port,0);
      break;
    }
   
  if (!user->failoversock)
    {
      //The socket couldnt be created
      s2c_failover_cant(server,user,0);
      return;
    }

  //This one could end up as a remote failover socket, add it to the
  //servers list of sockets to process
  server->socklist=socket_link(server->socklist,user->failoversock);

  //Now we just check it whenever we loop, to see if its alive or dead. If
  //it ends up dead, the client cant be a failover, if it ends up connected,
  //it can be a failover
}


//The client is reconnecting. This means we are a new host having just run
//failover, and the client is trying to find where to live next
static void process_message_reconnection(internal_server_data *server,  
					 grapple_connection *user,
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  intchar val;
  size_t length;

  //4 bytes : server ID
  //4 bytes : length of the name
  //        : Name

  if (datalen<8)
    return;

  memcpy(val.c,data,4);

  //Set the new users server ID
  user->reconnectserverid=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);

  length=ntohl(val.i);

  //Check we have enough data
  if (datalen-8<length)
    return;

  //Create the users name
  user->name=(char *)malloc(length+1);
  memcpy(user->name,(char *)data+8,length);
  user->name[length]=0;

  //Mark the user as reconnecting for when they finish their handshake
  user->reconnecting=1;
}

//The client is notifying us of whether they want to know about which users
//Are connected or not
static void process_message_notify_state(internal_server_data *server,  
					 grapple_connection *user,
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  intchar val;

  //4 bytes : notify state

  //Check we have enough data
  if (datalen<4)
    return;

  memcpy(val.c,data,4);
  user->notify=ntohl(val.i);

  //Thats it
}

//The server has received a confirmation that a message has been received
//by the one of the users it was sent to.
static void process_message_confirm_received(internal_server_data *server,  
					     grapple_connection *user,
					     grapple_messagetype_internal messagetype,
					     void *data,size_t datalen)
{
  intchar val;
  int userid,messageid;
  grapple_connection *origin=NULL,*scan;
  int offset;

  //4 bytes : ID of origin user
  //4 bytes : Message ID

  offset=0;
  //Check we have enough data
  if (datalen<8)
    return;

  memcpy(val.c,data,4);
  userid=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  messageid=ntohl(val.i);

  if (!userid)
    {
      //It came from the server, log the return here
      server_unregister_confirm(server,messageid,user->serverid);

      return;
    }

  //It came from a user
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Locate the user who sent the message      
  scan=server->userlist;
  while (scan)
    {
      if (scan->serverid==userid)
	{
	  //This is the user
	  origin=scan;

	  //Break the loop
	  scan=NULL;
	}
      else
	scan=scan->next;
      
      if (scan==server->userlist)
	scan=NULL;
    }
  
  //If we found a sender
  if (origin)
    //Register it as confirmed
    unregister_confirm(server,origin,messageid,user->serverid);

  grapple_thread_mutex_unlock(server->connection_mutex);

  return;
}

//A variable has been sent from the client
static void process_message_variable(internal_server_data *server,  
				     grapple_connection *user,
				     grapple_messagetype_internal messagetype,
				     void *data,size_t datalen)
{
  intchar val;
  int type;
  size_t offset,len;
  char *name;
  int intval;
  double doubleval;
  void *vardata;
  size_t vardatalen;

  //The data here is variable depending on the type of syncronised variable
  //we have
  //4 bytes : Variable type
  //4 bytes : Length of name
  //        : name
  //        : data. 4 bytes if int, otherwise string to the end

  //First one is the message id, we need to make sure we arent waiting on
  //a sync send for it

  //Check we have enough data
  if (datalen<8)
    return;

  memcpy(val.c,data,4);
  type=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  len=ntohl(val.i);

  offset=8;
  //Check we have enough data
  if (datalen-offset<len)
    return;
  name=(char *)malloc(len+1);
  memcpy(name,(char *)data+8,len);
  name[len]=0;

  offset+=len;

  switch (type)
    {
    case GRAPPLE_VARIABLE_TYPE_DATA:
      vardatalen=datalen-offset;
      vardata=(void *)malloc(vardatalen);
      memcpy(vardata,(char *)data+offset,vardatalen);
      grapple_variable_set_data(server->variables,name,vardata,vardatalen);
      free(vardata);
      break;
    case GRAPPLE_VARIABLE_TYPE_DOUBLE:
      vardatalen=datalen-offset;
      vardata=(void *)malloc(vardatalen+1);
      memcpy(vardata,(char *)data+offset,vardatalen);
      *((char *)vardata+vardatalen)=0;
      doubleval=atof((char *)vardata);
      grapple_variable_set_double(server->variables,name,doubleval);
      free(vardata);
      break;
    case GRAPPLE_VARIABLE_TYPE_INT:
      if (datalen-offset<4)
	{
	  free(name);
	  return;
	}
      memcpy(val.c,(char *)data+offset,4);
      intval=ntohl(val.i);
      grapple_variable_set_int(server->variables,name,intval);
      break;
    default:
      break;
    }

  grapple_variable_server_sync(server,name);

  free(name);

  return;
}

//The server has received a message from a user. 
//Call the appropriate handler function
static void process_message(internal_server_data *server,  
			    grapple_connection *user,
			    grapple_messagetype_internal messagetype,
			    void *data,size_t datalen)
{
  switch (messagetype)
    {
    case GRAPPLE_MESSAGE_GRAPPLE_VERSION:
      process_message_grapple_version(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PRODUCT_NAME:
      process_message_product_name(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PRODUCT_VERSION:
      process_message_product_version(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PASSWORD:
      process_message_password(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PROTECTIONKEY:
      process_message_protectionkey(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_USER_NAME:
      process_message_user_name(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_USER_MESSAGE:
      process_message_user_message(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_USER_DISCONNECTED:
      process_message_user_disconnected(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_RELAY_TO:
      process_message_relay_to(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_RELAY_ALL:
      process_message_relay_all(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_RELAY_ALL_BUT_SELF:
      process_message_relay_all_but_self(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PING:
      process_message_ping(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PING_REPLY:
      process_message_ping_reply(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_FAILOVER_CANT:
      process_message_failover_cant(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_FAILOVER_TRYME:
      process_message_failover_tryme(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_REQUEST_NEXT_GROUPID:
      process_message_request_next_groupid(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_CREATE:
      process_message_group_create(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_ADD:
      process_message_group_add(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_REMOVE:
      process_message_group_remove(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_DELETE:
      process_message_group_delete(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_RECONNECTION:
      process_message_reconnection(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_NOTIFY_STATE:
      process_message_notify_state(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_CONFIRM_RECEIVED:
      process_message_confirm_received(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_VARIABLE:
      process_message_variable(server,user,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_USER_CONNECTED:
    case GRAPPLE_MESSAGE_USER_YOU_CONNECTED:
    case GRAPPLE_MESSAGE_SERVER_DISCONNECTED:
    case GRAPPLE_MESSAGE_HANDSHAKE_FAILED:
    case GRAPPLE_MESSAGE_SERVER_CLOSED:
    case GRAPPLE_MESSAGE_SERVER_FULL:
    case GRAPPLE_MESSAGE_PASSWORD_FAILED:
    case GRAPPLE_MESSAGE_NAME_NOT_UNIQUE:
    case GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE:
    case GRAPPLE_MESSAGE_SESSION_NAME:
    case GRAPPLE_MESSAGE_PING_DATA:
    case GRAPPLE_MESSAGE_FAILOVER_ON:
    case GRAPPLE_MESSAGE_FAILOVER_OFF:
    case GRAPPLE_MESSAGE_FAILOVER_CAN:
    case GRAPPLE_MESSAGE_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_YOU_ARE_HOST:
    case GRAPPLE_MESSAGE_CONFIRM_TIMEOUT:
    case GRAPPLE_MESSAGE_GAME_DESCRIPTION:
      //Will never be received by the server
      break;
    }
}

//Process a users incoming data which has been received via UDP
static int process_user_udp(internal_server_data *server,  
			    grapple_connection *user)
{
  socket_udp_data *pulldata;
  int messagelength;
  intchar indata;
  grapple_messagetype_internal messagetype;
  int count=0;
  char *ptr;

  //If the user is dead, ignore it
  if (user->deleted)
    return 0;

  //if this is a reconnection dummy socket
  if (!(user->sock))
    return 0;

  //Pull the next UDP packet from the socket
  pulldata=socket_udp_indata_pull(user->sock);

  //Continue while there is data to read
  while (pulldata)
    {
      //Data is of the form:
      //4 bytes: Message type
      //4 bytes: Message length
      //         DATA
      
      ptr=pulldata->data;

      memcpy(indata.c,ptr,4);
      messagetype=(grapple_messagetype_internal)ntohl(indata.i);
      ptr+=4;
      
      memcpy(indata.c,ptr,4);
      messagelength=ntohl(indata.i);
      ptr+=4;
      

      //Process the message
      process_message(server,user,messagetype,ptr,messagelength);

      //Free the data struct we were passed  
      socket_udp_data_free(pulldata);
      count++;

      //Try and get another
      pulldata=socket_udp_indata_pull(user->sock);
    }

  return count;
}


//Process a users incoming data which has been received via TCP
static int process_user_tcp(internal_server_data *server,  
			    grapple_connection *user)
{
  const void *data,*ptr;
  void *pulldata,*pullptr;
  size_t length,messagelength;
  intchar indata;
  grapple_messagetype_internal messagetype;
  int count=0;

  //If the user is dead, dont read
  if (user->deleted)
    return 0;

  //if this is a reconnection dummy socket
  if (!(user->sock))
    return 0;

  //We will return as soon as there is no more data, so we can loop forever
  while (1)
    {
      //Initially only VIEW the data, dont take it
      length=socket_indata_length(user->sock);

      //There must be at least 8 bytes for the data, that is the minimum
      //amount of data a packet can contain
      if (length<8)
	return count;
      
      //Get the data to view
      data=socket_indata_view(user->sock);
      ptr=data;

      //Data is of the form:
      //4 bytes: Message type
      //4 bytes: Message length
      //         DATA
      
      memcpy(indata.c,ptr,4);
      ptr=(const char *)ptr+4;
      messagetype=(grapple_messagetype_internal)ntohl(indata.i);
      
      memcpy(indata.c,ptr,4);
      ptr=(const char *)ptr+4;
      messagelength=ntohl(indata.i);
      
      //Check there is enough in the buffer for the whole message
      if (length < messagelength+8)
	return count;

      //We have enough for the whole message, grab it
      pulldata=socket_indata_pull(user->sock,messagelength+8);

      //Move to the start of the data
      pullptr=(char *)pulldata+8;
      
      //Process the message
      process_message(server,user,
		      messagetype,pullptr,messagelength);
      
      //Free the data we took
      free(pulldata);

      count++;
    }

  return count;
}

//Here we are processing the users failover socket, looking for a reply
//from that socket that would indicate that that user is OK to use as a
//failover
static int process_failoversock(internal_server_data *server,
				grapple_connection *user)
{
  grapple_connection *scan;

  if (socket_dead(user->failoversock))
    {
      //This is a failed try, delete the socket and tell the user
      server->socklist=socket_unlink(server->socklist,user->failoversock);
      
      socket_destroy(user->failoversock);
      user->failoversock=NULL;
      s2c_failover_cant(server,user,0);

      return 1;
    }

  if (socket_connected(user->failoversock))
    {
      //This is a successful try, delete the socket and tell the user
      server->socklist=socket_unlink(server->socklist,user->failoversock);
      socket_destroy(user->failoversock);
      user->failoversock=NULL;

      grapple_thread_mutex_lock(server->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);

      //Tell all users
      scan=server->userlist;
      while (scan)
	{
	  //Send the message
	  s2c_failover_can(server,scan,user->serverid,user->sock->host);
	  
	  scan=scan->next;

	  if (scan==server->userlist)
	    scan=0;
	}
      
      grapple_thread_mutex_unlock(server->connection_mutex);
      
      //Now add this one to the list of possible failovers
      server->failoverhosts=failover_link_by_id(server->failoverhosts,
						user->serverid,
						user->sock->host);

      
      return 1;
    }

  return 0;
}

//This is the function that processes each user connected. It looks at
//their inbound and outbound sockets, and disconnects dead users.
static int process_userlist(internal_server_data *server)
{
  grapple_connection *scan,*subscan,*target;
  int count=0; /*Count will be incrimented each time something is done. At
		 the end of the cycle, if count is still 0, the thread will
		 sleep for a short time, to avoid massive overhead when not
		 being used*/

  //Lock the userlist so the parent cant change anything
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=server->userlist;

  while (scan)
    {
      //Process the users sockets based on what protocol they are using
      switch (server->protocol)
	{
	case GRAPPLE_PROTOCOL_UNKNOWN:
	  break;
	case GRAPPLE_PROTOCOL_TCP:
	  count+=process_user_tcp(server,scan);
	  break;
	case GRAPPLE_PROTOCOL_UDP:
	  count+=process_user_udp(server,scan);
	  break;
	}

      //Process the failover sockets
      if (scan->failoversock)
	{
	  count+=process_failoversock(server,scan);
	}

      scan=scan->next;

      if (scan==server->userlist)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);

  //Unlock and lock to let another thread in for a moment, if we are blocking
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  scan=server->userlist;

  //Now loop through all the users
  while (scan)
    {
      target=scan;
      scan=scan->next;


      if (target->sock) //First test normal socketed users
	{
	  //If their socket is dead, tag for deletion
	  if (!target->deleted && socket_dead(target->sock))
	    user_set_delete(server,target);

	  //If they are deleted, and have nothing left to send to the server
	  if (target->deleted && !target->message_out_queue)
	    {
	      count++;
	      
	      //If they are dead 
	      if (socket_dead(target->sock) || 
		  !socket_outdata_length(target->sock))
		{
		  //Now unlink them
		  server->userlist=connection_unlink(server->userlist,target);
		  server->socklist=socket_unlink(server->socklist,target->sock);
		  
		  if (target->handshook)
		    {
		      target->handshook=0;
		      
		      //Decriment the usercount
		      server->usercount--;
		      
		      //Now inform other users
		      subscan=server->userlist;
		      while (subscan)
			{
			  //Let each user know this user has disconnected
			  s2c_inform_disconnect(server,subscan,target);
			  subscan=subscan->next;
			  if (subscan==server->userlist)
			    subscan=0;
			}
		      //Let the server player know the user has disconnected
		      s2SUQ_user_disconnect(server,target);
		      
		      //If we are running failover, remove this one from the 
		      //failover circuit
		      if (server->failover)
			server->failoverhosts=
			  failover_unlink_by_id(server->failoverhosts,
						target->serverid);
		      
		    }

		  //Dispose of this user
		  connection_struct_dispose(target);
		}
	    }
	}
      else
	{
	  //If this is a reconnection link after expiry
	  
	  if (server->reconnect_expire < time(NULL))
	    connection_struct_dispose(target);
	}

      if (!server->userlist || scan==server->userlist)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);

  return count;
}

//This function sends the outbound data queues to the socket
static int process_message_out_queue_tcp(grapple_connection *user)
{
  grapple_queue *data;
  int count=0;

  if (!user->sock)
    return 0;

  //Write ALL the data at once
  while (user->message_out_queue)
    {
      grapple_thread_mutex_lock(user->message_out_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

      data=user->message_out_queue;

      if (!data)
	{
	  grapple_thread_mutex_unlock(user->message_out_mutex);
	  return count;
	}

      user->message_out_queue=queue_unlink(user->message_out_queue,data);

      grapple_thread_mutex_unlock(user->message_out_mutex);

      //We now have the message data to send
      socket_write(user->sock,
		   (char *)data->data,data->length);

      free(data->data);
      free(data);

      //Count the send
      count++;
    }

  return count;
}

//Process the users outbound UDP data
static int process_message_out_queue_udp(grapple_connection *user)
{
  grapple_queue *data;
  int count=0;

  if (!user->sock)
    return 0;

  //Continue while there is data to send
  while (user->message_out_queue)
    {
      grapple_thread_mutex_lock(user->message_out_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      data=user->message_out_queue;

      if (!data)
	{
	  grapple_thread_mutex_unlock(user->message_out_mutex);
	  return count;
	}

      user->message_out_queue=queue_unlink(user->message_out_queue,data);
      grapple_thread_mutex_unlock(user->message_out_mutex);

      //We now have the message data to send. It may be reliable or unreliable
      if (data->reliablemode)
	socket_write_reliable(user->sock,
			      (char *)data->data,data->length);
      else
	socket_write(user->sock,
		     (char *)data->data,data->length);
      
      free(data->data);
      free(data);

      count++;
    }

  return count;
}

//This function processess all users via the TCP protocol
static int process_message_out_queues_tcp(internal_server_data *server)
{
  grapple_connection *scan;
  int count=0;

  //Loop for all users
  scan=server->userlist;

  while (scan)
    {
      //Process this user
      count+=process_message_out_queue_tcp(scan);

      scan=scan->next;
      if (scan==server->userlist)
	scan=0;
    }

  return count;
}

//This function processess all users via the UDP protocol
static int process_message_out_queues_udp(internal_server_data *server)
{
  grapple_connection *scan;
  int count=0;

  scan=server->userlist;

  //All users
  while (scan)
    {
      //Process this user
      count+=process_message_out_queue_udp(scan);

      scan=scan->next;
      if (scan==server->userlist)
	scan=0;
    }

  return count;
}

//If autoping is running, they we ping each user every few seconds
static void run_autoping(internal_server_data *server)
{
  grapple_connection *scan;
  struct timeval time_now;

  //Only do this if we are autopinging
  if (!server->autoping)
    return;

  //Find when the last time the user may have pinged, that it has been long
  //enough that it needs to ping again
  gettimeofday(&time_now,NULL);
  time_now.tv_usec-=(long)(server->autoping*1000000);
  
  while (time_now.tv_usec<0)
    {
      time_now.tv_usec+=1000000;
      time_now.tv_sec--;
    }

  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  scan=server->userlist;
  //Loop through every user
  while (scan)
    {
      if (scan->pingstart.tv_sec < scan->pingend.tv_sec ||
	  (scan->pingstart.tv_sec == scan->pingend.tv_sec &&
	   scan->pingstart.tv_usec <= scan->pingend.tv_usec))
	{
	  //We arent currently pinging this one
	  if (scan->pingend.tv_sec < time_now.tv_sec ||
	      (scan->pingend.tv_sec == time_now.tv_sec &&
	       scan->pingend.tv_usec < time_now.tv_usec))
	    {
	      //We have passed the autoping repeat time, so now ping
	      s2c_ping(server,scan,++scan->pingnumber);
	      gettimeofday(&scan->pingstart,NULL);
	    }
	  
	}
      scan=scan->next;

      if (scan==server->userlist)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);

  return;
}

//Run the server thread for one TCP/IP cycle
static void grapple_server_thread_tcp(internal_server_data *server)
{
  int count,sockcount,serverid;
  socketbuf *newsock;

  //Run continual pinging
  run_autoping(server);

  //Process the outbound messages
  count=process_message_out_queues_tcp(server);

  //This function tells the low level socket layer to actually do read and
  //write operations on the sockets
  sockcount=socket_process_sockets(server->socklist,server->timeout);

  //If anything happened on the sockets
  if (sockcount)
    {
      //Check if there are new connections
      newsock=socket_new(server->sock);
      while (newsock)
	{
	  //There was, add this to the user list
	  serverid=connection_server_add(server,newsock);

	  //Link the socket into the process list
	  server->socklist=socket_link(server->socklist,newsock);

	  count++;

	  newsock=socket_new(server->sock);
	}

      //There was some data in the sockets, go through the userlist and process
      //the data
      count+=process_userlist(server);
    }

  count+=sockcount;

  //If after all the processing, we have nothing to do, we set the next loop
  //to have a longer timeout on the socket processing, meaning that
  //if something DOES come in and interrupt, then we can return immediately,
  //otherwise we will queue for up to 1/10th of a second doing nothing
  if (!count)
    server->timeout=100000;
  else
    server->timeout=0;
}

//The UDP version of the server thread. This is pretty much the same as the
//TCP one, it just sends to different handler functions
static void grapple_server_thread_udp(internal_server_data *server)
{
  int count,sockcount,serverid;
  socketbuf *newsock;

  //Run continual pinging
  run_autoping(server);

  //Process the outbound messages
  count=process_message_out_queues_udp(server);

  //This function tells the low level socket layer to actually do read and
  //write operations on the sockets
  sockcount=socket_process_sockets(server->socklist,server->timeout);

  //If anything happened on the sockets
  if (sockcount)
    {
      //Check if there are new connections
      newsock=socket_new(server->sock);
      while (newsock)
	{
	  //There was, add this to the user list
	  serverid=connection_server_add(server,newsock);

	  //Link the socket into the process list
	  server->socklist=socket_link(server->socklist,newsock);

	  count++;

	  newsock=socket_new(server->sock);
	}

      //There was some data in the sockets, go through the userlist and process
      //the data
      count+=process_userlist(server);
    }

  count+=sockcount;

  //If after all the processing, we have nothing to do, we set the next loop
  //to have a longer timeout on the socket processing, meaning that
  //if something DOES come in and interrupt, then we can return immediately,
  //otherwise we will queue for up to 1/20th of a second doing nothing
  if (!count)
    server->timeout=100000;
  else
    server->timeout=0;
}

//This is the function that is called when the server thread starts. It loops
//while the thread is alive, and cleans up some when it dies
#ifdef HAVE_PTHREAD_H
static void *grapple_server_thread_main(void *voiddata)
#else
  static DWORD WINAPI grapple_server_thread_main(LPVOID voiddata)
#endif
{
  internal_server_data *data;
  int finished=0;
  grapple_connection *user;
  grapple_callback_dispatcher **tmpdispatcher;
  grapple_confirm *confirm;
  grapple_failover_host *failover;
  internal_grapple_group *group;
  int loopa;
  int all_done;

#ifdef HAVE_SIGACTION
  struct sigaction sa;
  memset(&sa,0,sizeof(struct sigaction));
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, 0);
#endif

  //The server we have started
  data=(internal_server_data *)voiddata;

  //Immediately, before anything else, create the dispatcher process

  //The dispatcher is a new thread that has messages passed to it for event 
  //handling. This allows events to be called asynchronously, and not slow
  //down this handling thread which is pretty important to keep running
  //smoothly. For more information see grapple_dispatcher.c

  //More than one dispatcher can be run at once. If no callbacks are
  //set then by default then no dispatcher will be started
  grapple_thread_mutex_lock(data->dispatcher_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  if (!data->dispatcherlist)
    {
      data->dispatcherlist=(grapple_callback_dispatcher **)calloc(1,sizeof(grapple_callback_dispatcher *)*(data->dispatcher_count+1));
      
      for (loopa=0;loopa <data->dispatcher_count;loopa++)
	{
	  data->dispatcherlist[loopa]=grapple_callback_dispatcher_create(data,0);
	}
    }

  grapple_thread_mutex_unlock(data->dispatcher_mutex);

  //Link the main incoming socket into the list of sockets to process.
  data->socklist=socket_link(data->socklist,data->sock);

  //Link the wakeup socket into the list of sockets to process.
  data->socklist=socket_link(data->socklist,data->wakesock);

  //Continue while we are not finished
  while (!finished)
    {
      //Process the thread data (users etc) via either the TCP or UDP handler
      switch (data->protocol)
	{
	case GRAPPLE_PROTOCOL_UNKNOWN:
	  break;
	case GRAPPLE_PROTOCOL_TCP:
	  grapple_server_thread_tcp(data);
	  break;
	case GRAPPLE_PROTOCOL_UDP:
	  grapple_server_thread_udp(data);
	  break;
	}

      //Process confirmation messages that are slow to come back
      process_slow_confirms(data);

      if (data->threaddestroy)
	{
	  //We have been told to end the thread
	  finished=1;

	  //Destroy the incoming socket
	  data->socklist=socket_unlink(data->socklist,data->sock);
	  socket_destroy(data->sock);
	  data->sock=NULL;
	
	  grapple_thread_mutex_lock(data->internal_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  if (data->wakesock)
	    {
	      data->socklist=socket_unlink(data->socklist,data->wakesock);
	      socket_destroy(data->wakesock);
	      data->wakesock=NULL;
	    }
	  grapple_thread_mutex_unlock(data->internal_mutex);

	  //Destroy the userlist, processing all outstanding data as possible
	  while (data->userlist)
	    {
	      grapple_thread_mutex_lock(data->connection_mutex,
					GRAPPLE_LOCKTYPE_EXCLUSIVE);
	      user=data->userlist;
	      if (!user)
		//The user could have been deleted by another thread since we
		//ehecked just a moment ago. Make SURE
		break;
	      data->userlist=connection_unlink(data->userlist,data->userlist);
	      grapple_thread_mutex_unlock(data->connection_mutex);

	      //Send the disconnect message for this user
	      s2c_disconnect(data,user);

	      //Now try and ensure all data is sent to the user
	      while (user->message_out_queue && !socket_dead(user->sock))
		{
		  //Process outgoing messages
		  switch (user->protocol)
		    {
		    case GRAPPLE_PROTOCOL_UNKNOWN:
		      break;
		    case GRAPPLE_PROTOCOL_TCP:
		      process_message_out_queue_tcp(user);
		      break;
		    case GRAPPLE_PROTOCOL_UDP:
		      process_message_out_queue_udp(user);
		      break;
		    }

		  //Try and push the data down the socket. We do this here
		  //as well as a little below so that we can try and give the
		  //kernel as much time as possible to send the data
		  if (!socket_dead(user->sock) &&
		      socket_outdata_length(user->sock)>0)
		      
		    {
		      socket_process(user->sock,0);
		    }
		}

	      //While the socket is still alive, try and shove the remaining 
	      //data down the socket
	      while (!socket_dead(user->sock) &&
		     socket_outdata_length(user->sock)>0)
		     
		{
		  socket_process(user->sock,0);
		}

	      //Get rid of the socket now
	      data->socklist=socket_unlink(data->socklist,user->sock);
	      connection_struct_dispose(user);
	    }


	  //Remove all callbacks
	  grapple_thread_mutex_lock(data->callback_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  while (data->callbackanchor)
	    {
	      data->callbackanchor=grapple_callback_remove(data->callbackanchor,
							   data->callbackanchor->type);
	    }
	  grapple_thread_mutex_unlock(data->callback_mutex);

	  //Kill the callback dispatcher thread	  
	  grapple_thread_mutex_lock(data->dispatcher_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  tmpdispatcher=(grapple_callback_dispatcher **)calloc(1,sizeof(grapple_callback_dispatcher *)*(data->dispatcher_count+1));
	  for (loopa=0;loopa < data->dispatcher_count;loopa++)
	    {
	      tmpdispatcher[loopa]=data->dispatcherlist[loopa];
	      data->dispatcherlist[loopa]=NULL;
	      if (tmpdispatcher[loopa]->finished==0)
		tmpdispatcher[loopa]->finished=1;
	    }
	  free(data->dispatcherlist);
	  data->dispatcherlist=0;
	  grapple_thread_mutex_unlock(data->dispatcher_mutex);

	  //Unlink all of the confirm requests waiting, they dont matter now
	  grapple_thread_mutex_lock(data->confirm_mutex,
				     GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  while (data->confirm)
	    {
	      confirm=data->confirm;
	      data->confirm=grapple_confirm_unlink(data->confirm,
						   data->confirm);
	      grapple_confirm_dispose(confirm);
	    }
	  grapple_thread_mutex_unlock(data->confirm_mutex);

	  //Remove the failover hosts
	  grapple_thread_mutex_lock(data->failover_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  while (data->failoverhosts)
	    {
	      failover=data->failoverhosts;
	      data->failoverhosts=failover_unlink(data->failoverhosts,
						  data->failoverhosts);
	      failover_dispose(failover);
	    }
	  grapple_thread_mutex_unlock(data->failover_mutex);

	  //Remove all the message groups
	  grapple_thread_mutex_lock(data->group_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  while (data->groups)
	    {
	      group=data->groups;
	      data->groups=group_unlink(data->groups,
					data->groups);
	      group_dispose(group);
	    }
	  grapple_thread_mutex_unlock(data->group_mutex);

	  //Now we check for the dispatcher thread being done with
	  all_done=0;
	  while (all_done==0)
	    {
	      all_done=1;

	      loopa=0;
	      while (all_done && tmpdispatcher[loopa])
		{
		  if (tmpdispatcher[loopa]->finished==1)
		    all_done=0;
		  loopa++;
		}

	      if (!all_done)
		//They havent all finished hasnt finished
		microsleep(1000);
	    }
	  
	  //now the dispatcher is finished, let the dispatcher know it can end
	  loopa=0;
	  while (tmpdispatcher[loopa])
	    {
	      tmpdispatcher[loopa]->finished=3;
	      loopa++;
	    }
	  free(tmpdispatcher);
	}
    }

  //We're done, the thread ends when this function ends
  grapple_thread_destroy(data->thread);
  data->thread=0;
  data->threaddestroy=0;

#ifdef HAVE_PTHREAD_H
  return NULL;
#else
  return 0;
#endif
}

//Function called by the grapple_server_start function to actually start the
//thread
int grapple_server_thread_start(internal_server_data *data)
{
  data->threaddestroy=0;

  data->thread=grapple_thread_create(grapple_server_thread_main,(void *)data);

  if (data->thread==NULL)
    return -1;

  return 1;
}
