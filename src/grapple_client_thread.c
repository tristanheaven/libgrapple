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
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "grapple_client_thread.h"
#include "grapple_client_internal.h"
#include "grapple_queue.h"
#include "grapple_connection.h"
#include "grapple_comms_api.h"
#include "grapple_group.h"
#include "grapple_defines.h"
#include "grapple_failover.h"
#include "prototypes.h"
#include "socket.h"
#include "tools.h"
#include "grapple_callback_internal.h"
#include "grapple_callback_dispatcher.h"
#include "grapple_variable.h"

//The server has sent us a message that a user has connected
static void process_message_user_connected(internal_client_data *client,  
					   grapple_messagetype_internal messagetype,
					   void *data,size_t datalen)
{
  intchar val;
  grapple_connection *user;
  int newserverid;

  //Put the first 4 bytes into the intchar, ready to convert to int
  memcpy(val.c,data,4);

  newserverid=ntohl(val.i);

  //Add a new user to the queue
  connection_client_add(client,newserverid,
			messagetype==GRAPPLE_MESSAGE_USER_CONNECTED?0:1);

  if (messagetype==GRAPPLE_MESSAGE_USER_YOU_CONNECTED)
    {
      //This is the clients own connection
      client->serverid=newserverid;

      //The client is now connected, set the socket mode to sequential
      //if required
      if (client->sequential)
	socket_mode_set(client->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);
      else 
	socket_mode_unset(client->sock,SOCKET_MODE_UDP2W_SEQUENTIAL);
    }

  if (datalen>4)
    {
      //We have a name too
      grapple_thread_mutex_lock(client->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      user=connection_from_serverid(client->userlist,newserverid);
      if (user)
	{
	  if (user->name)
	    free(user->name);
	  user->name=(char *)malloc(datalen-3);
	  memcpy((void *)user->name,(void *)((char *)data+4),datalen-4);
	  user->name[datalen-4]=0;
	}
      grapple_thread_mutex_unlock(client->connection_mutex);

      val.i=newserverid;
      memcpy(data,val.c,4);//Overwrite data, its being deleted on return anyway
      c2CUQ_send(client,messagetype,data,datalen);
    }
  else
    {
      //We just have the ID, send that
      //Add a connected message to the clients inbound message queue
      c2CUQ_send_int(client,messagetype,newserverid);
    }

  return;
}

//The server has told us of a user disconnecting
static void process_message_user_disconnected(internal_client_data *client,  
					      grapple_messagetype_internal messagetype,
					      void *data,size_t datalen)
{
  intchar val;
  int serverid;

  //Find the user ID
  memcpy(val.c,data,4);
  serverid=ntohl(val.i);

  //remove user from the queue
  connection_client_remove_by_id(client,serverid);

  //If we are running failover, remove this one from the failover circuit
  if (client->failover)
    client->failoverhosts=failover_unlink_by_id(client->failoverhosts,
						serverid);

  //Add a connected message to the clients inbound message queue
  c2CUQ_send_int(client,messagetype,serverid);

  return;
}

//The server has rejected our connection attempt
static void process_message_handshake_failed(internal_client_data *client,  
					     grapple_messagetype_internal messagetype,
					     void *data,size_t datalen)
{
  //Add a failed handshake message to the clients inbound message queue
  c2CUQ_send_int(client,messagetype,0);

  return;
}

//The connection was OK, but the server is closed
static void process_message_server_closed(internal_client_data *client,  
					  grapple_messagetype_internal messagetype,
					  void *data,size_t datalen)
{
  //Add afailed handshake message to the clients inbound message queue
  c2CUQ_send_int(client,messagetype,0);

  return;
}

//The connection was ok, but the server is full
static void process_message_server_full(internal_client_data *client,  
					grapple_messagetype_internal messagetype,
					void *data,size_t datalen)
{
  //Add afailed handshake message to the clients inbound message queue
  c2CUQ_send_int(client,messagetype,0);

  return;
}

//An invalid key was sent to the server
static void process_message_protectionkey_not_unique(internal_client_data *client,  
					       grapple_messagetype_internal messagetype,
					       void *data,size_t datalen)
{
  //Add a failed handshake message to the clients inbound message queue
  c2CUQ_send_int(client,messagetype,0);
  
  return;
}

//An invalid name was sent to the server
static void process_message_name_not_unique(internal_client_data *client,  
					    grapple_messagetype_internal messagetype,
					    void *data,size_t datalen)
{
  //Add a failed handshake message to the clients inbound message queue
  c2CUQ_send_int(client,messagetype,0);

  return;
}

//The wrong password was sent to the server
static void process_message_password_failed(internal_client_data *client,  
					    grapple_messagetype_internal messagetype,
					    void *data,size_t datalen)
{
  //Add a failed handshake message to the clients inbound message queue
  c2CUQ_send_int(client,messagetype,0);

  return;
}

//We have been informed of a users name
static void process_message_user_name(internal_client_data *client,  
				      grapple_messagetype_internal messagetype,
				      void *data,size_t datalen)
{
  intchar val;
  int serverid;
  void *outdata;

  //Find the users ID, and then swap it to host byte order
  memcpy(val.c,data,4);
  serverid=ntohl(val.i);
  val.i=serverid;

  //Copy the name into the outdata
  outdata=malloc(datalen+1);
  memcpy(outdata,data,datalen);
  memcpy(outdata,val.c,4);
  ((char *)outdata)[datalen]=0;
  
  //Change the users name
  connection_client_rename(client,serverid,(char *)outdata+4);

  //Add a renamed message to the clients inbound message queue
  c2CUQ_send(client,messagetype,outdata,datalen);

  free(outdata);

  return;
}

//The server has told us that the session name has either been set or RE-set
static void process_message_session_name(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  //If it has been set already, delete it
  if (client->session)
    free(client->session);

  //Save the session name
  client->session=(char *)malloc(datalen+1);
  memcpy(client->session,data,datalen);
  client->session[datalen]=0;
  
  //Add a message to the clients inbound message queue
  c2CUQ_send(client,messagetype,data,datalen);

  return;
}


//We have received a message from the server
static void process_message_user_message(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  //Split the message into its parts
  intchar val;
  int flags,messageid;

  //Data stream
  //4 bytes : flags
  //4 bytes : message ID
  //        : DATA

  memcpy(val.c,data,4);
  flags=val.i;
  
  memcpy(val.c,(char *)data+4,4);
  messageid=ntohl(val.i);

  //Add a  message to the clients inbound message queue
  c2CUQ_send(client,messagetype,(char *)data+8,datalen-8);

  //If we are supposed to confirm receipt, do so
  if (flags & GRAPPLE_CONFIRM)
    {
      c2s_confirm_received(client,0,messageid);
    }

  return;
}

static void process_message_relay_to(internal_client_data *client,  
				     grapple_messagetype_internal messagetype,
				     void *data,size_t datalen)
{
  intchar val;
  int from,flags,messageid;
  char *outdata;
  //Add a  message to the clients inbound message queue

  //Data is:
  // 4 bytes sender ID
  // 4 bytes flags
  // 4 bytes message ID

  memcpy(val.c,data,4);
  from=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  flags=val.i;

  memcpy(val.c,(char *)data+8,4);
  messageid=ntohl(val.i);

  outdata=(char *)malloc(datalen);
  val.i=from;
  memcpy(outdata,val.c,4);

  memcpy(outdata+4,(char *)data+12,datalen-12);

  //Send the message to the user
  c2CUQ_send(client,messagetype,outdata,datalen-8); //-8 cos we're -12 +4

  //If we are supposed to confirm it, do that
  if (flags & GRAPPLE_CONFIRM)
    c2s_confirm_received(client,from,messageid);

  free(outdata);

  return;
}

//We have received a ping, process that
static void process_message_ping(internal_client_data *client,  
				 grapple_messagetype_internal messagetype,
				 void *data,size_t datalen)
{
  intchar val;

  //When we receive a ping, ALL we do is send the same number back - we dont
  //even need to ntohl it as its going back as it came
  if (datalen!=4)
    return;

  memcpy(val.c,data,4);

  c2s_pingreply(client,val.i);
  
  return;
}

//We have received a reply to one of our pings
static void process_message_ping_reply(internal_client_data *client,  
				      grapple_messagetype_internal messagetype,
				      void *data,size_t datalen)
{
  intchar val;
  doublechar dval;
  char outdata[12];
  grapple_connection *user;

  //When we receive a ping reply, the ping number is already correct

  if (datalen!=4)
    return;

  memcpy(val.c,data,4);

  if (val.i!=client->pingnumber)
    {
      //This ping is returning after the next one is sent,ignore it
      return;
    }

  //Now we see how long the ping took
  gettimeofday(&client->pingend,NULL);
  
  client->pingtime=((client->pingend.tv_sec-client->pingstart.tv_sec)*1000000);
  client->pingtime+=(client->pingend.tv_usec-client->pingstart.tv_usec);

  //Now get the connection data and set it there too
  grapple_thread_mutex_lock(client->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=connection_from_serverid(client->userlist,client->serverid);
  if (user)
    {
      user->pingtime=client->pingtime;
    }
  grapple_thread_mutex_unlock(client->connection_mutex);

  //Now send a message to the client
  val.i=client->serverid;
  dval.d=client->pingtime;

  memcpy(outdata,val.c,4);
  memcpy(outdata+4,dval.c,8);

  c2CUQ_send(client,GRAPPLE_MESSAGE_PING_DATA,outdata,12);
  
  return;
}

//We have been passed ping data about another user from the server
static void process_message_ping_data(internal_client_data *client,  
				      grapple_messagetype_internal messagetype,
				      void *data,size_t datalen)
{
  intchar val;
  doublechar dval;
  double pingtime;
  int serverid;
  char floatstr[50];
  char outdata[12];
  grapple_connection *user;

  //We now extract the information on who the ping time is about and
  //what the time is

  memcpy(val.c,data,4);
  serverid=ntohl(val.i);

  //The data is sent as a string, so we dont have to worry about endianness
  //for floats
  memcpy(floatstr,(char *)data+4,datalen-4);
  floatstr[datalen-4]=0;

  pingtime=atof(floatstr);

  //Now get the connection data and set it there too
  grapple_thread_mutex_lock(client->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=connection_from_serverid(client->userlist,serverid);
  if (user)
    {
      user->pingtime=pingtime;
    }
  grapple_thread_mutex_unlock(client->connection_mutex);

  //Now send a message to the client
  val.i=serverid;
  dval.d=pingtime;

  memcpy(outdata,val.c,4);
  memcpy(outdata+4,dval.c,8);

  c2CUQ_send(client,GRAPPLE_MESSAGE_PING_DATA,outdata,12);
  
  return;
}

//We have been told by the server to turn off failover
static void process_message_failover_off(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  grapple_failover_host *target;

  //Set the flag
  client->failover=0;

  //Remove any failover lists we have

  grapple_thread_mutex_lock(client->failover_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  while (client->failoverhosts)
    {
      target=client->failoverhosts;

      client->failoverhosts=failover_unlink(client->failoverhosts,
					    client->failoverhosts);

      failover_dispose(target);
    }
  
  grapple_thread_mutex_unlock(client->failover_mutex);
  
  return;
}

static void process_message_failover_on(internal_client_data *client,  
					grapple_messagetype_internal messagetype,
					void *data,size_t datalen)
{
  client->failover=1;  /*It is on, but that doesnt mean that its on and
			 we can do it. We need to test this first. This
			 just lets us know that failover is an option
			 if the server dies*/

  //we have been requested to turn on failover. This means we need to see if
  //we CAN failover
  
  //The process goes like this: We open a port, the port that we would use
  //for failover, and we then tell the server to test us to see if they can
  //connect to us. If they can, we can be the server

  
  //So, start by opening a port on the socket we connect to (if we can)
  switch (client->protocol)
    {
    case GRAPPLE_PROTOCOL_UNKNOWN:
      break;
    case GRAPPLE_PROTOCOL_TCP:
      client->failoversock=
	socket_create_inet_tcp_listener_on_ip(NULL,client->port);
      break;
    case GRAPPLE_PROTOCOL_UDP:
      client->failoversock=
	socket_create_inet_udp2way_listener_on_ip(NULL,client->port);
      break;
    }

  if (!client->failoversock)
    {
      //We cant even bind to the socket, so forget it, we're never going to
      //be the host

      c2s_failover_cant(client);
      return;
    }


  //Add this socket to the process list, so we will do the UDP processing on it
  client->socklist=socket_link(client->socklist,client->failoversock);

  //Tell the server to see if it can connect
  c2s_failover_tryme(client);
  return;
}

//We have been told that a user can be the failover. This may or may not be us,
//that is pretty immaterial
static void process_message_failover_can(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  intchar val;
  int failoverid;
  int length;
  char *host;

  //Disect the data

  //4 bytes : failover ID (user ID of the failover server)
  //4 bytes : data length
  //          ADDRESS

  memcpy(val.c,data,4);
  failoverid=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  length=ntohl(val.i);

  host=(char *)malloc(length+1);
  memcpy(host,(char *)data+8,length);
  host[length]=0;

  //We now know who and where.

  //If the host is *us* then we first must disconnect the waiting socket
  if (failoverid==client->serverid)
    {
      if (client->failoversock)
	{
	  //Remove it from the socket list too
	  client->socklist=socket_unlink(client->socklist,
					 client->failoversock);
	  socket_destroy(client->failoversock);
	  client->failoversock=NULL;
	}
    }

  //Now add this one to the list (it can be adding ourown info to the list
  client->failoverhosts=failover_link_by_id(client->failoverhosts,
					    failoverid,host);

  free(host);

  return;
}

//We have been told that someone can no longer be a failover
static void process_message_failover_cant(internal_client_data *client,  
					  grapple_messagetype_internal messagetype,
					  void *data,size_t datalen)
{
  intchar val;
  int failoverid;

  //Find out the ID of who
  memcpy(val.c,data,4);
  failoverid=ntohl(val.i);

  if (failoverid==0)
    {
      //This is telling us we cant failover, close the remote socket
      if (client->failoversock)
	{
	  //Remove it from the socket list too
	  client->socklist=socket_unlink(client->socklist,
					 client->failoversock);
	  socket_destroy(client->failoversock);
	  client->failoversock=NULL;
	}
      return;
    }

  //We're taking a user off of the failover circuit
  client->failoverhosts=failover_unlink_by_id(client->failoverhosts,
					      failoverid);

  return;
}

//We have been given the next group ID from the server
static void process_message_next_groupid(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  int groupid;
  intchar val;

  memcpy(val.c,data,4);
  groupid=ntohl(val.i);

  //set this value into the connection data
  client->next_group=groupid;

  //Thats all we need to do here
}

//We have been told to create a group. Either the server or another player
//has created this group.
static void process_message_group_create(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  int groupid;
  char *name,*password;
  int length,offset;
  intchar val;
  char *outdata;

  //Data is:
  //4 bytes: Group ID
  //4 bytes: Name length
  //       : Group Name
  //4 bytes: Password length
  //       : Password

  outdata=(char *)malloc(datalen);
  memcpy(outdata,data,datalen);

  memcpy(val.c,data,4);
  groupid=ntohl(val.i);

  val.i=groupid;
  memcpy(outdata,val.c,4);

  memcpy(val.c,(char *)data+4,4);
  length=ntohl(val.i);
  
  val.i=length;
  memcpy(outdata+4,val.c,4);

  name=(char *)malloc(length+1);
  memcpy(name,(char *)data+8,length);
  name[length]=0;

  offset=length+8;

  memcpy(val.c,(char *)data+offset,4);
  length=ntohl(val.i);

  val.i=length;
  memcpy(outdata+offset,val.c,4);

  offset+=4;

  if (length>0)
    {
      password=(char *)malloc(length+1);
      memcpy(password,(char *)data+offset,length);
      password[length]=0;
    }
  else
    password=NULL;

  //create a new group in the client
  create_client_group(client,groupid,name,password);

  //Send the notification to the player
  c2CUQ_send(client,GRAPPLE_MESSAGE_GROUP_CREATE,outdata,datalen);

  free(name);
  if (password && *password)
    free(password);
  free(outdata);
}


//The server or another client has added a member to a group
static void process_message_group_add(internal_client_data *client,  
				      grapple_messagetype_internal messagetype,
				      void *data,size_t datalen)
{
  int groupid;
  int contentid;
  intchar val;
  char outdata[8];

  //4 bytes : Group ID
  //4 bytes : ID of who has just been added


  memcpy(val.c,data,4);
  groupid=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  contentid=ntohl(val.i);

  //add a new member in the clients group
  if (!client_group_forceadd(client,groupid,contentid))
    return;

  //Construct the data to send to the clients queue
  val.i=groupid;
  memcpy(outdata,val.c,4);

  val.i=contentid;
  memcpy(outdata+4,val.c,4);

  //Send the message
  c2CUQ_send(client,GRAPPLE_MESSAGE_GROUP_ADD,outdata,8);
}

//The server or another client has removed someone from a message group
static void process_message_group_remove(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  int groupid;
  int contentid;
  intchar val;
  char outdata[8];

  //4 bytes : Group ID
  //4 bytes : ID of who has just been removed

  memcpy(val.c,data,4);
  groupid=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  contentid=ntohl(val.i);

  //remove the member from the clients group
  if (!client_group_remove(client,groupid,contentid))
    return;

  //Construct data for the players message queue
  val.i=groupid;
  memcpy(outdata,val.c,4);

  val.i=contentid;
  memcpy(outdata+4,val.c,4);

  //Send the message
  c2CUQ_send(client,GRAPPLE_MESSAGE_GROUP_REMOVE,outdata,8);
}

//The server or another client has deleted a message group
static void process_message_group_delete(internal_client_data *client,  
					 grapple_messagetype_internal messagetype,
					 void *data,size_t datalen)
{
  int groupid;
  intchar val;
  char *outdata;
  internal_grapple_group *group;
  size_t length;
  
  //The ID is the only data
  memcpy(val.c,data,4);
  groupid=ntohl(val.i);

  grapple_thread_mutex_lock(client->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  group=group_locate(client->groups,groupid);

  length=strlen(group->name);
  outdata=(char *)malloc(length+4);
  
  val.i=groupid;
  memcpy(outdata,val.c,4);

  memcpy(outdata+4,group->name,length);

  grapple_thread_mutex_unlock(client->group_mutex);
  
  //Delete the group
  delete_client_group(client,groupid);

  //Let the player know
  c2CUQ_send(client,GRAPPLE_MESSAGE_GROUP_DELETE,outdata,length+4);

  free(outdata);
}

//This is confirmation that a message has been received by all of its
//intended recipients
static void process_message_confirm_received(internal_client_data *client,  
					     grapple_messagetype_internal messagetype,
					     void *data,size_t datalen)
{
  int messageid;
  intchar val;

  //Get the message ID
  memcpy(val.c,data,4);
  messageid=ntohl(val.i);

  if (messageid==client->sendwait)
    client->sendwait=0;

  //Let the player know
  c2CUQ_send_int(client,GRAPPLE_MESSAGE_CONFIRM_RECEIVED,messageid);
}

//This is confirmation that a message has timed out when trying to send it
//to one or more recipients
static void process_message_confirm_timeout(internal_client_data *client,  
					     grapple_messagetype_internal messagetype,
					     void *data,size_t datalen)
{
  intchar val;
  char *outdata;
  unsigned int loopa;

  outdata=(char *)malloc(datalen);

  //It is a load of ints, just ntohl them and send them on their way,
  //we dont care what they are at this stage. (They are actually
  //4 bytes : message ID
  //4 bytes : number of failures
  //        : DATA

  //First one is the message id, we need to make sure we arent waiting on
  //a sync send for it
  memcpy(val.c,data,4);
  val.i=ntohl(val.i);
  memcpy(outdata,val.c,4);

  if (val.i==client->sendwait)
    client->sendwait=0;

  for (loopa=1;loopa < datalen/4;loopa++)
    {
      memcpy(val.c,(char *)data+(loopa*4),4);
      val.i=ntohl(val.i);
      memcpy(outdata+(loopa*4),val.c,4);
    }

  //Send this now correctly endianded message to the client
  c2CUQ_send(client,GRAPPLE_MESSAGE_CONFIRM_TIMEOUT,outdata,datalen);

  free(outdata);

  return;
}

//This is informing the client that a synchronised variable has been set or
//changed
static void process_message_variable(internal_client_data *client,  
				     grapple_messagetype_internal messagetype,
				     void *data,size_t datalen)
{
  intchar val;
  int type,sec,usec,offset,len;
  char *name;
  int intval;
  double doubleval;
  void *vardata;
  size_t vardatalen;

  //The data here is variable depending on the type of syncronised variable
  //we have
  //4 bytes : Variable type
  //4 bytes : Second time of change
  //4 bytes : Microsecond time of change
  //4 bytes : Length of name
  //        : name
  //        : data. 4 bytes if int, otherwise string to the end

  //First one is the message id, we need to make sure we arent waiting on
  //a sync send for it

  memcpy(val.c,data,4);
  type=ntohl(val.i);

  memcpy(val.c,(char *)data+4,4);
  sec=ntohl(val.i);

  memcpy(val.c,(char *)data+8,4);
  usec=ntohl(val.i);

  memcpy(val.c,(char *)data+12,4);
  len=ntohl(val.i);

  name=(char *)malloc(len+1);
  memcpy(name,(char *)data+16,len);
  name[len]=0;

  offset=len+16;

  switch (type)
    {
    case GRAPPLE_VARIABLE_TYPE_DATA:
      vardatalen=datalen-offset;
      vardata=(void *)malloc(vardatalen);
      memcpy(vardata,(char *)data+offset,vardatalen);
      grapple_variable_timeset_data(client->variables,name,vardata,vardatalen,
				    sec,usec);
      free(vardata);
      break;
    case GRAPPLE_VARIABLE_TYPE_DOUBLE:
      vardatalen=datalen-offset;
      vardata=(void *)malloc(vardatalen+1);
      memcpy(vardata,(char *)data+offset,vardatalen);
      *((char *)vardata+vardatalen)=0;
      doubleval=atof((char *)vardata);
      grapple_variable_timeset_double(client->variables,name,doubleval,
				      sec,usec);
      free(vardata);
      break;
    case GRAPPLE_VARIABLE_TYPE_INT:
      memcpy(val.c,(char *)data+offset,4);
      intval=ntohl(val.i);
      grapple_variable_timeset_int(client->variables,name,intval,sec,usec);
      break;
    default:
      break;
    }

  free(name);

  return;
}

//The server has disconnected, we are in failover mode, so now we try and find
//a new server. This may be ourself.
static int client_run_failover(internal_client_data *client)
{
  grapple_failover_host *newhost;
  grapple_server server=0;
  socketbuf *newsock=NULL;
  int retry;
  grapple_connection *connscan;
  internal_grapple_group *groupscan,*newgroup;
  grapple_group_container *container,*newcontainer;
  int maxval;
  internal_server_data *serverdata;
  grapple_connection *newuser;


  //Find the ID of the lowest possible server
  newhost=failover_locate_lowest_id(client->failoverhosts);

  //There were no servers available
  if (!newhost)
    {
      //Send a disconnect message instead
      c2CUQ_send(client,GRAPPLE_MESSAGE_SERVER_DISCONNECTED,"",0);

      //Destroy ourself
      client->threaddestroy=1;
      client->disconnected=1;
      return 0;
    }

  //The client will now be connecting to somewhere else, drop the address
  free(client->address);
  //And set the new one
  client->address=(char *)malloc(strlen(newhost->address)+1);
  strcpy(client->address,newhost->address);

  //Test if we are to be the new server
  if (newhost->id == client->serverid)
    {
      //We are the new host, run a server
      server=grapple_server_init(client->productname,client->productversion);
      grapple_server_ip_set(server,client->address);
      grapple_server_port_set(server,client->port);
      grapple_server_protocol_set(server,client->protocol);
      grapple_server_session_set(server,client->session);

      serverdata=internal_server_get(server,GRAPPLE_LOCKTYPE_EXCLUSIVE);

      //Set the time when the clients ability to reconnect expires
      serverdata->reconnect_expire=time(NULL)+60;
      
      //Find the highest number of serverid in use, and incriment it by one
      //to the new server id, so we dont get conflicts with the new
      //servers set of IDs
      grapple_thread_mutex_lock(client->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      
      connscan=client->userlist;
      maxval=0;
      while (connscan)
	{
	  if (connscan->serverid>maxval)
	    maxval=connscan->serverid;

	  connscan=connscan->next;
	  if (connscan==client->userlist)
	    connscan=NULL;
	}
      grapple_thread_mutex_unlock(client->connection_mutex);

      //We do the same for groups too, but for groups we also have other work
      //to do. We need to take the list of groups from the client and
      //transfer them to the ner server
      grapple_thread_mutex_lock(client->group_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      
      groupscan=client->groups;
      while (groupscan)
	{
	  //Check the max ID (thats what we are initially doing here)
	  if (groupscan->id>maxval)
	    maxval=groupscan->id;

	  //Add this group to the servers groups now
	  create_server_group(serverdata,groupscan->id,groupscan->name,
			      groupscan->password);

	  newgroup=group_locate(serverdata->groups,groupscan->id);

	  //Now add all the members to this group that are in the clients group
	  container=groupscan->contents;
	  while (container)
	    {
	      newcontainer=group_container_aquire(container->id);

	      //Add this new group member to the group
	      newgroup->contents=group_container_link(newgroup->contents,
						      newcontainer);

	      container=container->next;
	      if (container==groupscan->contents)
		container=NULL;
	    }
	  
	  groupscan=groupscan->next;
	  if (groupscan==client->groups)
	    groupscan=NULL;
	}
      grapple_thread_mutex_unlock(client->group_mutex);

      //Incriment the server connection ID to be correct
      serverdata->user_serverid=maxval+2;


      //Now - for holding user data that may be required later, we add in
      //a set of dummy users

      grapple_thread_mutex_lock(client->connection_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      
      connscan=client->userlist;
      while (connscan)
	{
	  //Create the struct to hold the data
	  newuser=connection_struct_aquire();

	  //Asign a new server ID
	  newuser->serverid=connscan->serverid;
	  newuser->handshook=1;

	  //Create the mutex
	  newuser->message_in_mutex=grapple_thread_mutex_init();
	  newuser->message_out_mutex=grapple_thread_mutex_init();
	  newuser->confirm_mutex=grapple_thread_mutex_init();
	  
	  //Link this into the server
	  serverdata->userlist=connection_link(serverdata->userlist,newuser);

	  connscan=connscan->next;
	  if (connscan==client->userlist)
	    connscan=NULL;
	}
      
      grapple_thread_mutex_unlock(client->connection_mutex);

      //ONLY NOW start the server
      grapple_server_start(server);

      //Set sequential if required
      grapple_server_sequential_set(server,client->sequential);

      //Tell the client that they are now the server
      c2CUQ_send_int(client,GRAPPLE_MESSAGE_YOU_ARE_HOST,(int)server);
    }
  
  //Now we connect the client to the new host - we do this if we are the new
  //host or not

  //For TCP we loop for up to 40 seconds trying to connect, as the new host
  //may not have the new connection up yet
  
  //For UDP we juet let it keep trying, it will time out on itsown at a 
  //lower level in the end.

  switch (client->protocol)
    {
    case GRAPPLE_PROTOCOL_UNKNOWN:
      break;
    case GRAPPLE_PROTOCOL_TCP:
      retry=0;
      while (retry<6000)
	{
	  newsock=socket_create_inet_tcp_wait(client->address,client->port,1);
	  if (newsock && socket_connected(newsock))
	    {
	      retry=6000;
	    }
	  else
	    {
	      retry++;
	      microsleep(10000);
	    }
	}
      break;
    case GRAPPLE_PROTOCOL_UDP:
      newsock=socket_create_inet_udp2way_wait(client->address,client->port,1);
      client->connecting=1;
    }

  //If we have a dead socket now, we cant failover

  if (!newsock || socket_dead(newsock))
    {
      //destroy our new socket
      if (newsock)
	socket_destroy(newsock);

      //Destroy our new server if we cant connect to it
      if (server)
	{
	  grapple_server_stop(server);
	  grapple_server_destroy(server);
	}

      //Let the client know the game is over
      c2CUQ_send(client,GRAPPLE_MESSAGE_SERVER_DISCONNECTED,"",0);

      //Kill ourself
      client->threaddestroy=1;
      client->disconnected=1;
      return 0;
    }
  

  //Immediately send to the server the message that we are a reconnecting
  //player, and what our ID is
  c2s_send_reconnection(client);

  //Then run through the standard handshake
  c2s_handshake(client);

  //We've connected the socket, now use low level socket routines to transfer
  //any outstanding socket buffers to the new socket output stream
  socket_mode_set(newsock,socket_mode_get(client->sock));
  socket_relocate_data(client->sock,newsock);

  //Destroy the old socket
  client->socklist=socket_unlink(client->socklist,client->sock);
  socket_destroy(client->sock);

  //Make the new socket the standard socket
  client->sock=newsock;
  client->socklist=socket_link(client->socklist,client->sock);

  //Now finally remove the chosen failover host from the failover list
  client->failoverhosts=failover_unlink_by_id(client->failoverhosts,
					      newhost->id);

  return 0;
}

//The server has disconnected, this means we must either failover or
//die
static void process_message_server_disconnected(internal_client_data *client,  
						grapple_messagetype_internal messagetype,
						void *data,size_t datalen)
{
  if (client->failover && client->failoverhosts)
    {
      //FAILOVER!
      client_run_failover(client);
    }
  else
    {
      //Now we disconnect the thread, its done
  
      c2CUQ_send(client,GRAPPLE_MESSAGE_SERVER_DISCONNECTED,data,datalen);

      client->threaddestroy=1;
      client->disconnected=1;
    }

  return;
}

//This is message that the game has changed its description
static void process_message_game_description(internal_client_data *client,  
					     grapple_messagetype_internal messagetype,
					     void *data,size_t datalen)
{
  //Let the player know
  c2CUQ_send(client,GRAPPLE_MESSAGE_GAME_DESCRIPTION,data,datalen);
}

//We have received a message from the server, dispatch it to one of the handler
//functions
static void process_message(internal_client_data *client,  
			    grapple_messagetype_internal messagetype,
			    void *data,size_t datalen)
{
  switch (messagetype)
    {
    case GRAPPLE_MESSAGE_USER_CONNECTED:
    case GRAPPLE_MESSAGE_USER_YOU_CONNECTED:
      process_message_user_connected(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_USER_NAME:
      process_message_user_name(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_USER_MESSAGE:
      process_message_user_message(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_USER_DISCONNECTED:
      process_message_user_disconnected(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_HANDSHAKE_FAILED:
      process_message_handshake_failed(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_SESSION_NAME:
      process_message_session_name(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_RELAY_TO:
      process_message_relay_to(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_SERVER_CLOSED:
      process_message_server_closed(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_SERVER_FULL:
      process_message_server_full(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PASSWORD_FAILED:
      process_message_password_failed(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_NAME_NOT_UNIQUE:
      process_message_name_not_unique(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE:
      process_message_protectionkey_not_unique(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PING:
      process_message_ping(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PING_REPLY:
      process_message_ping_reply(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_PING_DATA:
      process_message_ping_data(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_SERVER_DISCONNECTED:
      process_message_server_disconnected(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_FAILOVER_ON:
      process_message_failover_on(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_FAILOVER_OFF:
      process_message_failover_off(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_FAILOVER_CAN:
      process_message_failover_can(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_FAILOVER_CANT:
      process_message_failover_cant(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_NEXT_GROUPID:
      process_message_next_groupid(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_CREATE:
      process_message_group_create(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_ADD:
      process_message_group_add(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_REMOVE:
      process_message_group_remove(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GROUP_DELETE:
      process_message_group_delete(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_CONFIRM_RECEIVED:
      process_message_confirm_received(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_CONFIRM_TIMEOUT:
      process_message_confirm_timeout(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_VARIABLE:
      process_message_variable(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GAME_DESCRIPTION:
      process_message_game_description(client,messagetype,data,datalen);
      break;
    case GRAPPLE_MESSAGE_GRAPPLE_VERSION:
    case GRAPPLE_MESSAGE_PRODUCT_NAME:
    case GRAPPLE_MESSAGE_PRODUCT_VERSION:
    case GRAPPLE_MESSAGE_RELAY_ALL:
    case GRAPPLE_MESSAGE_RELAY_ALL_BUT_SELF:
    case GRAPPLE_MESSAGE_PASSWORD:
    case GRAPPLE_MESSAGE_FAILOVER_TRYME:
    case GRAPPLE_MESSAGE_REQUEST_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_YOU_ARE_HOST:   //This one only used internally
    case GRAPPLE_MESSAGE_RECONNECTION:
    case GRAPPLE_MESSAGE_NOTIFY_STATE:
    case GRAPPLE_MESSAGE_PROTECTIONKEY:
      //Never received by the client
      break;
    }
}

//Here we process the data that has been sent to the clients TCP port
static int process_user_indata_tcp(internal_client_data *client)
{
  const void *data,*ptr;
  void *pulldata,*pullptr;
  size_t length;
  size_t messagelength;
  intchar indata;
  grapple_messagetype_internal messagetype;
  int count=0;

  //We will return as soon as there is no more data, so we can loop forever
  while (1)
    {

      //Initially only VIEW the data, dont take it
      length=socket_indata_length(client->sock);

      //There must be at least 8 bytes for the data, that is the minimum
      //amount of data a packet can contain
      if (length<8)
	return count;

      data=socket_indata_view(client->sock);
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
      pulldata=socket_indata_pull(client->sock,messagelength+8);


      //Move to the start of the data
      pullptr=(char *)pulldata+8;

      //Process the message
      process_message(client,messagetype,pullptr,messagelength);
  
      //Free the data we took
      free(pulldata);

      count++;
    }

  return count;
}

//Here we process the data that has been sent to the clients UDP port
static int process_user_indata_udp(internal_client_data *client)
{
  socket_udp_data *pulldata;
  int messagelength;
  intchar indata;
  grapple_messagetype_internal messagetype;
  int count=0;
  char *ptr;

  //Pull the next UDP packet from the socket
  pulldata=socket_udp_indata_pull(client->sock);

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
      process_message(client,messagetype,ptr,messagelength);
  
      //Free the data struct we were passed
      socket_udp_data_free(pulldata);

      count++;

      //Try and get another
      pulldata=socket_udp_indata_pull(client->sock);
    }

  return count;
}

//This function sends the outbound data queues to the socket
static int process_message_out_queue_tcp(internal_client_data *client)
{
  grapple_queue *data;
  int count=0;

  //Write ALL the data at once
  while (client->message_out_queue)
    {
      grapple_thread_mutex_lock(client->message_out_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      data=client->message_out_queue;
      
      if (!data)
        {
          grapple_thread_mutex_unlock(client->message_out_mutex);
          return count;
        }

      client->message_out_queue=queue_unlink(client->message_out_queue,
					     data);
      grapple_thread_mutex_unlock(client->message_out_mutex);


      //We now have the message data to send
      socket_write(client->sock,
		   (char *)data->data,data->length);

      free(data->data);
      free(data);

      count++;
    }

  return count;
}

//Process the users outbound UDP data
static int process_message_out_queue_udp(internal_client_data *client)
{
  grapple_queue *data;
  int count=0;

  //Continue while there is data to send
  while (client->message_out_queue)
    {
      grapple_thread_mutex_lock(client->message_out_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      data=client->message_out_queue;

      if (!data)
	{
	  grapple_thread_mutex_unlock(client->message_out_mutex);
	  return count;
	}

      client->message_out_queue=queue_unlink(client->message_out_queue,
					     data);
      grapple_thread_mutex_unlock(client->message_out_mutex);

      
      //We now have the message data to send. It may be reliable or unreliable
      if (data->reliablemode)
	socket_write_reliable(client->sock,
			      (char *)data->data,data->length);
      else
	socket_write(client->sock,
		     (char *)data->data,data->length);


      free(data->data);
      free(data);

      count++;
    }

  return count;
}

//This is the main data processing function for TCP/IP links
static void grapple_client_thread_tcp(internal_client_data *client)
{
  int count=0;
  int sockcount;

  //If there are any messages to send out
  if (client->message_out_queue)
    //Send them
    count=process_message_out_queue_tcp(client);

  //Actually process the socket - this function actually sends and receives
  //the data from the network
  sockcount=socket_process_sockets(client->socklist,client->timeout);

  //If the socket has died
  if (socket_dead(client->sock))
    {
      //The server is dead so try and failover if possible
      if (client->failover && client->failoverhosts)
	{
	  //FAILOVER!
	  client_run_failover(client);
	}
      else
	{
	  //The server link is dead, and no failover is offered
	  if (!client->disconnected)
	    {	
	      //Set the client to kill itself
	      c2CUQ_send_int(client,GRAPPLE_MESSAGE_SERVER_DISCONNECTED,0);
	      client->threaddestroy=1;
	      client->disconnected=1;
	    }
	}
    }
  else
    {
      //The socket is still alive in this branch
      if (sockcount)
	{
	  //Process incoming data into the users inbound queue
	  count+=process_user_indata_tcp(client);
	}

      count+=sockcount;

      //If after all the processing, we have nothing to do, we set the next 
      //loop to have a longer timeout on the socket processing, meaning that
      //if something DOES come in and interrupt, then we can return
      //immediately, otherwise we will queue for up to 1/20th of a second 
      //doing nothing
      if (!count)
	client->timeout=100000;
      else
	client->timeout=0;
    }
}

//This is the main data processing function for 2 way UDP/IP links
static void grapple_client_thread_udp(internal_client_data *client)
{
  int count=0;
  int sockcount;

  //If there are any messages to send out
  if (client->message_out_queue)
    //Send them
    count=process_message_out_queue_udp(client);

  //Actually process the socket - this function actually sends and receives
  //the data from the network
  sockcount=socket_process_sockets(client->socklist,client->timeout);

  //If the socket has died
  if (socket_dead(client->sock))
    {
      //The server is dead so try and failover if possible
      if (client->failover && client->failoverhosts)
	{
	  //FAILOVER!
	  client_run_failover(client);
	}
      else
	{
	  //The server link is dead, and no failover is offered
	  if (!client->disconnected)
	    {	
	      //Set the client to kill itself
	      c2CUQ_send_int(client,GRAPPLE_MESSAGE_SERVER_DISCONNECTED,0);
	      client->threaddestroy=1;
	      client->disconnected=1;
	    }
	  //If this socket is still trying to connect, it is dead, too late
	  if (client->connecting)
	    {
	      c2CUQ_send_int(client,GRAPPLE_MESSAGE_SERVER_DISCONNECTED,0);
	      client->connecting=0;
	      client->threaddestroy=1;
	      client->disconnected=1;
	    }
	}
    }
  else
    {
      //The socket is alive in this branch
      if (client->connecting)
	{
	  if (socket_connected(client->sock))
	    {
	      //We have finished connecting, now we can do stuff
	      client->connecting=0;
	    }
	}

      if (sockcount)
	{
	  //Process incoming data into the users inbound queue
	  count+=process_user_indata_udp(client);
	}

      count+=sockcount;

      //If after all the processing, we have nothing to do, we set the next 
      //loop to have a longer timeout on the socket processing, meaning that
      //if something DOES come in and interrupt, then we can return
      //immediately, otherwise we will queue for up to 1/20th of a second 
      //doing nothing
      if (!count)
	client->timeout=100000;
      else
	client->timeout=0;
    }
}


//This is the function that is called when the server thread starts. It loops
//while the thread is alive, and cleans up some when it dies
#ifdef HAVE_PTHREAD_H
static void *grapple_client_thread_main(void *voiddata)
#else
static DWORD WINAPI grapple_client_thread_main(LPVOID voiddata)
#endif
{
  internal_client_data *data;
  int finished=0;
  grapple_queue *target;
  grapple_connection *user;
  grapple_callback_dispatcher **tmpdispatcher;
  grapple_failover_host *failover;
  internal_grapple_group *group;
  int loopa,all_done;

#ifdef HAVE_SIGACTION
  struct sigaction sa;
  memset(&sa,0,sizeof(struct sigaction));
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, 0);
#endif
  //The client we have started
  data=(internal_client_data *)voiddata;

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
	data->dispatcherlist[loopa]=grapple_callback_dispatcher_create(0,data);
    }

  grapple_thread_mutex_unlock(data->dispatcher_mutex);

  //Link the main incoming socket into the list of sockets to process.
  data->socklist=socket_link(data->socklist,data->sock);

  //Link the wakeup socket into the list of sockets to process.
  data->socklist=socket_link(data->socklist,data->wakesock);

  //Continue while we are not finished
  while (!finished)
    {
      //Process the thread data via either the TCP or UDP handler
      switch (data->protocol)
	{
	case GRAPPLE_PROTOCOL_UNKNOWN:
	  break;
	case GRAPPLE_PROTOCOL_TCP:
	  grapple_client_thread_tcp(data);
	  break;
	case GRAPPLE_PROTOCOL_UDP:
	  grapple_client_thread_udp(data);
	  break;
	}

      if (data->threaddestroy)
	{
          //We have been told to end the thread
	  finished=1;

	  //Try and quickly send all remaining messages, as we have to
	  //try and send the disconnect message...
	  switch (data->protocol)
	    {
	    case GRAPPLE_PROTOCOL_UNKNOWN:
	      break;
	    case GRAPPLE_PROTOCOL_TCP:
	      while (data->message_out_queue && !socket_dead(data->sock))
		{
		  process_message_out_queue_tcp(data);
		  if (!socket_dead(data->sock) &&
		      socket_outdata_length(data->sock)>0)
		      
		    {
		      //Try and push the data down the socket. We do this here
		      //as well as a little below so that we can try and give
		      //the kernel as much time as possible to send the data
		      socket_process(data->sock,0);
		    }
		}
	      break;
	    case GRAPPLE_PROTOCOL_UDP:
	      while (data->message_out_queue && !socket_dead(data->sock))
		{
		  process_message_out_queue_udp(data);
		  if (!socket_dead(data->sock) &&
		      socket_outdata_length(data->sock)>0)
		      
		    {
		      //Try and push the data down the socket. We do this here
		      //as well as a little below so that we can try and give
		      //the kernel as much time as possible to send the data
		      socket_process(data->sock,0);
		    }
		}
	      break;
	    }

	  //While the socket is still alive, try and shove the remaining
	  //data down the socket
	  while (!socket_dead(data->sock) &&
		 socket_outdata_length(data->sock)>0)
		 
	    {
	      socket_process(data->sock,0);
	    }

	  //Get rid of the socket now
          data->socklist=socket_unlink(data->socklist,data->sock);
          socket_destroy(data->sock);
          data->sock=NULL;

	  //And the wake socket if it existed
	  grapple_thread_mutex_lock(data->internal_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  if (data->wakesock)
	    {
	      data->socklist=socket_unlink(data->socklist,data->wakesock);
	      socket_destroy(data->wakesock);
	      data->wakesock=NULL;
	    }
	  grapple_thread_mutex_unlock(data->internal_mutex);

	  //And the failover socket if it existed - its a bit late now
	  if (data->failoversock)
	    {
	      socket_destroy(data->failoversock);
	      data->failoversock=NULL;
	    }

	  //Remove anything left in the outbound queue
	  grapple_thread_mutex_lock(data->message_out_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);

	  while (data->message_out_queue)
	    {
	      target=data->message_out_queue;
	      data->message_out_queue=queue_unlink(data->message_out_queue,
						  data->message_out_queue);
	      queue_struct_dispose(target);
	    }
	  grapple_thread_mutex_unlock(data->message_out_mutex);

	  //Clear the userlist
	  while (data->userlist)
	    {
	      grapple_thread_mutex_lock(data->connection_mutex,
					GRAPPLE_LOCKTYPE_EXCLUSIVE);
	      user=data->userlist;
	      if (data->userlist)
		data->userlist=
		  connection_unlink(data->userlist,data->userlist);
	      grapple_thread_mutex_unlock(data->connection_mutex);
	      if (user)
		connection_struct_dispose(user);
	    }

	  //Delete all callbacks	  
	  grapple_thread_mutex_lock(data->callback_mutex,
				    GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  while (data->callbackanchor)
	    {
	      data->callbackanchor=grapple_callback_remove(data->callbackanchor,
							   data->callbackanchor->type);
	    }
	  grapple_thread_mutex_unlock(data->callback_mutex);

	  //Now kill the callback dispatcher thread
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
  data->threaddestroy=0;

  grapple_thread_destroy(data->thread);
  data->thread=0;

#ifdef HAVE_PTHREAD_H
  return NULL;
#else
  return 0;
#endif
}

//Function called by the grapple_client_start function to actually start the
//thread
int grapple_client_thread_start(internal_client_data *data)
{
  data->threaddestroy=0;

  data->thread=grapple_thread_create(grapple_client_thread_main,(void *)data);

  if (!data->thread)
    return -1;

  return 1;
}
