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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "grapple_comms_api.h"
#include "grapple_comms.h"
#include "grapple_client_internal.h"
#include "grapple_defines.h"
#include "grapple_internal.h"
#include "grapple_confirm.h"
#include "grapple_variable.h"


/* Most of the functions in this file are simply taking data from one form
   and moving it onto a message queue. As such Im not going to comment each
   small detail, just overviers*/

//Conventions in this file for function names
/*  
    c2s is a function sending data from the client to the server
    s2c is sending from the server to the client
    s2SUQ is sending data from the server to the servers user queue
    c2CUQ is sending data from the client to the clients user queue
*/

//Send the hardcoded version of this library to the server
static int c2s_handshake_send_grapple_version(internal_client_data *client)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  returnval=c2s_send(client,GRAPPLE_MESSAGE_GRAPPLE_VERSION,
		     GRAPPLE_VERSION,strlen(GRAPPLE_VERSION));
  client->reliablemode=reliable;
  
  return returnval;
}

//Send the name of the game we are playing
static int c2s_handshake_send_product_name(internal_client_data *client)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  returnval=c2s_send(client,GRAPPLE_MESSAGE_PRODUCT_NAME,
		     client->productname,
		     strlen(client->productname));
  client->reliablemode=reliable;
  
  return returnval;
}

//Send the name of the game we are playing
static int c2s_handshake_send_protectionkey(internal_client_data *client)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  if (client->protectionkey && *client->protectionkey)
    returnval=c2s_send(client,GRAPPLE_MESSAGE_PROTECTIONKEY,
		       client->protectionkey,
		       strlen(client->protectionkey));
  else
    returnval=c2s_send(client,GRAPPLE_MESSAGE_PROTECTIONKEY,
		       "",0);

  client->reliablemode=reliable;
  
  return returnval;
}

//Send the version of the game we are playing
static int c2s_handshake_send_product_version(internal_client_data *client)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  returnval=c2s_send(client,GRAPPLE_MESSAGE_PRODUCT_VERSION,
		     client->productversion,
		     strlen(client->productversion));
  client->reliablemode=reliable;
  
  return returnval;
}

//Send the password - if there is one, otherwise an empty string
static int c2s_handshake_send_password(internal_client_data *client)
{
  int reliable;
  int returnval;
  const char *password;
  size_t len;
  
  reliable=client->reliablemode;
  client->reliablemode=1;

  if (client->name_provisional && *client->name_provisional)
    {
      c2s_send(client,GRAPPLE_MESSAGE_USER_NAME,
	       client->name_provisional,strlen(client->name_provisional));
    }

  if (client->password && *client->password)
    {
      password=client->password;
      len=strlen(client->password);
    }
  else
    {
      password="";
      len=0;
    }

  returnval=c2s_send(client,GRAPPLE_MESSAGE_PASSWORD,
		     password,len);

  client->reliablemode=reliable;
  
  return returnval;
}

//Run the whole handshake, calling the subfunctions
int c2s_handshake(internal_client_data *client)
{
  //Send notify early on, as we want to do this before handshake finishes and
  //we dont want the notifications
  if (client->notify!=GRAPPLE_NOTIFY_STATE_ON)
    c2s_set_notify_state(client,client->notify);

  if (!c2s_handshake_send_grapple_version(client))
    return 0;

  if (!c2s_handshake_send_protectionkey(client))
    return 0;

  if (!c2s_handshake_send_product_name(client))
    return 0;

  if (!c2s_handshake_send_product_version(client))
    return 0;

  if (!c2s_handshake_send_password(client))
    return 0;

  return 1;
}

//Client ping the server
int c2s_ping(internal_client_data *client,int number)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  returnval=c2s_send_int(client,GRAPPLE_MESSAGE_PING,number);

  client->reliablemode=reliable;
  
  return returnval;
}

int c2s_set_notify_state(internal_client_data *client,int notify)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  returnval=c2s_send_int(client,GRAPPLE_MESSAGE_NOTIFY_STATE,notify);

  client->reliablemode=reliable;
  
  return returnval;
}

//Client has been pinged by the server, replying
int c2s_pingreply(internal_client_data *client,int number)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  returnval=c2s_send_int(client,GRAPPLE_MESSAGE_PING_REPLY,number);

  client->reliablemode=reliable;
  
  return returnval;
}

//Client has sent a variable to the server
int c2s_variable_send(internal_client_data *client,grapple_variable *var)
{
  int reliable;
  int returnval;
  size_t namelen,length,offset;
  char *outdata;
  intchar val;

  reliable=client->reliablemode;

  client->reliablemode=1;

  namelen=strlen(var->name);
  length=8; //length of type + size of name
  length+=namelen; //name length
  if (var->vartype==GRAPPLE_VARIABLE_TYPE_DATA)
    {
      length+=(var->length);
      outdata=(char *)malloc(length);

      val.i=htonl(GRAPPLE_VARIABLE_TYPE_DATA);
      memcpy(outdata,val.c,4);

      val.i=htonl((long)namelen);
      memcpy(outdata+4,val.c,4);
      
      memcpy(outdata+8,var->name,namelen);

      offset=namelen+8;

      memcpy(outdata+offset,var->data,var->length);
      
    }
  else if (var->vartype==GRAPPLE_VARIABLE_TYPE_INT)
    {
      length+=4;
      outdata=(char *)malloc(length);

      val.i=htonl(GRAPPLE_VARIABLE_TYPE_INT);
      memcpy(outdata,val.c,4);

      val.i=htonl((long)namelen);
      memcpy(outdata+4,val.c,4);
      
      memcpy(outdata+8,var->name,namelen);

      offset=namelen+8;

      val.i=htonl(var->intdata);
      memcpy(outdata+offset,val.c,4);
    }
  else if (var->vartype==GRAPPLE_VARIABLE_TYPE_DOUBLE)
    {
      length+=30;
      outdata=(char *)malloc(length);

      val.i=htonl(GRAPPLE_VARIABLE_TYPE_DOUBLE);
      memcpy(outdata,val.c,4);

      val.i=htonl((long)namelen);
      memcpy(outdata+4,val.c,4);
      
      memcpy(outdata+8,var->name,namelen);

      offset=namelen+8;

      sprintf(outdata+offset,"%f",var->doubledata);
      length-=30;
      length+=strlen(outdata+offset);
    }
  else
    return 0;

  returnval=c2s_send(client,GRAPPLE_MESSAGE_VARIABLE,outdata,length);

  client->reliablemode=reliable;
  
  free(outdata);

  return returnval;
}

//Server letting the client know their handshake failed
int s2c_handshake_failed(internal_server_data *server,
			 grapple_connection *user)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_HANDSHAKE_FAILED,0);
  
  user->reliablemode=reliable;

  return returnval;
}

//Server letting the client know their password was wrong
int s2c_password_failed(internal_server_data *server,grapple_connection *user)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_PASSWORD_FAILED,0);
  
  user->reliablemode=reliable;

  return returnval;
}

//Server letting the client know that their key needed to be unique and wasnt
int s2c_unique_protectionkey_failed(internal_server_data *server,
				    grapple_connection *user)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE,0);
  
  user->reliablemode=reliable;

  return returnval;
}

//Server letting the client know that their name needed to be unique and wasnt
int s2c_unique_name_failed(internal_server_data *server,
			   grapple_connection *user)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_NAME_NOT_UNIQUE,0);
  
  user->reliablemode=reliable;

  return returnval;
}

//Server letting the client know that the server is closed to new connections
int s2c_server_closed(internal_server_data *server,grapple_connection *user)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_SERVER_CLOSED,0);
  
  user->reliablemode=reliable;

  return returnval;
}

//Server letting the client know the server is full, cant connect
int s2c_server_full(internal_server_data *server,grapple_connection *user)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_SERVER_FULL,0);
  
  user->reliablemode=reliable;

  return returnval;
}

//Server sending the name of the session to a client
int s2c_session_name(internal_server_data *server,
		     grapple_connection *user,const char *session)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_SESSION_NAME,
		     session,strlen(session));
  
  user->reliablemode=reliable;

  return returnval;
}

//Server letting a client know a user has connected
int s2c_user_connected(internal_server_data *server,
		       grapple_connection *target,grapple_connection *newuser)
{
  int reliable;
  int returnval;
  char *outdata;
  intchar val;
  size_t length;

  if (!target->handshook || !newuser->handshook)
    return 0;

  if (target->notify==GRAPPLE_NOTIFY_STATE_OFF && target!=newuser)
    return 0;
  if (server->notify==GRAPPLE_NOTIFY_STATE_OFF)
    return 0;

  val.i=htonl(newuser->serverid);

  if (newuser->name)
    {
      length=strlen(newuser->name);
      outdata=(char *)malloc(length+4);

      memcpy(outdata,val.c,4);
      memcpy(outdata+4,newuser->name,length);
    }
  else
    {
      length=0;
      outdata=(char *)malloc(4);
      memcpy(outdata,val.c,4);
    }


  reliable=target->reliablemode;

  target->reliablemode=1;

  if (target==newuser)
    returnval=s2c_send(server,target,GRAPPLE_MESSAGE_USER_YOU_CONNECTED,
		       outdata,length+4);
  else
    returnval=s2c_send(server,target,GRAPPLE_MESSAGE_USER_CONNECTED,
		       outdata,length+4);

  target->reliablemode=reliable;
  
  free(outdata);

  return returnval;
}

//Client sending their name to the server
int c2s_set_name(internal_client_data *client,const char *name)
{
  int reliable;
  int returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;
  returnval=c2s_send(client,GRAPPLE_MESSAGE_USER_NAME,
		     name,
		     strlen(name));
  client->reliablemode=reliable;
  
  return returnval;
}


//Server letting a client know of someone elses name
int s2c_user_setname(internal_server_data *server,
		     grapple_connection *target,grapple_connection *user)
{
  //Assemble new data that contains the ID and then the name
  void *data;
  intchar serverid;
  int returnval;
  int reliable;

  data=(void *)malloc(strlen(user->name)+4);

  serverid.i=htonl(user->serverid);
  memcpy(data,serverid.c,4);

  memcpy((char *)data+4,user->name,strlen(user->name));

  reliable=target->reliablemode;

  target->reliablemode=1;

  returnval=s2c_send(server,target,GRAPPLE_MESSAGE_USER_NAME,
		     data,
		     strlen(user->name)+4);

  target->reliablemode=reliable;
  
  free(data);
  
  return returnval;
}


int s2SUQ_group_remove(internal_server_data *server,
		       grapple_connection *user,
		       grapple_user groupid,
		       grapple_user removeid)
{
  intchar val;
  char outdata[8];

  //Now construct the data for the servers message queue
  val.i=groupid;
  memcpy(outdata,val.c,4);

  val.i=removeid;
  memcpy(outdata+4,val.c,4);

  //Send the message to the servers message queue
  return s2SUQ_send(server,user->serverid,GRAPPLE_MESSAGE_GROUP_REMOVE,
		    outdata,8);
}

//Server telling the calling program that a user has set their name
int s2SUQ_user_setname(internal_server_data *server,grapple_connection *user)
{
  //Assemble new data that contains the ID and then the name
  return s2SUQ_send(server,
		    user->serverid,
		    GRAPPLE_MESSAGE_USER_NAME,
		    user->name,
		    strlen(user->name));
}

//Server letting a client know a user has connected
int s2SUQ_user_connected(internal_server_data *server,grapple_connection *user)
{
  int returnval;
  char *outdata;
  intchar val;
  size_t length;

  val.i=user->serverid;

  if (user->name)
    {
      length=strlen(user->name);
      outdata=(char *)malloc(length+4);

      memcpy(outdata,val.c,4);
      memcpy(outdata+4,user->name,length);
    }
  else
    {
      length=0;
      outdata=(char *)malloc(4);
      memcpy(outdata,val.c,4);
    }

  returnval=s2SUQ_send(server,
		       user->serverid,
		       GRAPPLE_MESSAGE_USER_CONNECTED,
		       outdata,length+4);

  free(outdata);

  return returnval;
}

//Server telling the calling program that a message has been confirmed
int s2SUQ_confirm_received(internal_server_data *server,int messageid)
{
  //Assemble new data that contains the ID of the completed message
  
  return s2SUQ_send_int(server,
			0,
			GRAPPLE_MESSAGE_CONFIRM_RECEIVED,
			messageid);
}

//Server telling the calling program that a user has disconnected
int s2SUQ_user_disconnect(internal_server_data *server,
			  grapple_connection *user)
{
  //Assemble new data that contains the ID and then the name
  return s2SUQ_send_int(server,
			user->serverid,
			GRAPPLE_MESSAGE_USER_DISCONNECTED,
			user->serverid);
}

//Server telling the calling program that some users didnt receive a message
int s2SUQ_confirm_timeout(internal_server_data *server,grapple_confirm *conf)
{
  char *outdata;
  intchar val;
  int size,loopa;
  int returnval;
  //This is the most complex message we have

  //We need to send the message ID, the number of failuers and then the list
  //of failures
  size=conf->receivercount+2;

  size*=4;
  
  outdata=(char *)malloc(size);

  val.i=conf->messageid;
  memcpy(outdata,val.c,4);

  val.i=conf->receivercount;
  memcpy(outdata+4,val.c,4);

  for (loopa=0;loopa<conf->receivercount;loopa++)
    {
      val.i=conf->receivers[loopa];
      memcpy(outdata+(loopa*4)+8,val.c,4);
    }

  returnval=s2SUQ_send(server,
		       0,
		       GRAPPLE_MESSAGE_CONFIRM_TIMEOUT,
		       outdata,
		       size);

  free(outdata);

  return returnval;
  
}

//Server sending a user message to a client
int s2c_message(internal_server_data *server,
		grapple_connection *user,int flags,int messageid,
		const void *data,size_t datalen)
{
  int reliable,returnval;
  char *outdata;
  intchar val;

  if (!user->handshook)
    {
      return 0;
    }

  if (flags & GRAPPLE_CONFIRM)
    server_register_confirm(server,messageid,user->serverid);

  reliable=user->reliablemode;
  if (flags & GRAPPLE_RELIABLE)
    user->reliablemode=1;

  outdata=(char *)malloc(datalen+8);

  val.i=flags;
  memcpy(outdata,val.c,4);

  val.i=htonl(messageid);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,data,datalen);

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_USER_MESSAGE,
		     outdata,datalen+8);

  free(outdata);

  user->reliablemode=reliable;

  return returnval;
}

//Client sending a user message to the server
int c2s_message(internal_client_data *client,int flags,grapple_confirmid id,
		const void *data,size_t datalen)
{
  char *outdata;
  intchar val;
  int returnval,reliable;

  reliable=client->reliablemode;
  if (flags & GRAPPLE_RELIABLE)
    client->reliablemode=1;

  outdata=(char *)malloc(datalen+8);
  
  val.i=flags;
  memcpy(outdata,val.c,4);

  val.i=htonl(id);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,data,datalen);
  
  returnval=c2s_send(client,GRAPPLE_MESSAGE_USER_MESSAGE,outdata,datalen+8);

  free(outdata);

  client->reliablemode=reliable;

  return returnval;
}

//Client asking the server to relay a message to another client
int c2s_relaymessage(internal_client_data *client,int target,
		     int flags,grapple_confirmid id,
		     const void *data,size_t datalen)
{
  char *outdata;
  intchar val;
  int returnval,reliable;

  reliable=client->reliablemode;
  if (flags & GRAPPLE_RELIABLE)
    client->reliablemode=1;

  outdata=(char *)malloc(datalen+12);
  
  val.i=htonl(target);
  memcpy(outdata,val.c,4);

  val.i=flags;
  memcpy(outdata+4,val.c,4);

  val.i=htonl(id);
  memcpy(outdata+8,val.c,4);

  memcpy(outdata+12,data,datalen);
  
  returnval=c2s_send(client,GRAPPLE_MESSAGE_RELAY_TO,outdata,datalen+12);

  free(outdata);

  client->reliablemode=reliable;

  return returnval;
}

//Client asking the server to relay a message to everyone
int c2s_relayallmessage(internal_client_data *client,
			int flags,grapple_confirmid id,
			const void *data,size_t datalen)
{
  char *outdata;
  intchar val;
  int returnval,reliable;

  reliable=client->reliablemode;
  if (flags & GRAPPLE_RELIABLE)
    client->reliablemode=1;

  outdata=(char *)malloc(datalen+8);
  
  val.i=flags;
  memcpy(outdata,val.c,4);

  val.i=htonl(id);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,data,datalen);
  
  returnval=c2s_send(client,GRAPPLE_MESSAGE_RELAY_ALL,outdata,datalen+8);

  free(outdata);

  client->reliablemode=reliable;

  return returnval;
}

//Client asking the server to relay a message to everyone but themselves
int c2s_relayallbutselfmessage(internal_client_data *client,
			       int flags,grapple_confirmid id,
			       const void *data,size_t datalen)
{
  char *outdata;
  intchar val;
  int returnval,reliable;

  reliable=client->reliablemode;
  if (flags & GRAPPLE_RELIABLE)
    client->reliablemode=1;

  outdata=(char *)malloc(datalen+8);
  
  val.i=flags;
  memcpy(outdata,val.c,4);

  val.i=htonl(id);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,data,datalen);
  
  returnval=c2s_send(client,GRAPPLE_MESSAGE_RELAY_ALL_BUT_SELF,
		     outdata,datalen+8);

  free(outdata);

  client->reliablemode=reliable;

  return returnval;
}

//Client letting the server know they are disconnecting
int c2s_disconnect(internal_client_data *client)
{
  int reliable,returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;

  returnval=c2s_send(client,GRAPPLE_MESSAGE_USER_DISCONNECTED,"",0);

  client->reliablemode=reliable;

  return returnval;
}

//Client is requesting a group ID from the server
int c2s_request_group(internal_client_data *client)
{
  int reliable,returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;

  returnval=c2s_send(client,GRAPPLE_MESSAGE_REQUEST_NEXT_GROUPID,"",0);

  client->reliablemode=reliable;

  return returnval;
}

//Client is creating a group, and informing the server
int c2s_group_create(internal_client_data *client,int id,const char *name,
		     const char *password)
{
  int returnval;
  size_t offset;
  int reliable;
  size_t length,passlength;
  intchar val;
  char *outdata;

  length=strlen(name);
  if (password && *password)
    passlength=strlen(password);
  else
    passlength=0;
  outdata=(char *)malloc(length+passlength+12);

  val.i=htonl(id);
  memcpy(outdata,val.c,4);

  val.i=htonl((long)length);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,name,length);

  offset=8+length;

  val.i=htonl((long)passlength);
  memcpy(outdata+offset,val.c,4);

  offset+=4;

  if (passlength)
    {
      memcpy(outdata+offset,password,passlength);
      offset+=passlength;
    }

  reliable=client->reliablemode;

  client->reliablemode=1;

  returnval=c2s_send(client,GRAPPLE_MESSAGE_GROUP_CREATE,outdata,offset);

  client->reliablemode=reliable;

  free(outdata);
  
  return returnval;
}

//Client informing the server of the user they just added to the group
int c2s_group_add(internal_client_data *client,int group,int add,
		  const char *password)
{
  char *outdata;
  intchar val;
  int reliable,returnval;
  size_t passlength;

  if (password && *password)
    passlength=strlen(password);
  else
    passlength=0;
  
  outdata=(char *)malloc(passlength+12);

  reliable=client->reliablemode;

  client->reliablemode=1;

  val.i=htonl(group);
  memcpy(outdata,val.c,4);

  val.i=htonl(add);
  memcpy(outdata+4,val.c,4);

  val.i=htonl((long)passlength);
  memcpy(outdata+8,val.c,4);

  if (passlength)
    memcpy(outdata+12,password,passlength);
    
  returnval=c2s_send(client,GRAPPLE_MESSAGE_GROUP_ADD,outdata,12+passlength);

  client->reliablemode=reliable;

  free(outdata);

  return returnval;
}

//Client informing the server of the user they removed FROM the group
int c2s_group_remove(internal_client_data *client,int group,int removeid)
{
  char outdata[8];
  intchar val;
  int reliable,returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;

  val.i=htonl(group);
  memcpy(outdata,val.c,4);

  val.i=htonl(removeid);
  memcpy(outdata+4,val.c,4);

  returnval=c2s_send(client,GRAPPLE_MESSAGE_GROUP_REMOVE,outdata,8);

  client->reliablemode=reliable;

  return returnval;
}

//Client letting the server know they deleted a group
int c2s_group_delete(internal_client_data *client,int id)
{
  int reliable,returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;

  returnval=c2s_send_int(client,GRAPPLE_MESSAGE_GROUP_DELETE,id);

  client->reliablemode=reliable;

  return returnval;
}

//Client tellign the server they cant failover
int c2s_failover_cant(internal_client_data *client)
{
  int reliable,returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;

  returnval=c2s_send(client,GRAPPLE_MESSAGE_FAILOVER_CANT,"",0);

  client->reliablemode=reliable;

  return returnval;
}

//client letting the server know they THINK they can failover and asking the
//server to test it
int c2s_failover_tryme(internal_client_data *client)
{
  int reliable,returnval;

  reliable=client->reliablemode;

  client->reliablemode=1;

  returnval=c2s_send(client,GRAPPLE_MESSAGE_FAILOVER_TRYME,"",0);

  client->reliablemode=reliable;

  return returnval;
}

//Client telling the new server they are a reconnecting user
int c2s_send_reconnection(internal_client_data *client)
{
  int reliable,returnval;
  char *outdata;
  intchar val;
  size_t length;

  length=strlen(client->name);

  outdata=(char *)malloc(length+8);

  val.i=htonl(client->serverid);
  memcpy(outdata,val.c,4);

  val.i=htonl((long)length);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,client->name,length);

  reliable=client->reliablemode;

  client->reliablemode=1;

  returnval=c2s_send(client,GRAPPLE_MESSAGE_RECONNECTION,outdata,length+8);

  client->reliablemode=reliable;

  return returnval;
}

//Client telling the server they have received the message that the server
//requested they confirm
int c2s_confirm_received(internal_client_data *client,int from,int messageid)
{
  int returnval;
  int reliable;
  intchar val;
  char outdata[8];

  reliable=client->reliablemode;

  client->reliablemode=1;

  val.i=htonl(from);
  memcpy(outdata,val.c,4);

  val.i=htonl(messageid);
  memcpy(outdata+4,val.c,4);

  returnval=c2s_send(client,GRAPPLE_MESSAGE_CONFIRM_RECEIVED,outdata,8);

  client->reliablemode=reliable;
  
  return returnval;
}

//Server relaying a user message to a client
int s2c_relaymessage(internal_server_data *server,
		     grapple_connection *user,grapple_connection *origin,
		     int flags,int messageid,
		     void *data,size_t datalen)
{
  char *outdata;
  intchar val;
  int returnval,reliable;

  if (!user->handshook)
    return 0;

  outdata=(char *)malloc(datalen+12);
  
  val.i=htonl(origin->serverid);
  memcpy(outdata,val.c,4);

  val.i=flags;
  memcpy(outdata+4,val.c,4);

  val.i=htonl(messageid);
  memcpy(outdata+8,val.c,4);

  memcpy(outdata+12,data,datalen);

  reliable=user->reliablemode;

  if (flags & GRAPPLE_RELIABLE)
    user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_RELAY_TO,outdata,datalen+12);

  user->reliablemode=reliable;

  free(outdata);

  if (flags & GRAPPLE_CONFIRM)
    register_confirm(origin,messageid,user->serverid);

  return returnval;

}

//Server informing a client that someone else has disconnected
int s2c_inform_disconnect(internal_server_data *server,
			  grapple_connection *user,grapple_connection *target)
{
  int reliable;
  int returnval;

  if (!user->handshook && user!=target)
    return 0;

  if (user->notify==GRAPPLE_NOTIFY_STATE_OFF && target!=user)
    return 0;
  if (server->notify==GRAPPLE_NOTIFY_STATE_OFF)
    return 0;

  reliable=target->reliablemode;

  target->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_USER_DISCONNECTED,
			 target->serverid);

  target->reliablemode=reliable;
  
  return returnval;
}

//Server pinging a client
int s2c_ping(internal_server_data *server,grapple_connection *user,int number)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;
  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_PING,number);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server replying to a ping sent by a client
int s2c_pingreply(internal_server_data *server,
		  grapple_connection *user,int number)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;
  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_PING_REPLY,number);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server is disconnecting
int s2c_disconnect(internal_server_data *server,grapple_connection *user)
{
  int reliable;
  int returnval;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_SERVER_DISCONNECTED,"",0);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server sending ping data to a client about someone elses ping times
int s2c_ping_data(internal_server_data *server,
		  grapple_connection *target,grapple_connection *about)
{
  int returnval;
  intchar val;
  char data[50];
  int reliable;

  if (!target->handshook)
    return 0;

  val.i=htonl(about->serverid);
  memcpy(data,val.c,4);

  sprintf(data+4,"%f",about->pingtime);

  reliable=target->reliablemode;

  target->reliablemode=1;

  returnval=s2c_send(server,target,GRAPPLE_MESSAGE_PING_DATA,data,
		     strlen(data+4)+4);

  target->reliablemode=reliable;
  
  return returnval;
}

//Server requests the client turn off failover
int s2c_failover_off(internal_server_data *server,grapple_connection *user)
{
  int returnval;
  int reliable;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_FAILOVER_OFF,"",0);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server requests the client turn ON failover
int s2c_failover_on(internal_server_data *server,grapple_connection *user)
{
  int returnval;
  int reliable;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_FAILOVER_ON,"",0);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server notifying the client they cant failover
int s2c_failover_cant(internal_server_data *server,
		      grapple_connection *user,int id)
{
  int returnval;
  int reliable;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_FAILOVER_CANT,id);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server notifying a client that an address can be used to failover to
int s2c_failover_can(internal_server_data *server,
		     grapple_connection *user,int id,const char *host)
{
  int returnval;
  int reliable;
  size_t length;
  intchar val;
  char *outdata;

  if (!user->handshook)
    return 0;

  length=strlen(host);

  outdata=(char *)malloc(length+8);

  val.i=htonl(id);
  memcpy(outdata,val.c,4);

  val.i=htonl((long)length);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,host,length);

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_FAILOVER_CAN,
		     outdata,length+8);

  user->reliablemode=reliable;
  
  return returnval;
}


//Server sending a new group ID to a client
int s2c_send_nextgroupid(internal_server_data *server,
			 grapple_connection *user,int groupid)
{
  int returnval;
  int reliable;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_NEXT_GROUPID,groupid);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server has created a group, notify a client
int s2c_group_create(internal_server_data *server,
		     grapple_connection *user,int groupid,const char *name,
		     const char *password)
{
  int returnval;
  int reliable;
  size_t namelength,passlength,offset;
  intchar val;
  char *outdata;

  if (!user->handshook)
    return 0;

  namelength=strlen(name);
  if (password && *password)
    passlength=strlen(password);
  else
    passlength=0;
  outdata=(char *)malloc(namelength+passlength+12);

  val.i=htonl(groupid);
  memcpy(outdata,val.c,4);

  val.i=htonl((long)namelength);
  memcpy(outdata+4,val.c,4);

  memcpy(outdata+8,name,namelength);
  
  offset=namelength+8;

  val.i=htonl((long)passlength);
  memcpy(outdata+offset,val.c,4);

  offset+=4;

  if (passlength)
    {
      memcpy(outdata+offset,password,passlength);
      offset+=passlength;
    }
  

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_GROUP_CREATE,
		     outdata,offset);

  user->reliablemode=reliable;
  
  free(outdata);

  return returnval;
}

//Server has added a user to a group, notify a client
int s2c_group_add(internal_server_data *server,
		  grapple_connection *user,int group,int add)
{
  int returnval;
  int reliable;
  char outdata[8];
  intchar val;

  if (!user->handshook)
    return 0;

  val.i=htonl(group);
  memcpy(outdata,val.c,4);

  val.i=htonl(add);
  memcpy(outdata+4,val.c,4);

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_GROUP_ADD,outdata,8);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server has removed someone from a group, notify a client
int s2c_group_remove(internal_server_data *server,
		     grapple_connection *user,int group,int removeid)
{
  int returnval;
  int reliable;
  char outdata[8];
  intchar val;

  if (!user->handshook)
    return 0;

  val.i=htonl(group);
  memcpy(outdata,val.c,4);

  val.i=htonl(removeid);
  memcpy(outdata+4,val.c,4);

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_GROUP_REMOVE,outdata,8);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server has deleted a group, notify a client
int s2c_group_delete(internal_server_data *server,
		     grapple_connection *user,int groupid)
{
  int returnval;
  int reliable;

  if (!user->handshook)
    return 0;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_GROUP_DELETE,groupid);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server is confirming to the client that a message has reached all of
//its intended recipients
int s2c_confirm_received(internal_server_data *server,
			 grapple_connection *user,int messageid)
{
  int returnval;
  int reliable;

  reliable=user->reliablemode;

  user->reliablemode=1;

  returnval=s2c_send_int(server,user,GRAPPLE_MESSAGE_CONFIRM_RECEIVED,
			 messageid);

  user->reliablemode=reliable;
  
  return returnval;
}

//Server is notifying a client that a message didnt reach everyone it was
//supposed to
int s2c_confirm_timeout(internal_server_data *server,
			grapple_connection *user,grapple_confirm *conf)
{
  char *outdata;
  intchar val;
  int size,loopa;
  int returnval;
  int reliable;

  reliable=user->reliablemode;

  user->reliablemode=1;

  //This is the most complex message we have

  //We need to send the message ID, the number of failuers and then the list
  //of failures
  size=conf->receivercount+2;

  size*=4;
  
  outdata=(char *)malloc(size);

  val.i=htonl(conf->messageid);
  memcpy(outdata,val.c,4);

  //This is the number of failed confirmations
  val.i=htonl(conf->receivercount);
  memcpy(outdata+4,val.c,4);

  //Loop through each remaining unreceived confirmation and add that ID
  //of that user to the list
  for (loopa=0;loopa<conf->receivercount;loopa++)
    {
      val.i=htonl(conf->receivers[loopa]);
      memcpy(outdata+(loopa*4)+8,val.c,4);
    }

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_CONFIRM_TIMEOUT,outdata,size);

  free(outdata);

  user->reliablemode=reliable;
  
  return returnval;
  
}

//Client has sent a variable to the server
int s2c_variable_send(internal_server_data *server,
		      grapple_connection *user,grapple_variable *var)
{
  int reliable;
  int returnval;
  size_t length,namelen,offset;
  char *outdata;
  intchar val;

  reliable=server->reliablemode;

  server->reliablemode=1;

  namelen=strlen(var->name);
  length=16; //length of type + size of name + times
  length+=namelen; //name length
  switch (var->vartype)
    {
    case GRAPPLE_VARIABLE_TYPE_DATA:
      {
	length+=(var->length);
	outdata=(char *)malloc(length);
	
	val.i=htonl(GRAPPLE_VARIABLE_TYPE_DATA);
	memcpy(outdata,val.c,4);
	
	val.i=htonl(var->sec);
	memcpy(outdata+4,val.c,4);
	
	val.i=htonl(var->usec);
	memcpy(outdata+8,val.c,4);
	
	val.i=htonl((long)namelen);
	memcpy(outdata+12,val.c,4);
	
	memcpy(outdata+16,var->name,namelen);
	
	offset=namelen+16;
	
	memcpy(outdata+offset,var->data,var->length);
	
      }
      break;
    case GRAPPLE_VARIABLE_TYPE_INT:
      {
	length+=4;
	outdata=(char *)malloc(length);
	
	val.i=htonl(GRAPPLE_VARIABLE_TYPE_INT);
	memcpy(outdata,val.c,4);
	
	val.i=htonl(var->sec);
	memcpy(outdata+4,val.c,4);
	
	val.i=htonl(var->usec);
	memcpy(outdata+8,val.c,4);
	
	val.i=htonl((long)namelen);
	memcpy(outdata+12,val.c,4);
	
	memcpy(outdata+16,var->name,namelen);
	
	offset=namelen+16;
	
	val.i=htonl(var->intdata);
	memcpy(outdata+offset,val.c,4);
      }
      break;
    case GRAPPLE_VARIABLE_TYPE_DOUBLE:
      {
	length+=30;
	outdata=(char *)malloc(length);
	
	val.i=htonl(GRAPPLE_VARIABLE_TYPE_DOUBLE);
	memcpy(outdata,val.c,4);
	
	val.i=htonl(var->sec);
	memcpy(outdata+4,val.c,4);
	
	val.i=htonl(var->usec);
	memcpy(outdata+8,val.c,4);
	
	val.i=htonl((long)namelen);
	memcpy(outdata+12,val.c,4);
	
	memcpy(outdata+16,var->name,namelen);
	
	offset=namelen+16;
	
	sprintf(outdata+offset,"%f",var->doubledata);
	length-=30;
	length+=strlen(outdata+offset);
      }
      break;
    default:
      return 0;
      break;
    }

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_VARIABLE,outdata,length);

  server->reliablemode=reliable;
  
  free(outdata);

  return returnval;
}

int s2c_description_change(internal_server_data *server,
			   grapple_connection *user,const void *data,size_t len)
      
{
  int reliable;
  int returnval;

  reliable=server->reliablemode;

  server->reliablemode=1;

  returnval=s2c_send(server,user,GRAPPLE_MESSAGE_GAME_DESCRIPTION,data,len);

  server->reliablemode=reliable;
  
  return returnval;
}
