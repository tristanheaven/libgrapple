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
#include <stdio.h>
#include <string.h>

#include "grapple_structs.h"
#include "grapple_message.h"
#include "grapple_message_internal.h"
#include "grapple_defines.h"

//Obtain a new message struct
static grapple_message *grapple_message_aquire(void)
{
  return (grapple_message *)calloc(1,sizeof(grapple_message));
}

//Delete a message struct
void grapple_message_dispose(grapple_message *message)
{
  //Delete associated memory based on the type of message
  switch (message->type)
    {
    case GRAPPLE_MSG_USER_NAME:
      if (message->USER_NAME.name)
	free(message->USER_NAME.name);
      break;
    case GRAPPLE_MSG_SESSION_NAME:
      if (message->SESSION_NAME.name)
	free(message->SESSION_NAME.name);
      break;
    case GRAPPLE_MSG_USER_MSG:
      if (message->USER_MSG.data)
	free(message->USER_MSG.data);
      break;
    case GRAPPLE_MSG_GROUP_CREATE:
    case GRAPPLE_MSG_GROUP_DELETE:
      if (message->GROUP.name)
	free(message->GROUP.name);
      if (message->GROUP.password)
	free(message->GROUP.password);
      break;
    case GRAPPLE_MSG_CONFIRM_TIMEOUT:
      if (message->CONFIRM.timeouts)
	free(message->CONFIRM.timeouts);
      break;
    case GRAPPLE_MSG_NEW_USER_ME:
    case GRAPPLE_MSG_NEW_USER:
      if (message->NEW_USER.name)
	free(message->NEW_USER.name);
      break;
    case GRAPPLE_MSG_GAME_DESCRIPTION:
      if (message->GAME_DESCRIPTION.description)
	free(message->GAME_DESCRIPTION.description);
      break;
    case GRAPPLE_MSG_USER_DISCONNECTED:
    case GRAPPLE_MSG_SERVER_DISCONNECTED:
    case GRAPPLE_MSG_CONNECTION_REFUSED:
    case GRAPPLE_MSG_PING:
    case GRAPPLE_MSG_GROUP_ADD:
    case GRAPPLE_MSG_GROUP_REMOVE:
    case GRAPPLE_MSG_YOU_ARE_HOST:
    case GRAPPLE_MSG_CONFIRM_RECEIVED:
      //No allocations here
      break;
    case GRAPPLE_MSG_NONE:
      //Never received, default NULL value
      break;
    }

  //Delete the message itself
  free(message);

  return;
}

/*
  From here on in, most of the functions are just converting one message
  type to another. There is little point in commenting the obvious, so
  each function will just note what is being converted to what

  GRAPPLE_MESSAGE_* is an internal grapple message
  GRAPPLE_MSG_* is a message to the outside, and is attached to a 
         grapple_message struct
*/

//Convert GRAPPLE_MESSAGE_USER_CONNECTED to GRAPPLE_MSG_NEW_USER
static grapple_message *server_convert_user_connected_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_NEW_USER;

  memcpy(val.c,queue->data,4);
  message->NEW_USER.id=val.i;

  if (queue->length>4)
    {
      message->NEW_USER.name=(char *)malloc(queue->length-3);
      memcpy(message->NEW_USER.name,(char *)queue->data+4,queue->length-4);
      message->NEW_USER.name[queue->length-4]=0;
    }

  return message;
}

//Converting GRAPPLE_MESSAGE_USER_DISCONNECTED to GRAPPLE_MSG_USER_DISCONNECTED
static grapple_message *generic_convert_user_disconnected_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_USER_DISCONNECTED;

  memcpy(val.c,queue->data,4);
  message->USER_DISCONNECTED.id=val.i;

  return message;
}

//GRAPPLE_MESSAGE_USER_NAME to GRAPPLE_MSG_USER_NAME
static grapple_message *server_convert_user_name_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_USER_NAME;

  message->USER_NAME.id=queue->from;

  message->USER_NAME.name=(char *)malloc(queue->length+1);
  memcpy(message->USER_NAME.name,queue->data,queue->length);
  message->USER_NAME.name[queue->length]=0;

  return message;
}

//GRAPPLE_MESSAGE_USER_MESSAGE to GRAPPLE_MSG_USER_MSG
static grapple_message *server_convert_user_message_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_USER_MSG;

  message->USER_NAME.id=queue->from;

  message->USER_MSG.data=(char *)malloc(queue->length+1);
  memcpy(message->USER_MSG.data,queue->data,queue->length);
  *((char *)message->USER_MSG.data+queue->length)=0;
  message->USER_MSG.length=queue->length;

  return message;
}

//GRAPPLE_MESSAGE_PING_REPLY to GRAPPLE_MSG_PING
static grapple_message *server_convert_ping_reply_message(grapple_queue *queue)
{
  doublechar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_PING;

  message->PING.id=queue->from;

  memcpy(val.c,queue->data,8);

  message->PING.pingtime=val.d;

  return message;
}

//GRAPPLE_MESSAGE_GROUP_CREATE to GRAPPLE_MSG_GROUP_CREATE
static grapple_message *generic_convert_group_create_message(grapple_queue *queue)
{
  intchar val;
  int length,offset;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_GROUP_CREATE;

  memcpy(val.c,queue->data,4);
  message->GROUP.groupid=val.i;

  memcpy(val.c,(char *)queue->data+4,4);
  length=val.i;

  message->GROUP.name=(char *)malloc(length+1);
  memcpy(message->GROUP.name,(char *)queue->data+8,length);
  message->GROUP.name[length]=0;

  offset=length+8;

  memcpy(val.c,(char *)queue->data+offset,4);
  length=val.i;

  offset+=4;

  if (length>0)
    {
      message->GROUP.password=(char *)malloc(length+1);
      memcpy(message->GROUP.password,(char *)queue->data+offset,length);
      message->GROUP.password[length]=0;
    }

  return message;
}

//GRAPPLE_MESSAGE_GROUP_ADD to GRAPPLE_MSG_GROUP_ADD
static grapple_message *generic_convert_group_add_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_GROUP_ADD;

  memcpy(val.c,queue->data,4);

  message->GROUP.groupid=val.i;

  memcpy(val.c,(char *)queue->data+4,4);

  message->GROUP.memberid=val.i;

  return message;
}

//GRAPPLE_MESSAGE_GROUP_REMOVE to GRAPPLE_MSG_GROUP_REMOVE
static grapple_message *generic_convert_group_remove_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_GROUP_REMOVE;

  memcpy(val.c,queue->data,4);

  message->GROUP.groupid=val.i;

  memcpy(val.c,(char *)queue->data+4,4);

  message->GROUP.memberid=val.i;

  return message;
}

//GRAPPLE_MESSAGE_GROUP_DELETE to GRAPPLE_MSG_GROUP_DELETE
static grapple_message *generic_convert_group_delete_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_GROUP_DELETE;

  memcpy(val.c,queue->data,4);

  message->GROUP.groupid=val.i;

  message->GROUP.name=(char *)malloc(queue->length);
  memcpy(message->GROUP.name,(char *)queue->data+4,queue->length-4);
  message->GROUP.name[queue->length-4]=0;

  return message;
}

//GRAPPLE_MESSAGE_CONFIRM_RECEIVED to GRAPPLE_MSG_CONFIRM_RECEIVED
static grapple_message *generic_convert_confirm_received_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONFIRM_RECEIVED;

  memcpy(val.c,queue->data,4);

  message->CONFIRM.messageid=val.i;

  return message;
}

//GRAPPLE_MESSAGE_CONFIRM_TIMEOUT to GRAPPLE_MSG_CONFIRM_TIMEOUT
static grapple_message *generic_convert_confirm_timeout_message(grapple_queue *queue)
{
  intchar val;
  int loopa;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONFIRM_TIMEOUT;

  memcpy(val.c,queue->data,4);
  message->CONFIRM.messageid=val.i;

  memcpy(val.c,(char *)queue->data+4,4);
  message->CONFIRM.usercount=val.i;

  message->CONFIRM.timeouts=
    (int *)malloc(message->CONFIRM.usercount*sizeof(int));

  for (loopa=0;loopa<message->CONFIRM.usercount;loopa++)
    {
      memcpy(val.c,(char *)queue->data+8+(loopa*4),4);
      message->CONFIRM.timeouts[loopa]=val.i;
    }

  return message;
}

//GRAPPLE_MESSAGE_GAME_DESCRIPTION to GRAPPLE_MSG_GAME_DESCRIPTION
static grapple_message *generic_convert_game_description_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_GAME_DESCRIPTION;

  message->GAME_DESCRIPTION.length=queue->length;
  
  if (queue->length)
    {
      message->GAME_DESCRIPTION.description=(void *)malloc(queue->length);
      memcpy(message->GAME_DESCRIPTION.description,
	     queue->data,queue->length);
    }
  else
    message->GAME_DESCRIPTION.description=NULL;

  return message;
}

//Convert a message for the server, pass off to a subfunction
grapple_message *server_convert_message_for_user(grapple_queue *queue)
{
  switch (queue->messagetype)
    {
    case GRAPPLE_MESSAGE_USER_CONNECTED:
      return server_convert_user_connected_message(queue);
      break;
    case GRAPPLE_MESSAGE_USER_NAME:
      return server_convert_user_name_message(queue);
      break;
    case GRAPPLE_MESSAGE_USER_MESSAGE:
      return server_convert_user_message_message(queue);
      break;
    case GRAPPLE_MESSAGE_USER_DISCONNECTED:
      return generic_convert_user_disconnected_message(queue);
      break;
    case GRAPPLE_MESSAGE_PING_REPLY:
      return server_convert_ping_reply_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_CREATE:
      return generic_convert_group_create_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_ADD:
      return generic_convert_group_add_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_REMOVE:
      return generic_convert_group_remove_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_DELETE:
      return generic_convert_group_delete_message(queue);
      break;
    case GRAPPLE_MESSAGE_CONFIRM_RECEIVED:
      return generic_convert_confirm_received_message(queue);
      break;
    case GRAPPLE_MESSAGE_CONFIRM_TIMEOUT:
      return generic_convert_confirm_timeout_message(queue);
      break;
    case GRAPPLE_MESSAGE_GRAPPLE_VERSION:
    case GRAPPLE_MESSAGE_PRODUCT_NAME:
    case GRAPPLE_MESSAGE_PRODUCT_VERSION:
    case GRAPPLE_MESSAGE_USER_YOU_CONNECTED:
    case GRAPPLE_MESSAGE_SERVER_DISCONNECTED:
    case GRAPPLE_MESSAGE_HANDSHAKE_FAILED:
    case GRAPPLE_MESSAGE_SESSION_NAME:
    case GRAPPLE_MESSAGE_RELAY_TO:
    case GRAPPLE_MESSAGE_RELAY_ALL:
    case GRAPPLE_MESSAGE_RELAY_ALL_BUT_SELF:
    case GRAPPLE_MESSAGE_SERVER_CLOSED:
    case GRAPPLE_MESSAGE_SERVER_FULL:
    case GRAPPLE_MESSAGE_PASSWORD:
    case GRAPPLE_MESSAGE_PASSWORD_FAILED:
    case GRAPPLE_MESSAGE_NAME_NOT_UNIQUE:
    case GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE:
    case GRAPPLE_MESSAGE_PING:
    case GRAPPLE_MESSAGE_PING_DATA:
    case GRAPPLE_MESSAGE_FAILOVER_OFF:
    case GRAPPLE_MESSAGE_FAILOVER_ON:
    case GRAPPLE_MESSAGE_FAILOVER_CANT:
    case GRAPPLE_MESSAGE_FAILOVER_TRYME:
    case GRAPPLE_MESSAGE_FAILOVER_CAN:
    case GRAPPLE_MESSAGE_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_REQUEST_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_YOU_ARE_HOST:
    case GRAPPLE_MESSAGE_RECONNECTION:
    case GRAPPLE_MESSAGE_NOTIFY_STATE:
    case GRAPPLE_MESSAGE_VARIABLE:
    case GRAPPLE_MESSAGE_GAME_DESCRIPTION:
    case GRAPPLE_MESSAGE_PROTECTIONKEY:
      //Never passed on to server
      break;
    }


  return NULL;
}

//GRAPPLE_MESSAGE_USER_YOU_CONNECTED to GRAPPLE_MSG_NEW_USER_ME
//and
//GRAPPLE_MESSAGE_USER_CONNECTED to GRAPPLE_MSG_NEW_USER
static grapple_message *client_convert_user_connected_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  if (queue->messagetype==GRAPPLE_MESSAGE_USER_YOU_CONNECTED)
    {
      message->type=GRAPPLE_MSG_NEW_USER_ME;
      message->NEW_USER.me=1;
    }
  else
    message->type=GRAPPLE_MSG_NEW_USER;

  memcpy(val.c,queue->data,4);
  message->NEW_USER.id=val.i;

  if (queue->length>4)
    {
      message->NEW_USER.name=(char *)malloc(queue->length-3);
      memcpy(message->NEW_USER.name,(char *)queue->data+4,queue->length-4);
      message->NEW_USER.name[queue->length-4]=0;
    }
  
  return message;
}

//GRAPPLE_MESSAGE_USER_NAME to GRAPPLE_MSG_USER_NAME
static grapple_message *client_convert_user_name_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();
  intchar val;

  message->type=GRAPPLE_MSG_USER_NAME;

  memcpy(val.c,queue->data,4);

  message->USER_NAME.id=val.i;

  message->USER_NAME.name=(char *)malloc(queue->length-3);
  memcpy(message->USER_NAME.name,(char *)queue->data+4,queue->length-4);
  message->USER_NAME.name[queue->length-4]=0;

  return message;
}

//GRAPPLE_MESSAGE_SESSION_NAME to GRAPPLE_MSG_SESSION_NAME
static grapple_message *client_convert_session_name_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_SESSION_NAME;

  message->SESSION_NAME.name=(char *)malloc(queue->length+1);
  memcpy(message->SESSION_NAME.name,queue->data,queue->length);
  message->SESSION_NAME.name[queue->length]=0;

  return message;
}

//GRAPPLE_MESSAGE_USER_MESSAGE to GRAPPLE_MSG_USER_MSG
static grapple_message *client_convert_user_message_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_USER_MSG;

  message->USER_MSG.id=GRAPPLE_SERVER;

  message->USER_MSG.data=(char *)malloc(queue->length+1);
  memcpy(message->USER_MSG.data,queue->data,queue->length);
  *((char *)message->USER_MSG.data+queue->length)=0;
  message->USER_MSG.length=queue->length;

  return message;
}

//GRAPPLE_MESSAGE_RELAY_MESSAGE to GRAPPLE_MSG_USER_MSG
static grapple_message *client_convert_relay_to_message(grapple_queue *queue)
{
  intchar val;

  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_USER_MSG;

  memcpy(val.c,queue->data,4);
  message->USER_MSG.id=val.i;

  message->USER_MSG.data=(char *)malloc(queue->length-4);
  memcpy(message->USER_MSG.data,(char *)queue->data+4,queue->length-4);
  message->USER_MSG.length=queue->length-4;

  return message;
}

//GRAPPLE_MESSAGE_CONNECTION_REFUSED to GRAPPLE_MSG_CONNECTION_REFUSED
static grapple_message *client_convert_handshake_failed_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONNECTION_REFUSED;

  message->CONNECTION_REFUSED.reason=GRAPPLE_NOCONN_VERSION_MISMATCH;

  return message;
}

//GRAPPLE_MESSAGE_PASSWORD_FAILED to GRAPPLE_MSG_CONNECTION_REFUSED
static grapple_message *client_convert_password_failed_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONNECTION_REFUSED;

  message->CONNECTION_REFUSED.reason=GRAPPLE_NOCONN_PASSWORD_MISMATCH;

  return message;
}

//GRAPPLE_MESSAGE_NAME_NOT_UNIQUE to GRAPPLE_MSG_CONNECTION_REFUSED
static grapple_message *client_convert_name_not_unique_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONNECTION_REFUSED;

  message->CONNECTION_REFUSED.reason=GRAPPLE_NOCONN_NAME_NOT_UNIQUE;

  return message;
}

//GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE to GRAPPLE_MSG_CONNECTION_REFUSED
static grapple_message *client_convert_protectionkey_not_unique_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONNECTION_REFUSED;

  message->CONNECTION_REFUSED.reason=GRAPPLE_NOCONN_PROTECTIONKEY_NOT_UNIQUE;

  return message;
}

//GRAPPLE_MESSAGE_SERVER_CLOSED to GRAPPLE_MESSAGE_CONNECTION_REFUSED
static grapple_message *client_convert_server_closed_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONNECTION_REFUSED;

  message->CONNECTION_REFUSED.reason=GRAPPLE_NOCONN_SERVER_CLOSED;

  return message;
}

//GRAPPLE_MESSAGE_SERVER_FULL to GRAPPLE_MESSAGE_CONNECTION_REFUSED
static grapple_message *client_convert_server_full_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_CONNECTION_REFUSED;

  message->CONNECTION_REFUSED.reason=GRAPPLE_NOCONN_SERVER_FULL;

  return message;
}

//GRAPPLE_MESSAGE_SERVER_DISCONNECTED to GRAPPLE_MSG_SERVER_DISCONNECTED
static grapple_message *client_convert_server_disconnected_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_SERVER_DISCONNECTED;

  return message;
}

//GRAPPLE_MESSAGE_PING_DATA to GRAPPLE_MSG_PING
static grapple_message *client_convert_ping_data_message(grapple_queue *queue)
{
  doublechar dval;
  intchar val;


  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_PING;

  memcpy(val.c,queue->data,4);
  memcpy(dval.c,(char *)queue->data+4,8);

  message->PING.pingtime=dval.d;
  message->PING.id=val.i;

  return message;
}

//GRAPPLE_MESSAGE_YOU_ARE_HOST to GRAPPLE_MSG_YOU_ARE_HOST
static grapple_message *client_convert_you_are_host_message(grapple_queue *queue)
{
  grapple_message *message=grapple_message_aquire();

  message->type=GRAPPLE_MSG_YOU_ARE_HOST;

  return message;
}

//Convert any message for the client, passing it off to a subfunction
grapple_message *client_convert_message_for_user(grapple_queue *queue)
{
  switch (queue->messagetype)
    {
    case GRAPPLE_MESSAGE_USER_CONNECTED:
    case GRAPPLE_MESSAGE_USER_YOU_CONNECTED:
      return client_convert_user_connected_message(queue);
      break;
    case GRAPPLE_MESSAGE_USER_NAME:
      return client_convert_user_name_message(queue);
      break;
    case GRAPPLE_MESSAGE_SESSION_NAME:
      return client_convert_session_name_message(queue);
      break;
    case GRAPPLE_MESSAGE_USER_MESSAGE:
      return client_convert_user_message_message(queue);
      break;
    case GRAPPLE_MESSAGE_USER_DISCONNECTED:
      return generic_convert_user_disconnected_message(queue);
      break;
    case GRAPPLE_MESSAGE_SERVER_DISCONNECTED:
      return client_convert_server_disconnected_message(queue);
      break;
    case GRAPPLE_MESSAGE_HANDSHAKE_FAILED:
      return client_convert_handshake_failed_message(queue);
      break;
    case GRAPPLE_MESSAGE_PASSWORD_FAILED:
      return client_convert_password_failed_message(queue);
      break;
    case GRAPPLE_MESSAGE_NAME_NOT_UNIQUE:
      return client_convert_name_not_unique_message(queue);
      break;
    case GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE:
      return client_convert_protectionkey_not_unique_message(queue);
      break;
    case GRAPPLE_MESSAGE_SERVER_FULL:
      return client_convert_server_full_message(queue);
      break;
    case GRAPPLE_MESSAGE_SERVER_CLOSED:
      return client_convert_server_closed_message(queue);
      break;
    case GRAPPLE_MESSAGE_RELAY_TO:
      return client_convert_relay_to_message(queue);
      break;
    case GRAPPLE_MESSAGE_PING_DATA:
      return client_convert_ping_data_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_CREATE:
      return generic_convert_group_create_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_ADD:
      return generic_convert_group_add_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_REMOVE:
      return generic_convert_group_remove_message(queue);
      break;
    case GRAPPLE_MESSAGE_GROUP_DELETE:
      return generic_convert_group_delete_message(queue);
      break;
    case GRAPPLE_MESSAGE_YOU_ARE_HOST:
      return client_convert_you_are_host_message(queue);
      break;
    case GRAPPLE_MESSAGE_CONFIRM_RECEIVED:
      return generic_convert_confirm_received_message(queue);
      break;
    case GRAPPLE_MESSAGE_CONFIRM_TIMEOUT:
      return generic_convert_confirm_timeout_message(queue);
      break;
    case GRAPPLE_MESSAGE_GAME_DESCRIPTION:
      return generic_convert_game_description_message(queue);
      break;
    case GRAPPLE_MESSAGE_GRAPPLE_VERSION:
    case GRAPPLE_MESSAGE_PRODUCT_NAME:
    case GRAPPLE_MESSAGE_PRODUCT_VERSION:
    case GRAPPLE_MESSAGE_RELAY_ALL:
    case GRAPPLE_MESSAGE_RELAY_ALL_BUT_SELF:
    case GRAPPLE_MESSAGE_PASSWORD:
    case GRAPPLE_MESSAGE_PING:
    case GRAPPLE_MESSAGE_PING_REPLY:
    case GRAPPLE_MESSAGE_FAILOVER_OFF:
    case GRAPPLE_MESSAGE_FAILOVER_ON:
    case GRAPPLE_MESSAGE_FAILOVER_CANT:
    case GRAPPLE_MESSAGE_FAILOVER_TRYME:
    case GRAPPLE_MESSAGE_FAILOVER_CAN:
    case GRAPPLE_MESSAGE_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_REQUEST_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_RECONNECTION:
    case GRAPPLE_MESSAGE_NOTIFY_STATE:
    case GRAPPLE_MESSAGE_VARIABLE:
    case GRAPPLE_MESSAGE_PROTECTIONKEY:
      //Never passed on to client
      break;
    }


  return NULL;
}

//Function to show which GRAPPLE_MESSAGES get passed to which
//GRAPPLE_MSG value
grapple_messagetype grapple_message_convert_to_usermessage_enum(grapple_messagetype_internal int_messagetype)
{
  switch (int_messagetype)
    {
    case GRAPPLE_MESSAGE_USER_CONNECTED:
      return GRAPPLE_MSG_NEW_USER;
      break;
    case GRAPPLE_MESSAGE_USER_YOU_CONNECTED:
      return GRAPPLE_MSG_NEW_USER_ME;
      break;
    case GRAPPLE_MESSAGE_USER_NAME:
      return GRAPPLE_MSG_USER_NAME;
      break;
    case GRAPPLE_MESSAGE_SESSION_NAME:
      return GRAPPLE_MSG_SESSION_NAME;
      break;
    case GRAPPLE_MESSAGE_USER_MESSAGE:
      return GRAPPLE_MSG_USER_MSG;
      break;
    case GRAPPLE_MESSAGE_USER_DISCONNECTED:
      return GRAPPLE_MSG_USER_DISCONNECTED;
      break;
    case GRAPPLE_MESSAGE_SERVER_DISCONNECTED:
      return GRAPPLE_MSG_SERVER_DISCONNECTED;
      break;
    case GRAPPLE_MESSAGE_PASSWORD_FAILED:
    case GRAPPLE_MESSAGE_NAME_NOT_UNIQUE:
    case GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE:
    case GRAPPLE_MESSAGE_HANDSHAKE_FAILED:
    case GRAPPLE_MESSAGE_SERVER_CLOSED:
    case GRAPPLE_MESSAGE_SERVER_FULL:
      return GRAPPLE_MSG_CONNECTION_REFUSED;
      break;
    case GRAPPLE_MESSAGE_RELAY_TO:
      return GRAPPLE_MSG_USER_MSG;
      break;
    case GRAPPLE_MESSAGE_PING_REPLY:
      return GRAPPLE_MSG_PING;
      break;
    case GRAPPLE_MESSAGE_GROUP_CREATE:
      return GRAPPLE_MSG_GROUP_CREATE;
      break;
    case GRAPPLE_MESSAGE_GROUP_ADD:
      return GRAPPLE_MSG_GROUP_ADD;
      break;
    case GRAPPLE_MESSAGE_GROUP_REMOVE:
      return GRAPPLE_MSG_GROUP_REMOVE;
      break;
    case GRAPPLE_MESSAGE_GROUP_DELETE:
      return GRAPPLE_MSG_GROUP_DELETE;
      break;
    case GRAPPLE_MESSAGE_YOU_ARE_HOST:
      return GRAPPLE_MSG_YOU_ARE_HOST;
      break;
    case GRAPPLE_MESSAGE_CONFIRM_RECEIVED:
      return GRAPPLE_MSG_CONFIRM_RECEIVED;
      break;
    case GRAPPLE_MESSAGE_CONFIRM_TIMEOUT:
      return GRAPPLE_MSG_CONFIRM_TIMEOUT;
      break;
    case GRAPPLE_MESSAGE_GAME_DESCRIPTION:
      return GRAPPLE_MSG_GAME_DESCRIPTION;
      break;
    case GRAPPLE_MESSAGE_GRAPPLE_VERSION:
    case GRAPPLE_MESSAGE_PRODUCT_NAME:
    case GRAPPLE_MESSAGE_PRODUCT_VERSION:
    case GRAPPLE_MESSAGE_RELAY_ALL:
    case GRAPPLE_MESSAGE_RELAY_ALL_BUT_SELF:
    case GRAPPLE_MESSAGE_PASSWORD:
    case GRAPPLE_MESSAGE_PING:
    case GRAPPLE_MESSAGE_PING_DATA:
    case GRAPPLE_MESSAGE_FAILOVER_OFF:
    case GRAPPLE_MESSAGE_FAILOVER_ON:
    case GRAPPLE_MESSAGE_FAILOVER_CANT:
    case GRAPPLE_MESSAGE_FAILOVER_TRYME:
    case GRAPPLE_MESSAGE_FAILOVER_CAN:
    case GRAPPLE_MESSAGE_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_REQUEST_NEXT_GROUPID:
    case GRAPPLE_MESSAGE_RECONNECTION:
    case GRAPPLE_MESSAGE_NOTIFY_STATE:
    case GRAPPLE_MESSAGE_VARIABLE:
    case GRAPPLE_MESSAGE_PROTECTIONKEY:
      return GRAPPLE_MSG_NONE;
      break;
    }

  return GRAPPLE_MSG_NONE;
}
