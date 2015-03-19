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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "grapple_comms.h"
#include "grapple_queue.h"
#include "grapple_callback_internal.h"

//Put the headers onto the data
static void *data_assemble(grapple_messagetype_internal message,
			   const void *data,size_t datalen)
{
  intchar num;
  void *returnval;
  
  //We know the header is 8 bytes, so allocate an extra 8

  //4 bytes : message protocol
  //4 bytes : length of data
  //        : DATA

  returnval=(void *)malloc(datalen+8);

  num.i=htonl((int)message);
  memcpy(returnval,num.c,4);

  num.i=htonl((long)datalen);
  memcpy((char *)returnval+4,num.c,4);

  memcpy((char *)returnval+8,data,datalen);

  return returnval;
}

//Get the length that the data will be with the headers
static size_t data_get_length(grapple_messagetype_internal message,
			      const void *data,size_t datalen)
{
  //Yes its just +8 but this could change if the protocol changes so
  //lets do it this way
  return datalen+8;
}


//Send a message from the client to the server. This is done by giving the
//server a queue object containing the data, the server then adds these to the
//socket
int c2s_send(internal_client_data *client,
	     grapple_messagetype_internal message,
	     const void *data,size_t datalen)
{
  grapple_queue *newitem;

  //Get the queue item
  newitem=queue_struct_aquire();

  //Put the data into the queue item
  newitem->data=data_assemble(message,
			      data,datalen);
  newitem->length=data_get_length(message,data,datalen);;

  //Set reliable mode if required
  if (client->protocol==GRAPPLE_PROTOCOL_UDP)
    newitem->reliablemode=client->reliablemode;

  grapple_thread_mutex_lock(client->message_out_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //add this to the queue
  client->message_out_queue=
    queue_link(client->message_out_queue,newitem);
  grapple_thread_mutex_unlock(client->message_out_mutex);

  grapple_thread_mutex_lock(client->internal_mutex,GRAPPLE_LOCKTYPE_SHARED);
  if (client->wakesock)
    socket_interrupt(client->wakesock);
  grapple_thread_mutex_unlock(client->internal_mutex);
  
  return 1;
}

//This cheats a little and uses the string sender with the int as the 4 byte
//data
int c2s_send_int(internal_client_data *client,
		 grapple_messagetype_internal message,
		 int val)
{
  intchar data;

  data.i=htonl(val);

  return c2s_send(client,message,data.c,4);
}

//Send a message to the clients user queue from the client. This is an
//internal message from one thread to another
int c2CUQ_send(internal_client_data *client,
	       grapple_messagetype_internal message,
	       const void *data,size_t datalen)
{
  grapple_queue *newitem;

  //Allocate the memory for the message
  newitem=queue_struct_aquire();

  //Set the values into the message
  newitem->messagetype=message;
  newitem->data=(void *)malloc(datalen);
  memcpy(newitem->data,data,datalen);
  newitem->length=datalen;

  //Now see if we have an appropriate callback
  if (grapple_client_callback_generate(client,newitem))
    {
      //We ran a callback, we're done, no need to add it to a queue
      queue_struct_dispose(newitem);
      return 1;
    }

  grapple_thread_mutex_lock(client->message_in_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  //Add to the queue
  client->message_in_queue=
    queue_link(client->message_in_queue,newitem);
  grapple_thread_mutex_unlock(client->message_in_mutex);

  return 1;
}

//Sending a double over the internal system is fine, no endianness to
//worry about. Just send the bytes
int c2CUQ_send_double(internal_client_data *client,
		      grapple_messagetype_internal message,
		      double val)
{
  doublechar data;

  data.d=val;

  return c2CUQ_send(client,message,data.c,8);
}

//Sending an int over the internal system is fine, no endianness to
//worry about. Just send the bytes
int c2CUQ_send_int(internal_client_data *client,
		   grapple_messagetype_internal message,
		   int val)
{
  intchar data;

  data.i=val;

  return c2CUQ_send(client,message,data.c,4);
}

//Send a message from the server to the client
int s2c_send(internal_server_data *server,
	     grapple_connection *target,
	     grapple_messagetype_internal message,
	     const void *data,size_t datalen)
{
  grapple_queue *newitem;

  //Refuse to send to anyone on the way out
  if (target->deleted)
    {
      return 0;
    }

  newitem=queue_struct_aquire();

  //Set the data into the struct
  newitem->data=data_assemble(message,
			      data,datalen);
  newitem->length=data_get_length(message,data,datalen);;

  //Send reliable if required
  if (target->protocol==GRAPPLE_PROTOCOL_UDP)
    newitem->reliablemode=target->reliablemode;

  grapple_thread_mutex_lock(target->message_out_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  //Add this to the queue to send. We DONT send here as we arent guarenteed
  //to be in the correct thread
  target->message_out_queue=
    queue_link(target->message_out_queue,newitem);

  grapple_thread_mutex_unlock(target->message_out_mutex);

  grapple_thread_mutex_lock(server->internal_mutex,GRAPPLE_LOCKTYPE_SHARED);
  if (server->wakesock)
    socket_interrupt(server->wakesock);
  grapple_thread_mutex_unlock(server->internal_mutex);
  
  return 1;
}


//Send an integer value - just call the above function
int s2c_send_int(internal_server_data *server,
		 grapple_connection *target,
		 grapple_messagetype_internal message,
		 int val)
{
  intchar data;

  data.i=htonl(val);

  return s2c_send(server,target,message,data.c,4);
}

//Send a double value. Now this needs to be turned into a string to
//ensure the other end understands it, and can atof it Im sure this could
//be done more efficiently if I read up on the endian effects of double
//storage. For now, this works
int s2c_send_double(internal_server_data *server,
		    grapple_connection *target,
		    grapple_messagetype_internal message,
		    double val)
{
  char data[40];

  sprintf(data,"%f",val);

  return s2c_send(server,target,message,data,strlen(data));
}

//Send a message to the servers internal message queue
int s2SUQ_send(internal_server_data *server,
	       int from,
	       grapple_messagetype_internal message,
	       const void *data,size_t datalen)
{
  grapple_queue *newitem;

  newitem=queue_struct_aquire();

  //Fill in the data
  newitem->messagetype=message;
  newitem->data=(void *)malloc(datalen);
  memcpy(newitem->data,data,datalen);
  newitem->length=datalen;

  newitem->from=from;

  //Check for an appropriate callback
  if (grapple_server_callback_generate(server,newitem))
    {
      //We did a callback, we're done.
      queue_struct_dispose(newitem);
      return 1;
    }

  grapple_thread_mutex_lock(server->message_in_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);
  //No callback, add to the message queue
  server->message_in_queue=
    queue_link(server->message_in_queue,newitem);
  grapple_thread_mutex_unlock(server->message_in_mutex);

  return 1;
}


//Send an int to the servers queue
int s2SUQ_send_int(internal_server_data *server,
		   int from,
		   grapple_messagetype_internal message,
		   int val)
{
  intchar data;

  data.i=val;

  //Just use the above function, no need to worry about endianness
  return s2SUQ_send(server,from,message,data.c,4);
}

//Send a double to the servers queue
int s2SUQ_send_double(internal_server_data *server,
		      int from,
		      grapple_messagetype_internal message,
		      double val)
{
  doublechar data;

  data.d=val;

  //Just use the above function, no need to worry about endianness
  return s2SUQ_send(server,from,message,data.c,8);
}
