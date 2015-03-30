#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#include "unittest.h"

#include "../src/grapple.h"
#include "../src/grapple_lobby.h"

static int staticpass=0,staticfail=0,quiet=0;
const char *error=NULL;

static void microsleep(int usec)
{
#ifdef WIN32
  Sleep(usec / 1000);
#else
  fd_set fds;
  struct timeval tv;
  
  tv.tv_sec=0;
  tv.tv_usec=usec;
  
  FD_ZERO(&fds);

  //Select on no file descriptors, which means it will just wait, until that
  //time is up. Thus sleeping for a microsecond exact time.
  select(FD_SETSIZE,&fds,0,0,&tv);
#endif
  return;
}


static grapple_server create_encrypted_server(grapple_protocol protocol,
					      const char *private,
					      const char *public,
					      const char *ca)
{
  grapple_server server;
  static char errormsg[256];
  
  server=grapple_server_init("unittest","1.0");
  grapple_server_port_set(server,4746);
  grapple_server_protocol_set(server,protocol);
  grapple_server_session_set(server,"Grapple unit test");
  grapple_server_sequential_set(server,GRAPPLE_SEQUENTIAL);
  grapple_server_encryption_enable(server,private,
				   private?"abcd":NULL,public,ca);

  if (grapple_server_start(server) == GRAPPLE_OK)
    return server;

  sprintf(errormsg,"Error creating server: %s\n",
	  grapple_error_text(grapple_server_error_get(server)));

  if (!error)
    error=errormsg;

  grapple_server_destroy(server);

  server=0;

  return server;
}

static grapple_server create_server(grapple_protocol protocol)
{
  grapple_server server;
  static char errormsg[256];
  
  server=grapple_server_init("unittest","1.0");
  grapple_server_port_set(server,4746);
  grapple_server_protocol_set(server,protocol);
  grapple_server_session_set(server,"Grapple unit test");
  grapple_server_sequential_set(server,GRAPPLE_SEQUENTIAL);
  if (grapple_server_start(server) == GRAPPLE_OK)
    return server;

  sprintf(errormsg,"Error creating server: %s\n",
	  grapple_error_text(grapple_server_error_get(server)));

  if (!error)
    error=errormsg;

  grapple_server_destroy(server);

  server=0;

  return server;
}

static grapple_client create_encrypted_client(grapple_protocol protocol,
					      int playernum,
					      const char *private,
					      const char *public,
					      const char *ca)
{
  grapple_client client;
  char name[128];
  static char errormsg[256];

  client=grapple_client_init("unittest","1.0");
  grapple_client_address_set(client,NULL);
  grapple_client_port_set(client,4746);
  grapple_client_protocol_set(client,protocol);
  sprintf(name,"Player%d",playernum);
  grapple_client_name_set(client,name);
  grapple_client_sequential_set(client,GRAPPLE_SEQUENTIAL);
  grapple_client_encryption_enable(client,private,
				   private?"abcd":NULL,public,ca);

  if (grapple_client_start(client,0) == GRAPPLE_OK)
    return client;

  sprintf(errormsg,"Error creating client: %s\n",
	  grapple_error_text(grapple_client_error_get(client)));

  if (!error)
    error=errormsg;

  grapple_client_destroy(client);

  client=0;

  return client;
}

static grapple_client create_client(grapple_protocol protocol,int playernum)
{
  grapple_client client;
  char name[128];
  static char errormsg[256];

  client=grapple_client_init("unittest","1.0");
  grapple_client_address_set(client,NULL);
  grapple_client_port_set(client,4746);
  grapple_client_protocol_set(client,protocol);
  sprintf(name,"Player%d",playernum);
  grapple_client_name_set(client,name);
  grapple_client_sequential_set(client,GRAPPLE_SEQUENTIAL);

  if (grapple_client_start(client,0) == GRAPPLE_OK)
    return client;

  sprintf(errormsg,"Error creating client: %s\n",
	  grapple_error_text(grapple_client_error_get(client)));

  if (!error)
    error=errormsg;

  grapple_client_destroy(client);

  client=0;

  return client;
}

static int basicconnect(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;

  server=create_server(protocol);

  if (!server)
    {
      if (!error)
	error="Failed to create server\n";
      return returnval;
    }
  client=create_client(protocol,1);
  if (client)
    {
      returnval=1;
      grapple_client_destroy(client);
      grapple_server_destroy(server);
    }
  else
    {
      grapple_server_destroy(server);
      if (!error)
	error="Failed to create client\n";
    }
  
  return returnval;
}

static int tcp_basicconnect(void)
{
  return basicconnect(GRAPPLE_PROTOCOL_TCP);
}

static int server_messagepull(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_server_message_pull(server);

      if (message)
	{
	  returnval=1;
	  grapple_message_dispose(message);
	}
      else
	microsleep(10000);

    }

  if (!returnval)
    error="No messages received";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_messagepull(void)
{
  return server_messagepull(GRAPPLE_PROTOCOL_TCP);
}

static int client_messagepull(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client);

      if (message)
	{
	  returnval=1;
	  grapple_message_dispose(message);
	}
      else
	microsleep(10000);
    }

  if (!returnval)
    error="No messages received";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_messagepull(void)
{
  return client_messagepull(GRAPPLE_PROTOCOL_TCP);
}

static int basicfailconnect(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  time_t start;
  grapple_message *message;
  int returnval=0;

  server=create_server(protocol);

  client=grapple_client_init("unittestfail","2.0");
  grapple_client_address_set(client,NULL);
  grapple_client_port_set(client,4746);
  grapple_client_protocol_set(client,protocol);
  grapple_client_name_set(client,"Player1");
  grapple_client_start(client,0);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONNECTION_REFUSED &&
	      message->CONNECTION_REFUSED.reason==GRAPPLE_NOCONN_VERSION_MISMATCH)
	    returnval=1;
	  
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="No fail message received";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_basicfailconnect(void)
{
  return basicfailconnect(GRAPPLE_PROTOCOL_TCP);
}

static int server_detectrunning(grapple_protocol protocol)
{
  grapple_server server;
  int returnval=0;

  server=create_server(protocol);

  returnval=grapple_server_running(server);

  grapple_server_destroy(server);

  if (!returnval)
    error="Could not detect running server";

  return returnval;
}

static int tcp_server_detectrunning(void)
{
  return server_detectrunning(GRAPPLE_PROTOCOL_TCP);
}

static int server_restart(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;

  server=create_server(protocol);

  grapple_server_stop(server);

  grapple_server_start(server);

  client=create_client(protocol,1);

  if (client)
    {
      returnval=1;
      grapple_client_destroy(client);
      grapple_server_destroy(server);
    }
  else
    {
      grapple_server_destroy(server);

      returnval=0;
	  
      if (!error)
	{
	  error="Unable to reconnect";
	}
    }
  
  return returnval;
}

static int tcp_server_restart(void)
{
  return server_restart(GRAPPLE_PROTOCOL_TCP);
}

static int client_connected(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);
  
  while (time(NULL)<start +5 && !returnval)
    {
      if (grapple_client_connected(client))
	returnval=1;
      else
	microsleep(10000);
    }

  if (!returnval)
    error="Couldnt detect client connection";

  grapple_server_destroy(server);
  grapple_client_destroy(client);

  return returnval;
}

static int tcp_client_connected(void)
{
  return client_connected(GRAPPLE_PROTOCOL_TCP);
}


static int userenumeration(grapple_user id,const char *name,
			    unsigned long flags,void *context)
{
  int *number;
  
  number=(int *)context;

  (*number)++;

  return 1;
}

static int server_userenumeraion(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  int returnval=0;
  int count;
  time_t start;

  server=create_server(protocol);

  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+10 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client3))
    microsleep(10000);

  //3 clients, now enumerate them

  count=0;

  grapple_server_enumusers(server,userenumeration,
			   (void *)&count);

  if (count==3)
    returnval=1;

  if (count>3)
    {
      error="Too many connections detected";
      returnval=0;
    }
  else if (count < 3)
    {
      error="Not enough connections detected";
      returnval=0;
    }

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_userenumeraion(void)
{
  return server_userenumeraion(GRAPPLE_PROTOCOL_TCP);
}

static int server_maxusers(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);

  grapple_server_maxusers_set(server,2);

  client1=create_client(protocol,1);
  client2=create_client(protocol,2);

  start=time(NULL);

  while (time(NULL) < start+10 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client2))
    microsleep(10000);

  if (!grapple_client_connected(client2) || !grapple_client_connected(client1))
    {
      error="A client couldnt connect";

      returnval=0;
      grapple_client_destroy(client2);
      grapple_client_destroy(client1);
      grapple_server_destroy(server);
  
      return returnval;
    }


  client3=create_client(protocol,3);

  //Now we should expect a connection refused message
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONNECTION_REFUSED &&
	      message->CONNECTION_REFUSED.reason==GRAPPLE_NOCONN_SERVER_FULL)
	    returnval=1;
	  
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 3 managed to connect";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_maxusers(void)
{
  return server_maxusers(GRAPPLE_PROTOCOL_TCP);
}

static int server_closed(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);

  grapple_server_closed_set(server,GRAPPLE_SERVER_CLOSED);

  client=create_client(protocol,1);

  start=time(NULL);

  //Now we should expect a connection refused message

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONNECTION_REFUSED && 
	      message->CONNECTION_REFUSED.reason==GRAPPLE_NOCONN_SERVER_CLOSED)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client was not refused connection";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int server_description(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);

  client=create_client(protocol,1);

  start=time(NULL);

  //Wait for the client to be connected
  while (time(NULL) < start+10 && !grapple_client_connected(client))
    microsleep(10000);

  //Now the server sets the game description
  grapple_server_description_set(server,"test",5);

  //Now we should expect a message about this on the client
  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_GAME_DESCRIPTION)
	    {
	      if (message->GAME_DESCRIPTION.length==5 && 
		  !strcmp(message->GAME_DESCRIPTION.description,"test"))
		returnval=1;
	    }
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Description not correctly set";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_closed(void)
{
  return server_closed(GRAPPLE_PROTOCOL_TCP);
}

static int tcp_server_description(void)
{
  return server_description(GRAPPLE_PROTOCOL_TCP);
}

static int server_usercount(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  int returnval=0;
  int count;
  time_t start;

  server=create_server(protocol);

  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+10 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client3))
    microsleep(10000);

  count=grapple_server_currentusers_get(server);

  if (count==3)
    returnval=1;
  else if (count > 3)
    error="Too many users";
  else
    error="Not enough users";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_usercount(void)
{
  return server_usercount(GRAPPLE_PROTOCOL_TCP);
}

static int server_userlist(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  int returnval=0;
  int loopa;
  grapple_user *userlist;
  time_t start;

  server=create_server(protocol);

  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+10 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client3))
    microsleep(10000);

  userlist=grapple_server_userlist_get(server);

  loopa=0;

  if (userlist)
    {
      while (userlist[loopa])
	loopa++;
      free(userlist);
    }

  if (loopa==3)
    returnval=1;
  else if (loopa>3)
    error="Too many users";
  else
    error="Not enough users";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_userlist(void)
{
  return server_userlist(GRAPPLE_PROTOCOL_TCP);
}

static int server_password(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=grapple_server_init("unittest","1.0");
  grapple_server_port_set(server,4746);
  grapple_server_protocol_set(server,protocol);
  grapple_server_session_set(server,"Grapple unit test");
  grapple_server_password_set(server,"testpass");
  grapple_server_start(server);


  client1=grapple_client_init("unittest","1.0");
  grapple_client_address_set(client1,NULL);
  grapple_client_port_set(client1,4746);
  grapple_client_protocol_set(client1,protocol);
  grapple_client_password_set(client1,"testpass");
  grapple_client_name_set(client1,"Player1");
  grapple_client_start(client1,0);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);

  if (!grapple_client_connected(client1))
    {
      error="Client couldnt connect";

      returnval=0;
      grapple_client_destroy(client1);
      grapple_server_destroy(server);
  
      return returnval;
    }

  client2=create_client(protocol,2);

  //Now we should expect a connection refused message
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONNECTION_REFUSED &&
	      message->CONNECTION_REFUSED.reason==GRAPPLE_NOCONN_PASSWORD_MISMATCH)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client was not refused without a password";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_password(void)
{
  return server_password(GRAPPLE_PROTOCOL_TCP);
}

static int server_messagecount(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      returnval=grapple_server_messagecount_get(server);

      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    error="Couldnt find any messages to count";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_messagecount(void)
{
  return server_messagecount(GRAPPLE_PROTOCOL_TCP);
}

static int server_messagetoone(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_user serverid;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  //Server sends them a message
  serverid=grapple_client_serverid_get(client);

  grapple_server_send(server,serverid,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);

  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }
  
  if (!returnval)
    error="Message not received";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_messagetoone(void)
{
  return server_messagetoone(GRAPPLE_PROTOCOL_TCP);
}

static int server_messagetoall(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  //Server sends them a message
  grapple_server_send(server,GRAPPLE_EVERYONE,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);


  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 didnt receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 didnt receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 3 didnt receive message";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_messagetoall(void)
{
  return server_messagetoall(GRAPPLE_PROTOCOL_TCP);
}

static int message_callback(grapple_message *message,void *context)
{
  int *count;

  count=(int *)context;

  (*count)++;

  grapple_message_dispose(message);

  return 1;
}

static int lobbymessage_callback(grapple_lobbymessage *message,void *context)
{
  int *count;

  count=(int *)context;

  (*count)++;

  grapple_lobbymessage_dispose(message);

  return 1;
}

static int server_callbacks(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;
  time_t start;
  int count;

  server=create_server(protocol);

  //Now create a callback
  count=0;
  grapple_server_callback_setall(server,message_callback,&count);

  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      returnval=count;
      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    error="Messages not reaching callbacks";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_callbacks(void)
{
  return server_callbacks(GRAPPLE_PROTOCOL_TCP);
}

static int server_disconnectclient(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int serverid;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  //The client is connected, now kill it
  serverid=grapple_client_serverid_get(client);

  grapple_server_disconnect_client(server,serverid);

  while (time(NULL) < start+5 && grapple_client_connected(client))
    microsleep(10000);

  if (!grapple_client_connected(client))
    returnval=1;

  if (!returnval)
    error="Client didnt disconnect";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_disconnectclient(void)
{
  return server_disconnectclient(GRAPPLE_PROTOCOL_TCP);
}

static int server_ping(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int serverid;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  serverid=grapple_client_serverid_get(client);

  grapple_server_ping(server,serverid);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_PING && 
	      message->PING.id==serverid)

	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Ping not received";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_ping(void)
{
  return server_ping(GRAPPLE_PROTOCOL_TCP);
}

static int server_autoping(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  int serverid1,serverid2,serverid3;
  int ping1,ping2,ping3;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  ping1=0;
  ping2=0;
  ping3=0;

  grapple_server_autoping(server,0.3);

  start=time(NULL);
  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_PING)
	    {
	      if (message->PING.id==serverid1)
		{
		  if (ping1<3)
		    {
		      start=time(NULL);
		      ping1++;
		    }
		}
	      else if (message->PING.id==serverid2)
		{
		  if (ping2<3)
		    {
		      start=time(NULL);
		      ping2++;
		    }
		}
	      else if (message->PING.id==serverid3)	
		{
		  if (ping3<3)
		    {
		      start=time(NULL);
		      ping3++;
		    }
		}
	    }
	  grapple_message_dispose(message);
	  if (ping1==3 && ping2==3 && ping3==3)
	    returnval=1;
	}
    }

  if (!returnval)
    error="Some pings not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_autoping(void)
{
  return server_autoping(GRAPPLE_PROTOCOL_TCP);
}

static int server_newgroup(grapple_protocol protocol)
{
  grapple_server server;
  int returnval=0;

  server=create_server(protocol);

  returnval=grapple_server_group_create(server,"Test Group",NULL);

  grapple_server_destroy(server);

  if (!returnval)
    error="Group creation failed";

  return returnval;
}

static int tcp_server_newgroup(void)
{
  return server_newgroup(GRAPPLE_PROTOCOL_TCP);
}

static int server_grouplist(grapple_protocol protocol)
{
  grapple_server server;
  int loopa;
  grapple_user *grouplist;
  int returnval=0;

  server=create_server(protocol);

  grapple_server_group_create(server,"Test Group",NULL);
  grapple_server_group_create(server,"Test Group 2",NULL);

  grouplist=grapple_server_grouplist_get(server);

  loopa=0;

  if (grouplist)
    {
      while (grouplist[loopa])
	loopa++;
      free(grouplist);
    }
  
  if (loopa==2)
    returnval=1;
  else if (loopa>2)
    error="Too many groups found";
  else
    error="Not all groups found";

  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_grouplist(void)
{
  return server_grouplist(GRAPPLE_PROTOCOL_TCP);
}

static int server_clientgrouplist(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int loopa=0;
  grapple_user *grouplist;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);
  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  grapple_server_group_create(server,"Test Group",NULL);
  grapple_server_group_create(server,"Test Group 2",NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      grouplist=grapple_client_grouplist_get(client);

      loopa=0;
      
      if (grouplist)
	{
	  while (grouplist[loopa])
	    loopa++;
	  free(grouplist);
	}
  
      if (loopa==2)
	returnval=1;
      else
	microsleep(10000);
    }

  if (loopa>2)
    {
      returnval=0;
      error="Too many groups reported to the client";
    }
  else if (loopa<2)
    {
      returnval=0;
      error="Not enough groups reported to the client";
    }

  grapple_server_destroy(server);
  grapple_client_destroy(client);

  return returnval;
}

static int tcp_server_clientgrouplist(void)
{
  return server_clientgrouplist(GRAPPLE_PROTOCOL_TCP);
}

static int server_addgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client;
  int returnval=0;
  grapple_user group;
  grapple_user serverid;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);

  serverid=grapple_client_serverid_get(client);

  if (grapple_server_group_add(server,group,serverid,NULL)==GRAPPLE_OK)
    returnval=1;
  else
    error="Group creation failed";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_addgroup(void)
{
  return server_addgroup(GRAPPLE_PROTOCOL_TCP);
}

static int server_groupmemberlist(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0,loopa;
  grapple_user group;
  grapple_user *userlist;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_server_group_add(server,group,serverid1,NULL);
  grapple_server_group_add(server,group,serverid2,NULL);
  grapple_server_group_add(server,group,serverid3,NULL);

  userlist=grapple_server_groupusers_get(server,group);
  
  loopa=0;

  if (userlist)
    {
      while (userlist[loopa])
	loopa++;
      free(userlist);
    }

  if (loopa==3)
    returnval=1;
  else if (loopa>3)
    error="Too many members";
  else
    error="Not enough members";
  
  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_groupmemberlist(void)
{
  return server_groupmemberlist(GRAPPLE_PROTOCOL_TCP);
}

static int server_groupmemberlistclient(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0,loopa=0;
  grapple_user group;
  grapple_user *userlist;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_server_group_add(server,group,serverid1,NULL);
  grapple_server_group_add(server,group,serverid2,NULL);
  grapple_server_group_add(server,group,serverid3,NULL);

  start=time(NULL);
  while (time(NULL) < start+5 && !returnval)
    {
      userlist=grapple_client_groupusers_get(client1,group);
  
      loopa=0;

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
  
      if (loopa==3)
	returnval=1;
      else
	microsleep(10000);
    }

  if (loopa<3)
    {
      returnval=0;
      error="Not enough members detected by the client";
    }
  else if (loopa>3)
    {
      returnval=0;
      error="Too many members detected by the client";
    }

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_groupmemberlistclient(void)
{
  return server_groupmemberlistclient(GRAPPLE_PROTOCOL_TCP);
}

static int groupenumeration(grapple_user id,const char *name,
			    unsigned long flags,void *context)
{
  int *number;
  
  number=(int *)context;

  (*number)++;

  return 1;
}

static int server_groupenum(grapple_protocol protocol)
{
  grapple_server server;
  int count;
  int returnval=0;

  server=create_server(protocol);

  grapple_server_group_create(server,"Test Group",NULL);
  grapple_server_group_create(server,"Test Group 2",NULL);

  count=0;

  grapple_server_enumgrouplist(server,groupenumeration,&count);

  if (count==2)
    returnval=1;
  else if (count > 2)
    {
      error="Too many groups enumerated";
    }
  else
    {
      error="Not enough groups enumerated";
    }
  
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_groupenum(void)
{
  return server_groupenum(GRAPPLE_PROTOCOL_TCP);
}

static int server_groupmemberenum(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0,count;
  grapple_user group;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  if (!grapple_client_connected(client1))
    {
      error="Client 1 failed to connect";

      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }
      
  if (!grapple_client_connected(client2))
    {
      error="Client 2 failed to connect";

      grapple_client_destroy(client1);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }
      
  if (!grapple_client_connected(client3))
    {
      error="Client 3 failed to connect";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_server_destroy(server);

      return returnval;
    }
      
  group=grapple_server_group_create(server,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  if (!serverid1 || !serverid2 || !serverid3)
    {
      error="Failed to obtain all server IDs";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }

  if (grapple_server_group_add(server,group,serverid1,NULL)!=GRAPPLE_OK)
    {
      error="Failed to connect client 1 to group";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }
  if (grapple_server_group_add(server,group,serverid2,NULL)!=GRAPPLE_OK)
    {
      error="Failed to connect client 2 to group";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }
  if (grapple_server_group_add(server,group,serverid3,NULL)!=GRAPPLE_OK)
    {
      error="Failed to connect client 3 to group";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      count=0;
      
      grapple_server_enumgroup(server,group,userenumeration,&count);

      if (count==3)
	returnval=1;
      else
	microsleep(10000);
    }

  if (count>3)
    error="Too many group members found";
  else if (count < 3)
    error="Not enough group members found";
  
  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_groupmemberenum(void)
{
  return server_groupmemberenum(GRAPPLE_PROTOCOL_TCP);
}

static int server_sendgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_server_group_add(server,group,serverid1,NULL);
  grapple_server_group_add(server,group,serverid2,NULL);
  grapple_server_group_add(server,group,serverid3,NULL);


  grapple_server_send(server,group,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 1 did not receive the message";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_sendgroup(void)
{
  return server_sendgroup(GRAPPLE_PROTOCOL_TCP);
}

static int server_sendgroupgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group,group2;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);
  group2=grapple_server_group_create(server,"Test Group 2",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_server_group_add(server,group,serverid1,NULL);
  grapple_server_group_add(server,group,serverid2,NULL);
  grapple_server_group_add(server,group,group2,NULL);

  grapple_server_group_add(server,group2,serverid3,NULL);

  grapple_server_send(server,group,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 2 did not receive the message";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_sendgroupgroup(void)
{
  return server_sendgroupgroup(GRAPPLE_PROTOCOL_TCP);
}

static int server_removegroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client;
  int returnval=0;
  grapple_user group;
  grapple_user serverid;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);

  serverid=grapple_client_serverid_get(client);

  grapple_server_group_add(server,group,serverid,NULL);

  if (grapple_server_group_remove(server,group,serverid)==GRAPPLE_OK)
    returnval=1;
  else
    error="Failed to remove the group";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_removegroup(void)
{
  return server_removegroup(GRAPPLE_PROTOCOL_TCP);
}

static int server_deletegroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_user group;
  int returnval=0;

  server=create_server(protocol);

  group=grapple_server_group_create(server,"Test Group",NULL);

  if (grapple_server_group_delete(server,group)==GRAPPLE_OK)
    returnval=1;
  else
    error="Failed to delete group";

  grapple_server_destroy(server);

  return returnval;
}

static int tcp_server_deletegroup(void)
{
  return server_deletegroup(GRAPPLE_PROTOCOL_TCP);
}

static int server_sendconfirmone(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_user serverid;
  grapple_message *message;
  grapple_confirmid messageid;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  //Server sends them a message
  serverid=grapple_client_serverid_get(client);

  messageid=grapple_server_send(server,serverid,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);

  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_client_message_pull(client);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {  
      error="Client did not receive message";

      grapple_client_destroy(client);
      grapple_server_destroy(server);
      
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Server did not receive confirmation";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_sendconfirmone(void)
{
  return server_sendconfirmone(GRAPPLE_PROTOCOL_TCP);
}

static int server_sendconfirmeveryone(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  grapple_message *message;
  int returnval=0;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  //Server sends them a message
  messageid=grapple_server_send(server,GRAPPLE_EVERYONE,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);


  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Server did not receive confirmation";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_sendconfirmeveryone(void)
{
  return server_sendconfirmeveryone(GRAPPLE_PROTOCOL_TCP);
}

static int server_sendconfirmgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_server_group_add(server,group,serverid1,NULL);
  grapple_server_group_add(server,group,serverid2,NULL);
  grapple_server_group_add(server,group,serverid3,NULL);


  messageid=grapple_server_send(server,group,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirmation not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_sendconfirmgroup(void)
{
  return server_sendconfirmgroup(GRAPPLE_PROTOCOL_TCP);
}

static int server_sendconfirmgroupgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group,group2;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_server_group_create(server,"Test Group",NULL);
  group2=grapple_server_group_create(server,"Test Group 2",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_server_group_add(server,group,serverid1,NULL);
  grapple_server_group_add(server,group,serverid2,NULL);
  grapple_server_group_add(server,group2,serverid3,NULL);
  grapple_server_group_add(server,group,group2,NULL);


  messageid=grapple_server_send(server,group,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirmation not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_server_sendconfirmgroupgroup(void)
{
  return server_sendconfirmgroupgroup(GRAPPLE_PROTOCOL_TCP);
}

static int client_restart(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  grapple_client_stop(client);

  start=time(NULL);

  while (time(NULL) < start+5 && grapple_client_connected(client))
    microsleep(10000);

  if (grapple_client_connected(client))
    {
      error="Client failedto stop";

      grapple_client_destroy(client);
      grapple_server_destroy(server);
  
      return returnval;
    }
  
  
  grapple_client_start(client,0);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);


  if (grapple_client_connected(client))
    returnval=1;
  else
    error="Client failed to reconnect";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_restart(void)
{
  return client_restart(GRAPPLE_PROTOCOL_TCP);
}

static int client_enumusers(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  int returnval=0;
  int count=0;
  time_t start;

  server=create_server(protocol);

  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  //3 clients, now enumerate them

  count=0;

  while (time(NULL) < start+5 && returnval==0)
    {
      grapple_client_enumusers(client1,userenumeration,
			       (void *)&count);

      if (count==3)
	returnval=1;
      else
	{
	  microsleep(10000);
	  count=0;
	}
    }

  if (count>3)
    error="Too many users reported";
  else if (count<3)
    error="Not enough users reported";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_enumusers(void)
{
  return client_enumusers(GRAPPLE_PROTOCOL_TCP);
}

static int client_changename(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;
  time_t start;
  grapple_user serverid;
  char *name;

  server=create_server(protocol);

  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  serverid=grapple_client_serverid_get(client);
  //Now change the name

  grapple_client_name_set(client,"NewName");

  start=time(NULL);

  while (time(NULL) < start+5 && returnval==0)
    {
      name=grapple_client_name_get(client,serverid);

      if (name && *name && !strcmp(name,"NewName"))
	returnval=1;
      else
	microsleep(10000);

      if (name && *name)
	free(name);
    }

  if (!returnval)
    error="Could not change name";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_changename(void)
{
  return client_changename(GRAPPLE_PROTOCOL_TCP);
}

static int client_userlist(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  int returnval=0;
  int loopa=0;
  grapple_user *userlist;
  time_t start;

  server=create_server(protocol);

  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+10 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+10 && !grapple_client_connected(client3))
    microsleep(10000);

  start=time(NULL);

  while (time(NULL) < start+5 && returnval==0)
    {
      loopa=0;

      userlist=grapple_client_userlist_get(client1);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa==3)
	returnval=1;
    }

  if (loopa>3)
    error="Too many users found";
  else if (loopa<3)
    {
      error="Not enough users found";
    }

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_userlist(void)
{
  return client_userlist(GRAPPLE_PROTOCOL_TCP);
}

static int client_messagecount(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      returnval=grapple_client_messagecount_get(client);

      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    error="No messages found";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_messagecount(void)
{
  return client_messagecount(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendtoserver(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  grapple_client_send(client,GRAPPLE_SERVER,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);


  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Server did not receive message";
  
  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendtoserver(void)
{
  return client_sendtoserver(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendtoone(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2;
  grapple_message *message;
  grapple_user serverid;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);

  serverid=grapple_client_serverid_get(client2);

  grapple_client_send(client1,serverid,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);

  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Message not received";
  
  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendtoone(void)
{
  return client_sendtoone(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendtoallother(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  grapple_client_send(client1,GRAPPLE_EVERYONEELSE,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 missed message";
      
      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 missed message";
      
      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  start=time(NULL);

  //Here we loop and make sure that the sender DIDNT get the message
  while (time(NULL) < start+5 && returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	break;
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=0;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 1 received message";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendtoallother(void)
{
  return client_sendtoallother(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendtoall(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  grapple_message *message;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  grapple_client_send(client1,GRAPPLE_EVERYONE,GRAPPLE_RELIABLE,
		      (void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 missed message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 missed message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 3 missed message";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendtoall(void)
{
  return client_sendtoall(GRAPPLE_PROTOCOL_TCP);
}

static int client_callbacks(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;
  time_t start;
  int count;

  count=0;

  server=create_server(protocol);
  client=create_client(protocol,1);

  //Now create a callback
  grapple_client_callback_setall(client,message_callback,&count);

  //A simple message we know works, so we know we have a message coming in
  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  grapple_client_name_set(client,"NewName");

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      returnval=count;
      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    error="No message callbacks triggered";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_callbacks(void)
{
  return client_callbacks(GRAPPLE_PROTOCOL_TCP);
}

static int client_ping(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_message *message;
  grapple_user serverid;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  serverid=grapple_client_serverid_get(client);

  grapple_client_ping(client);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_PING && 
	      message->PING.id==serverid)

	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Message not received";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_ping(void)
{
  return client_ping(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupcreate(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;

  server=create_server(protocol);
  client=create_client(protocol,1);

  returnval=grapple_client_group_create(client,"Test Group",NULL);

  if (!returnval)
    error="Group create failed";

  grapple_server_destroy(server);
  grapple_client_destroy(client);

  return returnval;
}

static int tcp_client_groupcreate(void)
{
  return client_groupcreate(GRAPPLE_PROTOCOL_TCP);
}

static int client_grouplist(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int loopa;
  grapple_user *grouplist;
  int returnval=0;

  server=create_server(protocol);
  client=create_client(protocol,1);

  grapple_client_group_create(client,"Test Group",NULL);
  grapple_client_group_create(client,"Test Group 2",NULL);

  grouplist=grapple_client_grouplist_get(client);

  loopa=0;

  if (grouplist)
    {
      while (grouplist[loopa])
	loopa++;
      free(grouplist);
    }

  if (loopa==2)
    returnval=1;
  else if (loopa>2)
    error="Too many groups detected";
  else
    error="Not enough groups detected";

  grapple_client_destroy(client); 
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_grouplist(void)
{
  return client_grouplist(GRAPPLE_PROTOCOL_TCP);
}

static int client_grouplistother(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2;
  int loopa=0;
  grapple_user *grouplist;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);

  grapple_client_group_create(client1,"Test Group",NULL);
  grapple_client_group_create(client1,"Test Group 2",NULL);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);

  start=time(NULL);
  while (time(NULL) < start+5 && !returnval)
    {
      grouplist=grapple_client_grouplist_get(client2);

      loopa=0;

      if (grouplist)
	{
	  while (grouplist[loopa])
	    loopa++;
	  free(grouplist);
	}
      
      if (loopa==2)
	returnval=1;
      else
	microsleep(10000);
    }

  if (loopa<2)
    error="Not enough groups detected";
  else if (loopa>2)
    error="Too many groups detected";
  
  grapple_client_destroy(client1); 
  grapple_client_destroy(client2); 
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_grouplistother(void)
{
  return client_grouplistother(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupadd(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client;
  int returnval=0;
  grapple_user group;
  grapple_user serverid;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  group=grapple_client_group_create(client,"Test Group",NULL);

  serverid=grapple_client_serverid_get(client);

  if (grapple_client_group_add(client,group,serverid,NULL)==GRAPPLE_OK)
    returnval=1;
  else
    error="Cannot add user to group";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_groupadd(void)
{
  return client_groupadd(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupmemberlist(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0,loopa;
  grapple_user group;
  grapple_user *userlist;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_client_group_create(client1,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_client_group_add(client1,group,serverid1,NULL);
  grapple_client_group_add(client1,group,serverid2,NULL);
  grapple_client_group_add(client1,group,serverid3,NULL);

  userlist=grapple_client_groupusers_get(client1,group);
  
  loopa=0;

  if (userlist)
    {
      while (userlist[loopa])
	{
	  loopa++;
	}
      free(userlist);
    }

  if (loopa==3)
    returnval=1;
  else if (loopa>3)
    error="Too many members in the group";
  else
    error="Not enough members in the group";
    
  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_groupmemberlist(void)
{
  return client_groupmemberlist(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupmemberlistother(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0,loopa=0;
  grapple_user group;
  grapple_user *userlist;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_client_group_create(client1,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_client_group_add(client1,group,serverid1,NULL);
  grapple_client_group_add(client1,group,serverid2,NULL);
  grapple_client_group_add(client1,group,serverid3,NULL);


  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      userlist=grapple_client_groupusers_get(client2,group);
  
      loopa=0;

      if (userlist)
	{
	  while (userlist[loopa])
	    {
	      loopa++;
	    }
	  free(userlist);
	}
      
      if (loopa==3)
	returnval=1;
      else
	microsleep(10000);
    }

  if (loopa>3)
    error="Too many members in the group";
  else if (loopa<3)
    error="Not enough members in the group";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_groupmemberlistother(void)
{
  return client_groupmemberlistother(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupenum(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int count;
  int returnval=0;

  server=create_server(protocol);
  client=create_client(protocol,1);

  grapple_client_group_create(client,"Test Group",NULL);
  grapple_client_group_create(client,"Test Group 2",NULL);

  count=0;

  grapple_client_enumgrouplist(client,groupenumeration,&count);

  if (count==2)
    returnval=1;
  else if (count > 2)
    error="Too many groups";
  else
    error="Not enough groups";
  
  grapple_server_destroy(server);
  grapple_client_destroy(client);

  return returnval;
}

static int tcp_client_groupenum(void)
{
  return client_groupenum(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupmemberenum(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0,count;
  grapple_user group;
  grapple_user *userlist;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;
  int loopa=0;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  if (!client1 || !client2 || !client3)
    {
      error="One of the clients failed to start";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }
  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  if (!grapple_client_connected(client1) ||
      !grapple_client_connected(client2) ||
      !grapple_client_connected(client3))
    {
      error="One of the clients failed to connect";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }

  //Now we wait for all users to be visible to client1
  start=time(NULL);

  while (time(NULL) < start+5 && loopa!=3)
    {
      loopa=0;

      userlist=grapple_client_userlist_get(client1);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa!=3)
	microsleep(10000);
    }

  if (loopa!=3)
    {
      if (loopa>3)
	error="Too many users detected";
      else
	error="Too few users detected";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }

  group=grapple_client_group_create(client1,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  if (!serverid1 || !serverid2 || !serverid3)
    {
      error="Failed to obtain a serverid";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }

  if (grapple_client_group_add(client1,group,serverid1,NULL)!=GRAPPLE_OK)
    {
      error="Client 1 failed to join group";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }
  if (grapple_client_group_add(client1,group,serverid2,NULL)!=GRAPPLE_OK)
    {
      error="Client 2 failed to join group";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }
  if (grapple_client_group_add(client1,group,serverid3,NULL)!=GRAPPLE_OK)
    {
      error="Client 3 failed to join group";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);

      return returnval;
    }

  count=0;

  grapple_client_enumgroup(client1,group,userenumeration,&count);

  if (count==3)
    returnval=1;
  else if (count > 3)
    error="Found too many group members";
  else
    error="Found too few group members";
  
  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_groupmemberenum(void)
{
  return client_groupmemberenum(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendtogroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_client_group_create(client1,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_client_group_add(client1,group,serverid1,NULL);
  grapple_client_group_add(client1,group,serverid2,NULL);
  grapple_client_group_add(client1,group,serverid3,NULL);


  grapple_client_send(client1,group,GRAPPLE_RELIABLE,(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 3 did not receive the message";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendtogroup(void)
{
  return client_sendtogroup(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendtogroupgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group,group2;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_client_group_create(client1,"Test Group",NULL);
  group2=grapple_client_group_create(client1,"Test Group 2",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_client_group_add(client1,group,serverid1,NULL);
  grapple_client_group_add(client1,group,serverid2,NULL);
  grapple_client_group_add(client1,group2,serverid3,NULL);
  grapple_client_group_add(client1,group,group2,NULL);

  grapple_client_send(client1,group,GRAPPLE_RELIABLE,(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive the message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Client 3 did not receive the message";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendtogroupgroup(void)
{
  return client_sendtogroupgroup(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupremove(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client;
  int returnval=0;
  grapple_user group;
  grapple_user serverid;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  group=grapple_client_group_create(client,"Test Group",NULL);

  serverid=grapple_client_serverid_get(client);

  grapple_client_group_add(client,group,serverid,NULL);

  if (grapple_client_group_remove(client,group,serverid)==GRAPPLE_OK)
    returnval=1;
  else
    error="Unable to remove user from group";

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_groupremove(void)
{
  return client_groupremove(GRAPPLE_PROTOCOL_TCP);
}

static int client_groupdelete(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  int returnval=0;
  grapple_user group;

  server=create_server(protocol);
  client=create_client(protocol,1);

  group=grapple_client_group_create(client,"Test Group",NULL);

  if (grapple_client_group_delete(client,group)==GRAPPLE_OK)
    returnval=1;
  else
    error="Cannoty delete group";

  grapple_server_destroy(server);
  grapple_client_destroy(client);

  return returnval;
}

static int tcp_client_groupdelete(void)
{
  return client_groupdelete(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendconfirmserver(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client;
  grapple_message *message;
  grapple_confirmid messageid;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client=create_client(protocol,1);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  messageid=grapple_client_send(client,GRAPPLE_SERVER,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);


  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_server_message_pull(server);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }
  
  if (!returnval)
    {
      error="Server did not receive message";

      grapple_client_destroy(client);
      grapple_server_destroy(server);
      
      return returnval;
    }


  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_client_message_pull(client);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirm not received";

  grapple_client_destroy(client);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendconfirmserver(void)
{
  return client_sendconfirmserver(GRAPPLE_PROTOCOL_TCP);
}


static int client_sendconfirmone(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2;
  grapple_message *message;
  grapple_user serverid;
  int returnval=0;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);

  serverid=grapple_client_serverid_get(client2);

  messageid=grapple_client_send(client1,serverid,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);

  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }
  
  if (!returnval)
    {
      error="Client did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_server_destroy(server);
      
      return returnval;
    }


  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirm message not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendconfirmone(void)
{
  return client_sendconfirmone(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendconfirmall(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  grapple_message *message;
  int returnval=0;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  messageid=grapple_client_send(client1,GRAPPLE_EVERYONE,
				GRAPPLE_CONFIRM,(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirm not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendconfirmall(void)
{
  return client_sendconfirmall(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendconfirmallother(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2,client3;
  grapple_message *message;
  int returnval=0;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  messageid=grapple_client_send(client1,GRAPPLE_EVERYONEELSE,
				GRAPPLE_CONFIRM,(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  //Here we loop and make sure that the sender DIDNT get the message
  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else 
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    {
	      grapple_message_dispose(message);
	      break;
	    }
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirm message not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendconfirmallother(void)
{
  return client_sendconfirmallother(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendconfirmgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_client_group_create(client1,"Test Group",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_client_group_add(client1,group,serverid1,NULL);
  grapple_client_group_add(client1,group,serverid2,NULL);
  grapple_client_group_add(client1,group,serverid3,NULL);


  messageid=grapple_client_send(client1,group,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  //Here we loop and make sure that the sender DIDNT get the message
  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else 
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirm nessage not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendconfirmgroup(void)
{
  return client_sendconfirmgroup(GRAPPLE_PROTOCOL_TCP);
}

static int client_sendconfirmgroupgroup(grapple_protocol protocol)
{
  grapple_server server;
  grapple_server client1,client2,client3;
  int returnval=0;
  grapple_message *message;
  grapple_user group,group2;
  grapple_user serverid1,serverid2,serverid3;
  time_t start;
  grapple_confirmid messageid;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);
  client3=create_client(protocol,3);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client3))
    microsleep(10000);

  group=grapple_client_group_create(client1,"Test Group",NULL);
  group2=grapple_client_group_create(client1,"Test Group 2",NULL);

  serverid1=grapple_client_serverid_get(client1);
  serverid2=grapple_client_serverid_get(client2);
  serverid3=grapple_client_serverid_get(client3);

  grapple_client_group_add(client1,group,serverid1,NULL);
  grapple_client_group_add(client1,group,serverid2,NULL);
  grapple_client_group_add(client1,group,group2,NULL);
  grapple_client_group_add(client1,group2,serverid3,NULL);


  messageid=grapple_client_send(client1,group,GRAPPLE_CONFIRM,
				(void *)"Test Message",12);

  //Now wait for the clients to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 1 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 2 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      //Loop getting messages looking for a failed connection message

      message=grapple_client_message_pull(client3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_MSG_USER_MSG &&
	      message->USER_MSG.length==12 &&
	      !memcmp(message->USER_MSG.data,"Test Message",12))
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 3 did not receive message";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_client_destroy(client3);
      grapple_server_destroy(server);
  
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  //Here we loop and make sure that the sender DIDNT get the message
  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_client_message_pull(client1);

      if (!message)
	microsleep(10000);
      else 
	{
	  if (message->type==GRAPPLE_MSG_CONFIRM_RECEIVED &&
	      message->CONFIRM.messageid==messageid)
	    returnval=1;
	  grapple_message_dispose(message);
	}
    }

  if (!returnval)
    error="Confirm message not received";

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_client_destroy(client3);
  grapple_server_destroy(server);
  
  return returnval;
}

static int tcp_client_sendconfirmgroupgroup(void)
{
  return client_sendconfirmgroupgroup(GRAPPLE_PROTOCOL_TCP);
}

static int client_sync_int(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);

  grapple_client_intvar_set(client1,"inttest",10);

  //Now wait for the clients to receive the message
  start=time(NULL);
  while (time(NULL) < start+10 && !returnval)
    {
      if (grapple_client_intvar_get(client2,"inttest")==10)
	returnval=1;

      if (returnval==0)
	microsleep(10000);
    }

  if (!returnval)
    {
      error="Client 2 did not get int variable";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_server_destroy(server);

      return returnval;
    }

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_server_destroy(server);

  return returnval;
}

static int client_sync_double(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2;
  int returnval=0;
  time_t start;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);

  grapple_client_doublevar_set(client1,"doubletest",1.234);

  //Now wait for the clients to receive the message
  start=time(NULL);
  while (time(NULL) < start+10 && !returnval)
    {
      double got;

      got=grapple_client_doublevar_get(client2,"doubletest");
      if (got > 1.2 && got < 1.3)
	returnval=1;

      if (returnval==0)
	microsleep(10000);
    }

  if (!returnval)
    {
      error="Client 2 did not get double variable";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_server_destroy(server);

      return returnval;
    }

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_server_destroy(server);

  return returnval;
}

static int client_sync_data(grapple_protocol protocol)
{
  grapple_server server;
  grapple_client client1,client2;
  int returnval=0;
  time_t start;
  char data[6];
  size_t datalen;

  server=create_server(protocol);
  client1=create_client(protocol,1);
  client2=create_client(protocol,2);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client1))
    microsleep(10000);
  while (time(NULL) < start+5 && !grapple_client_connected(client2))
    microsleep(10000);

  strcpy(data,"Hello");
  grapple_client_datavar_set(client1,"datatest",data,5);

  //Now wait for the clients to receive the message
  start=time(NULL);
  while (time(NULL) < start+10 && !returnval)
    {
      grapple_client_datavar_get(client2,"datatest",NULL,&datalen);
      if (datalen==5)
	{
	  grapple_client_datavar_get(client2,"datatest",data,&datalen);
	  data[5]=0;
	  if (!strcmp(data,"Hello"))
	    returnval=1;
	}

      if (returnval==0)
	microsleep(10000);
    }

  if (!returnval)
    {
      error="Client 2 did not get data variable";

      grapple_client_destroy(client1);
      grapple_client_destroy(client2);
      grapple_server_destroy(server);

      return returnval;
    }

  grapple_client_destroy(client1);
  grapple_client_destroy(client2);
  grapple_server_destroy(server);

  return returnval;
}

static int tcp_client_sync_int(void)
{
  return client_sync_int(GRAPPLE_PROTOCOL_TCP);
}

static int tcp_client_sync_double(void)
{
  return client_sync_double(GRAPPLE_PROTOCOL_TCP);
}

static int tcp_client_sync_data(void)
{
  return client_sync_data(GRAPPLE_PROTOCOL_TCP);
}

static int encyption_connect_with_keys(grapple_protocol protocol,
				       const char *server_private,
				       const char *server_public,
				       const char *server_ca,
				       const char *client_private,
				       const char *client_public,
				       const char *client_ca)
{
  grapple_server server;
  grapple_client client;
  grapple_certificate *cert = NULL;
  int returnval=1;
  time_t start;

  server=create_encrypted_server(protocol,server_private,server_public,
				 server_ca);
  client=create_encrypted_client(protocol,1,client_private,client_public,
				 client_ca);

  start=time(NULL);

  while (time(NULL) < start+5 && !grapple_client_connected(client))
    microsleep(10000);

  if (time(NULL) >= start+5)
    returnval=0;

  if (server_ca)
    {
      grapple_user *users;
      users=grapple_server_userlist_get(server);

      cert=grapple_server_user_certificate_get(server,users[0]);
    }

  grapple_client_destroy(client);
  grapple_server_destroy(server);

  if (cert)
    grapple_certificate_dispose(cert);

  return returnval;
}

static int encyption_connect_nokeys(grapple_protocol protocol)
{
  return encyption_connect_with_keys(protocol,
				     NULL,NULL,NULL,NULL,NULL,NULL);
}

static int tcp_encyption_connect_nokeys(void)
{
  return encyption_connect_nokeys(GRAPPLE_PROTOCOL_TCP);
}

static int encyption_connect_serverkeys(grapple_protocol protocol)
{
  return encyption_connect_with_keys(protocol,
				     enc_key,enc_cert,NULL,
				     NULL,NULL,NULL);
}

static int tcp_encyption_connect_serverkeys(void)
{
  return encyption_connect_serverkeys(GRAPPLE_PROTOCOL_TCP);
}

static int encyption_connect_clientkeys(grapple_protocol protocol)
{
  return encyption_connect_with_keys(protocol,
				     NULL,NULL,NULL,
				     enc_key,enc_cert,NULL);
}

static int tcp_encyption_connect_clientkeys(void)
{
  return encyption_connect_clientkeys(GRAPPLE_PROTOCOL_TCP);
}

static int encyption_connect_bothkeys(grapple_protocol protocol)
{
  return encyption_connect_with_keys(protocol,
				     enc_key,enc_cert,NULL,
				     enc_key,enc_cert,NULL);
}

static int tcp_encyption_connect_bothkeys(void)
{
  return encyption_connect_bothkeys(GRAPPLE_PROTOCOL_TCP);
}

static int encyption_connect_clientkeysca(grapple_protocol protocol)
{
  return encyption_connect_with_keys(protocol,
				     NULL,NULL,enc_ca,
				     enc_key,enc_cert,NULL);
}

static int tcp_encyption_connect_clientkeysca(void)
{
  return encyption_connect_clientkeysca(GRAPPLE_PROTOCOL_TCP);
}

static int encyption_connect_serverkeysca(grapple_protocol protocol)
{
  return encyption_connect_with_keys(protocol,
				     enc_key,enc_cert,NULL,
				     NULL,NULL,enc_ca);
}

static int tcp_encyption_connect_serverkeysca(void)
{
  return encyption_connect_serverkeysca(GRAPPLE_PROTOCOL_TCP);
}



static int udp_basicconnect(void)
{
  return basicconnect(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_messagepull(void)
{
  return server_messagepull(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_messagepull(void)
{
  return client_messagepull(GRAPPLE_PROTOCOL_UDP);
}

static int udp_basicfailconnect(void)
{
  return basicfailconnect(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_detectrunning(void)
{
  return server_detectrunning(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_restart(void)
{
  return server_restart(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_connected(void)
{
  return client_connected(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_userenumeraion(void)
{
  return server_userenumeraion(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_maxusers(void)
{
  return server_maxusers(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_closed(void)
{
  return server_closed(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_description(void)
{
  return server_description(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_usercount(void)
{
  return server_usercount(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_userlist(void)
{
  return server_userlist(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_password(void)
{
  return server_password(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_messagecount(void)
{
  return server_messagecount(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_messagetoone(void)
{
  return server_messagetoone(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_messagetoall(void)
{
  return server_messagetoall(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_callbacks(void)
{
  return server_callbacks(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_disconnectclient(void)
{
  return server_disconnectclient(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_ping(void)
{
  return server_ping(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_autoping(void)
{
  return server_autoping(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_newgroup(void)
{
  return server_newgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_grouplist(void)
{
  return server_grouplist(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_clientgrouplist(void)
{
  return server_clientgrouplist(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_addgroup(void)
{
  return server_addgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_groupmemberlist(void)
{
  return server_groupmemberlist(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_groupmemberlistclient(void)
{
  return server_groupmemberlistclient(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_groupenum(void)
{
  return server_groupenum(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_groupmemberenum(void)
{
  return server_groupmemberenum(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_sendgroup(void)
{
  return server_sendgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_sendgroupgroup(void)
{
  return server_sendgroupgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_removegroup(void)
{
  return server_removegroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_deletegroup(void)
{
  return server_deletegroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_sendconfirmone(void)
{
  return server_sendconfirmone(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_sendconfirmeveryone(void)
{
  return server_sendconfirmeveryone(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_sendconfirmgroup(void)
{
  return server_sendconfirmgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_server_sendconfirmgroupgroup(void)
{
  return server_sendconfirmgroupgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_restart(void)
{
  return client_restart(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_enumusers(void)
{
  return client_enumusers(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_changename(void)
{
  return client_changename(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_userlist(void)
{
  return client_userlist(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_messagecount(void)
{
  return client_messagecount(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendtoserver(void)
{
  return client_sendtoserver(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendtoone(void)
{
  return client_sendtoone(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendtoallother(void)
{
  return client_sendtoallother(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendtoall(void)
{
  return client_sendtoall(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_callbacks(void)
{
  return client_callbacks(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_ping(void)
{
  return client_ping(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupcreate(void)
{
  return client_groupcreate(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_grouplist(void)
{
  return client_grouplist(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_grouplistother(void)
{
  return client_grouplistother(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupadd(void)
{
  return client_groupadd(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupmemberlist(void)
{
  return client_groupmemberlist(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupmemberlistother(void)
{
  return client_groupmemberlistother(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupenum(void)
{
  return client_groupenum(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupmemberenum(void)
{
  return client_groupmemberenum(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendtogroup(void)
{
  return client_sendtogroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendtogroupgroup(void)
{
  return client_sendtogroupgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupremove(void)
{
  return client_groupremove(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_groupdelete(void)
{
  return client_groupdelete(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendconfirmserver(void)
{
  return client_sendconfirmserver(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendconfirmone(void)
{
  return client_sendconfirmone(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendconfirmall(void)
{
  return client_sendconfirmall(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendconfirmallother(void)
{
  return client_sendconfirmallother(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendconfirmgroup(void)
{
  return client_sendconfirmgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sendconfirmgroupgroup(void)
{
  return client_sendconfirmgroupgroup(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sync_int(void)
{
  return client_sync_int(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sync_double(void)
{
  return client_sync_double(GRAPPLE_PROTOCOL_UDP);
}

static int udp_client_sync_data(void)
{
  return client_sync_data(GRAPPLE_PROTOCOL_UDP);
}

static grapple_server create_lobbyserver(void)
{
  grapple_lobby lobbyserver;
  
  lobbyserver=grapple_lobby_init("unittest","1.0");
  grapple_lobby_port_set(lobbyserver,4567);
  grapple_lobby_start(lobbyserver);

  return lobbyserver;
}

static grapple_client create_lobbyclient(int playernum)
{
  grapple_lobbyclient lobbyclient;

  char name[128];

  lobbyclient=grapple_lobbyclient_init("unittest","1.0");
  grapple_lobbyclient_address_set(lobbyclient,NULL);
  grapple_lobbyclient_port_set(lobbyclient,4567);
  sprintf(name,"Player%d",playernum);
  grapple_lobbyclient_name_set(lobbyclient,name);

  if (grapple_lobbyclient_start(lobbyclient) == GRAPPLE_OK)
    return lobbyclient;

  grapple_lobbyclient_destroy(lobbyclient);

  lobbyclient=0;

  return lobbyclient;
}

static int lobby_basicconnect(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient;
  int returnval=0;

  //Start a lobby server, connect a client to it

  lobbyserver=create_lobbyserver();
  lobbyclient=create_lobbyclient(1);
  
  if (lobbyclient)
    returnval=1;


  grapple_lobbyclient_destroy(lobbyclient);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_getmessage(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient;
  int returnval=0;
  grapple_lobbymessage *message;
  time_t start;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient=create_lobbyclient(1);
  

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient);

      if (message)
	{
	  returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
      else
	microsleep(10000);
    }

  grapple_lobbyclient_destroy(lobbyclient);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_roomcreate(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient;
  int returnval=0;
  grapple_lobbyroomid roomid;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient=create_lobbyclient(1);
  
  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient);

  if (grapple_lobbyclient_room_create(lobbyclient,"Test Room",
				      NULL)==GRAPPLE_OK)
    {
      if (roomid!=grapple_lobbyclient_currentroomid_get(lobbyclient))
	returnval=1;
    }

  grapple_lobbyclient_destroy(lobbyclient);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_roomusers(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  grapple_user *userlist;
  grapple_lobbyroomid roomid;
  int returnval=0;
  int loopa;
  time_t start;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);

  start=time(NULL);
  while (time(NULL) < start+5 && !returnval)
    {
      loopa=0;

      userlist=grapple_lobbyclient_roomusers_get(lobbyclient1,roomid);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa==3)
	returnval=1;
      else
	microsleep(10000);
    }

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_roomlist(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_lobbyroomid *roomlist;
  int loopa=0;
  time_t start;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);
  grapple_lobbyclient_room_create(lobbyclient2,"Test Room 2",NULL); 
  grapple_lobbyclient_room_create(lobbyclient3,"Test Room 3",NULL);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient1);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa==3) //3 created rooms
	returnval=1;
      else
	microsleep(10000);
    }

  if (!returnval)
    {
      if (loopa<3)
	error="Not enough rooms detected";
      else
	error="Too Many rooms detected";
    }

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_roomjoin(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  grapple_lobbyroomid roomid,targetroomid;
  time_t start;
  int loopa;
  grapple_lobbyroomid *roomlist;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  
  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient2);
  
  targetroomid=grapple_lobbyclient_roomid_get(lobbyclient1,"Test Room");

  //Loop, wait for the number of rooms to be 1 for client2
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient2);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }
  
  grapple_lobbyclient_room_enter(lobbyclient2,targetroomid,NULL);
  if (grapple_lobbyclient_currentroomid_get(lobbyclient2)==targetroomid)
    returnval=1;

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_leaveroombasic(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient;
  int returnval=0;
  grapple_lobbyroomid roomid;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient=create_lobbyclient(1);
  
  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient);

  grapple_lobbyclient_room_create(lobbyclient,"Test Room",NULL);
  
  grapple_lobbyclient_room_leave(lobbyclient);

  if (grapple_lobbyclient_currentroomid_get(lobbyclient)==roomid)
    returnval=1;

  grapple_lobbyclient_destroy(lobbyclient);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_leaveroomnotlast(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  grapple_lobbyroomid roomid;
  time_t start;
  int loopa;
  grapple_lobbyroomid *roomlist;
  grapple_user *userlist;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  
  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);

  //Loop, wait for the number of rooms to be 1 for client2
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient2);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Room not detected for client2";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  grapple_lobbyclient_room_enter(lobbyclient2,roomid,NULL);

  start=time(NULL);

  loopa=0;

  while (time(NULL) < start+5 && loopa!=2)
    {
      loopa=0;

      //Loop till there are 2 users here for client 1
      //know its worked
      userlist=grapple_lobbyclient_roomusers_get(lobbyclient1,roomid);

      loopa=0;
      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      if (loopa!=2)
	microsleep(10000);
    }
  if (loopa!=2)
    {
      if (loopa>2)
	error="Too many users in room - waiting for client2 to arrive";
      else
	error="Client2 never arrives";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  grapple_lobbyclient_room_leave(lobbyclient1);

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      loopa=0;

      //Loop till there is just one user in the room for client 2, when we
      //know its worked
      userlist=grapple_lobbyclient_roomusers_get(lobbyclient2,roomid);

      loopa=0;
      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      if (loopa==1)
	returnval=1;
      else
	microsleep(10000);
    }

  if (!returnval)
    {
      if (loopa>1)
	error="Client 1 never leaves";
      else
	error="Erm, this room is empty!";
    }
  
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_leaveroomlast(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  grapple_lobbyroomid roomid;
  time_t start;
  int loopa;
  grapple_lobbyroomid *roomlist;
  grapple_user *userlist;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  
  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);

  //Loop, wait for the number of rooms to be 2 for client2
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient2);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      if (loopa>1)
	error="Client 2 found too many rooms";
      else
	error="Client 2 found too few rooms";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  grapple_lobbyclient_room_enter(lobbyclient2,roomid,NULL);

  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=2)
    {

      loopa=0;
      //Loop till there is just one user in the room for client 2, when we
      //know its worked
      userlist=grapple_lobbyclient_roomusers_get(lobbyclient2,roomid);

      loopa=0;
      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      if (loopa!=2)
	microsleep(10000);
    }

  if (loopa!=2)
    {
      if (loopa>2)
	error="Client 2 found too many users when there should be 2";
      else
	error="Client 2 found too few users when there should be 2";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Now have client 2 leave the room
  grapple_lobbyclient_room_leave(lobbyclient2);

  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {

      loopa=0;
      //Loop till there is just one user in the room for client 2, when we
      //know its worked
      userlist=grapple_lobbyclient_roomusers_get(lobbyclient2,roomid);

      loopa=0;
      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      if (loopa>1)
	error="Client 2 found too many users when there should be 1";
      else
	error="Client 2 found too few users when there should be 1";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  grapple_lobbyclient_room_leave(lobbyclient1);

  if (loopa!=1)
    {
      if (loopa>1)
	error="Client 2 found too many users";
      else
	error="Client 2 found too few users";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Now client 1 needs to test for only one room left
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient1);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa==0)
	returnval=1;
      else
	microsleep(10000);
    }

  if (!returnval)
    error="Client 1 found too many rooms still";


  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_mainchat(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_lobbymessage *message;
  time_t start;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  //1 sends a chat, check for 2 and 3 to receive it
  grapple_lobbyclient_chat(lobbyclient1,"Test Message");

  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_otherchat(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_lobbymessage *message;
  grapple_lobbyroomid roomid;
  grapple_lobbyroomid *roomlist;
  grapple_user *userlist;
  int loopa;
  time_t start;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);

  //Loop, wait for the number of rooms to be 2 for client2
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient2);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Join 2 to the room
  grapple_lobbyclient_room_enter(lobbyclient2,roomid,NULL);

  //Loop, wait for the number of rooms to be 2 for client3
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient3);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Join 2 to the room
  grapple_lobbyclient_room_enter(lobbyclient3,roomid,NULL);

  //Now both are in the room, wait for 1 to know they are there
  loopa=0;
  start=time(NULL);
  while (time(NULL) < start+5 && loopa!=3)
    {
      loopa=0;

      userlist=grapple_lobbyclient_roomusers_get(lobbyclient1,roomid);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa!=3)
	microsleep(10000);
    }

  //1 sends a chat, check for 2 and 3 to receive it
  grapple_lobbyclient_chat(lobbyclient1,"Test Message");

  //Now wait for the client to receive the message
  start=time(NULL);

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  returnval=0;
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_differentchat(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_lobbymessage *message;
  grapple_lobbyroomid roomid;
  grapple_lobbyroomid *roomlist;
  int loopa;
  time_t start;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);
  grapple_lobbyclient_room_create(lobbyclient2,"Test Room 2",NULL);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);

  //Loop, wait for the number of rooms to be 3 for client1
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=2)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient1);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa!=2)
	microsleep(10000);
    }

  if (loopa!=2)
    {
      error="Room count incorrect";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //1 sends a chat, check for 1 toreceive, then 2 and 3 to NOT receive it
  grapple_lobbyclient_chat(lobbyclient1,"Test Message");

  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+4 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client first message problem";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Client 1 received it, now we send a new chat for 2 and for 3, wait for
  //them to receive theirown - which is going to be after the c1 message,
  //if c1 message received

  start=time(NULL);
  returnval=0;

  grapple_lobbyclient_chat(lobbyclient2,"Test Message 2");
  grapple_lobbyclient_chat(lobbyclient3,"Test Message 3");

  while (time(NULL) < start+4 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==14 &&
	      !memcmp(message->CHAT.message,"Test Message 2",14))
	    returnval=1;
	  else if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    {
	      grapple_lobbymessage_dispose(message);
	      break;
	    }
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client second message problem";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+4 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient3);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    {
	      grapple_lobbymessage_dispose(message);
	      break;
	    }
	  else if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==14 &&
	      !memcmp(message->CHAT.message,"Test Message 3",14))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    error="Client third message problem";

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_gameregister(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient;
  int returnval=0;
  grapple_server server;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient=create_lobbyclient(1);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);
  
  grapple_server_description_set(server,"test",5);

  if (grapple_lobbyclient_game_register(lobbyclient,server))
    returnval=1;

  grapple_server_destroy(server);
  grapple_lobbyclient_destroy(lobbyclient);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_gamelist(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  grapple_server server;
  grapple_lobbygameid gameid,*gamelist;
  time_t start;
  int loopa;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);


  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && !returnval)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,
						grapple_lobbyclient_currentroomid_get(lobbyclient2));

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa==1)
	returnval=1;
      else
	microsleep(10000);
    }

  if (!returnval)
    error="Client 2 never received game";

  grapple_server_destroy(server);
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
  

  return returnval;
}

static int lobbyclient_gamejoin(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  grapple_server server;
  grapple_client client;
  grapple_lobbygameid gameid,*gamelist;
  time_t start;
  int loopa;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,
						grapple_lobbyclient_currentroomid_get(lobbyclient2));

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Now join the game
  client=grapple_client_init("unittest","1.0");
  grapple_client_sequential_set(client,GRAPPLE_SEQUENTIAL);

  if (grapple_lobbyclient_game_join(lobbyclient2,gameid,client)==GRAPPLE_OK)
    returnval=1;


  grapple_server_destroy(server);
  grapple_client_destroy(client);
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_gameserversubthread(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_server server;
  grapple_client client;
  grapple_lobbygameid gameid,*gamelist;
  time_t start;
  int loopa;
  grapple_lobbygame *game;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,
						grapple_lobbyclient_currentroomid_get(lobbyclient2));

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Client 2 never sees the game";
      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Now join the game
  client=grapple_client_init("unittest","1.0");
  grapple_client_sequential_set(client,GRAPPLE_SEQUENTIAL);
  grapple_lobbyclient_game_join(lobbyclient2,gameid,client);
  
  //Now we use client 3 to see what happens when the server changes stuff

  grapple_server_maxusers_set(server,5);
  grapple_server_closed_set(server,GRAPPLE_SERVER_CLOSED);
  grapple_server_description_set(server,"test",5);

  //Loop to get the values now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && !returnval)
    {
      game=grapple_lobbyclient_game_get(lobbyclient3,gameid);
      
      if (game)
	{
	  returnval=0;

	  if (game->maxusers==5 && 
	      game->currentusers==1 &&
	      game->closed==1 &&
	      game->descriptionlen==5 && 
	      !strcmp(game->description,"test"))
	    returnval=1;
	  else
	    {
	      if (game->maxusers!=5)
		error="Client 2 never sees 5 max users";
	      else if (game->currentusers!=1)
		error="Client 2 never sees 1 current user";
	      else if (game->closed!=1)
		error="Client 2 never sees game closed";
	      else
		error="Client 2 never sees the description";
	    }
	  grapple_lobbyclient_game_dispose(game);
	}
      if (!returnval)
	microsleep(10000);
    }

  if (returnval)
    error=NULL;

  grapple_server_destroy(server);
  grapple_client_destroy(client);
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_leavegame(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3,lobbyclient4;
  int returnval=0;
  grapple_server server;
  grapple_client client;
  grapple_lobbymessage *message;
  grapple_lobbygameid gameid,*gamelist;
  time_t start;
  int loopa;
  grapple_lobbygame *game;
  grapple_user *userlist;
  grapple_lobbyroomid roomid;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  lobbyclient4=create_lobbyclient(4);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);
  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);
      
      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Cant find game";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  //Now join the game
  client=grapple_client_init("unittest","1.0");
  grapple_client_sequential_set(client,GRAPPLE_SEQUENTIAL);

  grapple_lobbyclient_game_join(lobbyclient2,gameid,client);

  //Loop to get the values now
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      game=grapple_lobbyclient_game_get(lobbyclient3,gameid);
      
      if (game)
	{
	  if (game->currentusers==1)
	    returnval=1;
	  grapple_lobbyclient_game_dispose(game);
	}
      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    {
      error="Couldnt confirm number of users connected";

      grapple_server_destroy(server);
      grapple_client_destroy(client);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  //Now client 3 sends a chat message
  grapple_lobbyclient_chat(lobbyclient3,"Test Message");

  //Only 4 should receive it
  //Now wait for the client to receive the message
  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient4);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    {
      error="Client 4 didnt receive message";

      grapple_server_destroy(server);
      grapple_client_destroy(client);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  //Now someone has received the message - it is PHYSICALLY IMPOSSIBLE
  //and is NOT a race condition, to now be sure that when closing this client,
  //the next chat message will be the first one to get to the client that
  //has just quit
  
  grapple_client_destroy(client);

  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+5 && !returnval)
    {
      game=grapple_lobbyclient_game_get(lobbyclient3,gameid);
      
      if (game)
	{
	  if (game->currentusers==0)
	    returnval=1;
	  grapple_lobbyclient_game_dispose(game);
	}
      if (!returnval)
	microsleep(10000);
    }
  
  if (!returnval)
    {
      error="Couldnt confirm disconnection";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);
  
      return returnval;
    }

  //Wait for client 2 to be back in the room
  loopa=0;
  start=time(NULL);
  while (time(NULL) < start+5 && loopa!=3)
    {
      loopa=0;

      userlist=grapple_lobbyclient_roomusers_get(lobbyclient3,roomid);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa!=3)
	microsleep(10000);
    }

  if (loopa!=3)
    {
      error="Client never re-entered room";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);
  
      return returnval;
    }

  //Now client 3 sends a chat message
  grapple_lobbyclient_chat(lobbyclient3,"Test Message 2");

  //2 should Only receive this chat message
  //Now wait for the client to receive the message
  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient2);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    {
	      break;
	    }
	  else if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==14 &&
	      !memcmp(message->CHAT.message,"Test Message 2",14))
	    {
	      returnval=1;
	    }
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    error="Bad or lack of message on final test";

  grapple_server_destroy(server);
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobbyclient_destroy(lobbyclient4);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_gameclientsubthread(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_server server;
  grapple_client client;
  grapple_lobbygameid gameid,*gamelist;
  time_t start;
  int loopa;
  grapple_lobbygame *game;
  grapple_user *userlist;
  grapple_lobbyroomid roomid;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);
  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Client 2 never receives game list";
      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //NOW Make sure client3 has the game
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient3,roomid);

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Client 3 never receives game list";
      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Now join the game
  client=grapple_client_init("unittest","1.0");
  grapple_client_sequential_set(client,GRAPPLE_SEQUENTIAL);
  grapple_lobbyclient_game_join(lobbyclient2,gameid,client);

  //Loop to get the values now
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      game=grapple_lobbyclient_game_get(lobbyclient3,gameid);
      
      if (game)
	{
	  if (game->currentusers==1)
	    returnval=1;
	  grapple_lobbyclient_game_dispose(game);
	}
      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    {
      error="Client 3 never sees a user connected";
      grapple_server_destroy(server);
      grapple_client_destroy(client);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }
  
  grapple_client_destroy(client);

  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+5 && !returnval)
    {
      game=grapple_lobbyclient_game_get(lobbyclient3,gameid);
      
      if (game)
	{
	  if (game->currentusers==0)
	    returnval=1;
	  grapple_lobbyclient_game_dispose(game);
	}
      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    {
      error="Client 3 never sees user disconnect";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  returnval=0;

  //Wait for client 2 to be back in the room
  loopa=0;
  start=time(NULL);
  while (time(NULL) < start+5 && loopa!=2)
    {
      loopa=0;

      userlist=grapple_lobbyclient_roomusers_get(lobbyclient3,roomid);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa!=2)
	microsleep(10000);
    }

  if (loopa!=2)
    {
      error="Client 3 does not see client 2 back in the room";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
  
      return returnval;
    }

  returnval=1;
  
  grapple_server_destroy(server);
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_finishgameempty(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_server server;
  grapple_lobbymessage *message;
  grapple_lobbygameid gameid,*gamelist;
  grapple_lobbyroomid roomid;
  grapple_user *userlist;
  time_t start;
  int loopa,count;
  static char buf[128];

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient2);

  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Client 2 never gets the game";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  //Now client 2 sends a chat message
  grapple_lobbyclient_chat(lobbyclient2,"Test Message");

  //Players 2 and 3 should receive it, 1 is out of room

  //Now wait for the client to receive the message
  start=time(NULL);
  count=0;

  while (time(NULL) < start+10 && count<2)
    {
      if (count==0)
	message=grapple_lobbyclient_message_pull(lobbyclient2);
      else
	message=grapple_lobbyclient_message_pull(lobbyclient3);

      if (message)
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    {
	      count++;
	    }
	  grapple_lobbymessage_dispose(message);
	}
      else
	microsleep(10000);
    }

  if (count<2)
    {
      sprintf(buf,"Only %d users get the message",count);
      error=buf;

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
      
      return 0;
    }

  grapple_server_destroy(server);

  //Now we wait for the client to know its game is deleted

  start=time(NULL);
  returnval=0;

  loopa=1;
  while (time(NULL) < start+5 && loopa!=0)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);
      
      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=0)
	microsleep(10000);
    }

  if (loopa!=0)
    {
      error="The game is never destroyed";
      
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
  
      return returnval;
    }

  //Wait for client 1 to be back in the room
  loopa=0;
  start=time(NULL);
  while (time(NULL) < start+5 && loopa!=3)
    {
      loopa=0;

      userlist=grapple_lobbyclient_roomusers_get(lobbyclient3,roomid);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa!=3)
	microsleep(10000);
    }

  if (loopa!=3)
    {
      error="Client never returns to room";

      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);
  
      return returnval;
    }

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return 1;
}

static int lobbyclient_finishgamefull(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3,lobbyclient4;
  int returnval=0;
  grapple_server server;
  grapple_client client;
  grapple_lobbymessage *message;
  grapple_lobbygameid gameid,*gamelist;
  grapple_lobbyroomid roomid;
  grapple_user *userlist;
  time_t start;
  int loopa;
  grapple_lobbygame *game;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  lobbyclient4=create_lobbyclient(4);
  
  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient2);
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,
						grapple_lobbyclient_currentroomid_get(lobbyclient2));

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);
      
      return returnval;
    }

  //Now join the game
  client=grapple_client_init("unittest","1.0");
  grapple_client_sequential_set(client,GRAPPLE_SEQUENTIAL);
  grapple_lobbyclient_game_join(lobbyclient2,gameid,client);

  //Loop to get the values now
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      game=grapple_lobbyclient_game_get(lobbyclient3,gameid);
      
      if (game)
	{
	  if (game->currentusers==1)
	    returnval=1;
	  grapple_lobbyclient_game_dispose(game);
	}
      if (!returnval)
	microsleep(10000);
    }

  if (!returnval)
    {
      grapple_server_destroy(server);
      grapple_client_destroy(client);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  //Now client 3 sends a chat message
  grapple_lobbyclient_chat(lobbyclient3,"Test Message");

  //Only 4 should receive it
  //Now wait for the client to receive the message
  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient4);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    returnval=1;
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    {
      grapple_server_destroy(server);
      grapple_client_destroy(client);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  //Now someone has received the message - it is PHYSICALLY IMPOSSIBLE
  //and is NOT a race condition, to now be sure that when closing this client,
  //the next chat message will be the first one to get to the client that
  //has just quit
  
  grapple_server_destroy(server);

  start=time(NULL);
  returnval=0;

  loopa=1;
  while (time(NULL) < start+5 && loopa!=0)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);
      
      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=0)
	microsleep(10000);
    }

  if (loopa!=0)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);
      grapple_client_destroy(client);
  
      return returnval;
    }

  //Wait for client 2 to be back in the room
  loopa=0;
  start=time(NULL);
  while (time(NULL) < start+5 && loopa!=4)
    {
      loopa=0;

      userlist=grapple_lobbyclient_roomusers_get(lobbyclient3,roomid);

      if (userlist)
	{
	  while (userlist[loopa])
	    loopa++;
	  free(userlist);
	}
      
      if (loopa!=4)
	microsleep(10000);
    }

  if (loopa!=4)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);
      grapple_client_destroy(client);
  
      return returnval;
    }

  //Now client 2 sends a new chat message
  grapple_lobbyclient_chat(lobbyclient2,"Test Message 2");

  //1 should Only receive this chat message
  //Now wait for the client to receive the message
  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+10 && !returnval)
    {
      message=grapple_lobbyclient_message_pull(lobbyclient1);

      if (!message)
	microsleep(10000);
      else
	{
	  if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==12 &&
	      !memcmp(message->CHAT.message,"Test Message",12))
	    {
	      break;
	    }
	  else if (message->type==GRAPPLE_LOBBYMSG_CHAT &&
	      message->CHAT.length==14 &&
	      !memcmp(message->CHAT.message,"Test Message 2",14))
	    {
	      returnval=1;
	    }
	  grapple_lobbymessage_dispose(message);
	}
    }

  if (!returnval)
    {
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobbyclient_destroy(lobbyclient4);
      grapple_lobby_destroy(lobbyserver);
      grapple_client_destroy(client);
  
      return returnval;
    }

  loopa=0;
  returnval=0;

  userlist=grapple_lobbyclient_roomusers_get(lobbyclient1,roomid);

  if (userlist)
    {
      while (userlist[loopa])
	loopa++;
      free(userlist);
    }
      
  if (loopa==4)
    returnval=1;

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobbyclient_destroy(lobbyclient4);
  grapple_lobby_destroy(lobbyserver);
  grapple_client_destroy(client);
  
  return returnval;
}

static int lobbyclient_gamestartroom(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  grapple_server server;
  grapple_lobbygameid gameid,*gamelist;
  time_t start;
  int loopa=0;
  grapple_lobbyroomid roomid;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);

  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);
      
      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa==1)
	returnval=1;
      else
	microsleep(10000);
    }

  if (loopa>1)
    error="Too many games detected";
  else if (loopa<1)
    error="Not enough games detected";

  grapple_server_destroy(server);
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
   
 return returnval;
}

static int lobbyclient_leaveroomlastbutgame(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2,lobbyclient3;
  int returnval=0;
  grapple_server server;
  grapple_lobbygameid gameid,*gamelist;
  time_t start;
  int loopa;
  grapple_lobbyroomid roomid,*roomlist;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  lobbyclient3=create_lobbyclient(3);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  grapple_lobbyclient_room_create(lobbyclient1,"Test Room",NULL);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient1);

  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+3 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);
      
      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Cannot find created game";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobbyclient_destroy(lobbyclient3);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  //We now need to check the room is still there
  //To check this we create another room with client 3 and then wait for
  //client 2 to have TWO rooms, so this MUST mean we have all the ones we
  //should have
  grapple_lobbyclient_room_create(lobbyclient3,"Test Room 2",NULL);

  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && !returnval)
    {
      roomlist=grapple_lobbyclient_roomlist_get(lobbyclient2);

      loopa=0;
      if (roomlist)
	{
	  while (roomlist[loopa])
	    loopa++;
	  free(roomlist);
	}
      
      if (loopa==2)
	returnval=1;
      else
	microsleep(10000);
    }

  if (loopa>2)
    error="Found too many rooms";
  else if (loopa<2)
    error="Found too few rooms";

  grapple_server_destroy(server);
  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobbyclient_destroy(lobbyclient3);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_gameserverdisconnect(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  grapple_server server;
  grapple_lobbygameid gameid,*gamelist;
  grapple_lobbyroomid roomid;
  time_t start;
  int loopa;

  //Start a lobby server, connect a client to it
  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);
  
  server=create_server(GRAPPLE_PROTOCOL_TCP);

  roomid=grapple_lobbyclient_currentroomid_get(lobbyclient2);

  gameid=grapple_lobbyclient_game_register(lobbyclient1,server);

  //Make sure client2 has the game now
  start=time(NULL);

  loopa=0;
  while (time(NULL) < start+5 && loopa!=1)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);

      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	microsleep(10000);
    }

  if (loopa!=1)
    {
      error="Client 2 doesnt see the game start";

      grapple_server_destroy(server);
      grapple_lobbyclient_destroy(lobbyclient1);
      grapple_lobbyclient_destroy(lobbyclient2);
      grapple_lobby_destroy(lobbyserver);

      return returnval;
    }

  grapple_lobbyclient_destroy(lobbyclient1);

  start=time(NULL);
  returnval=0;

  while (time(NULL) < start+5 && !returnval)
    {
      gamelist=grapple_lobbyclient_gamelist_get(lobbyclient2,roomid);
      
      loopa=0;
      if (gamelist)
	{
	  while (gamelist[loopa])
	    loopa++;
	  free(gamelist);
	}
      
      if (loopa!=1)
	returnval=1;
      else
	microsleep(10000);
    }

  if (returnval==0)
    error="Client 2 doesnt see the game end";

  grapple_server_destroy(server);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}

static int lobbyclient_callbacks(void)
{
  grapple_lobby lobbyserver;
  grapple_lobbyclient lobbyclient1,lobbyclient2;
  int returnval=0;
  time_t start;
  int count;

  count=0;

  lobbyserver=create_lobbyserver();
  lobbyclient1=create_lobbyclient(1);
  lobbyclient2=create_lobbyclient(2);

  //Now create a callback
  grapple_lobbyclient_callback_setall(lobbyclient1,lobbymessage_callback,
				      &count);

  //A simple message we know works, so we know we have a message coming in
  start=time(NULL);

  grapple_lobbyclient_chat(lobbyclient2,"NewName");

  start=time(NULL);

  while (time(NULL) < start+5 && !returnval)
    {
      returnval=count;
      if (!returnval)
	microsleep(10000);
    }

  grapple_lobbyclient_destroy(lobbyclient1);
  grapple_lobbyclient_destroy(lobbyclient2);
  grapple_lobby_destroy(lobbyserver);
  
  return returnval;
}


static int runtest(const char *message,int (*function)(void))
{
  error=NULL;
  if (!quiet)
    {
      printf("%-70s",message);
      fflush(stdout);
    }

  if ((*function)() && !error)
    {
      staticpass++;
      if (!quiet)
	printf("[[00;32mPASS[00m]\n");
    }
  else
    {
      staticfail++;
      if (quiet)
	printf("%-70s",message);

      printf("[[00;31mFAIL[00m]\n");

      if (error && *error)
	{
	  printf("Error: %-70s\n",error);
	  error="";
	}
    }

  
  return 0;
}

int main(int argc,char **argv)
{
  int loopa=0;
  struct timeval starttime,thislooptime,endtime,diff;
  double dtime;
  ///////////////////SERVERS TCP
  int looptarget=1;

  for (loopa=1;loopa<argc;loopa++)
    {
      if (!strcmp(argv[loopa],"q"))
	quiet=1;
      else if (isdigit(argv[loopa][0]))
	looptarget=atoi(argv[loopa]);
    }
      
  gettimeofday(&starttime,NULL);

  loopa=0;

  while (loopa++<looptarget && staticfail==0)
    {
      gettimeofday(&thislooptime,NULL);

      /**/
      runtest("TCP: Connect a client to a server",tcp_basicconnect);
      runtest("TCP Server: Pull Messages",tcp_server_messagepull);
      runtest("TCP Client: Pull Messages",tcp_client_messagepull);
      runtest("TCP: Fail to connect a client to a different server",tcp_basicfailconnect);
      runtest("TCP Server: Detect server running",tcp_server_detectrunning);
      runtest("TCP Server: Stop and restart a server",tcp_server_restart);
      
      //Need to test this here
      runtest("TCP Client: Detect if client connected",tcp_client_connected);
      
      runtest("TCP Server: Connected user enumeration",tcp_server_userenumeraion);
      runtest("TCP Server: Set maximum connected users",tcp_server_maxusers);
      runtest("TCP Server: Set closed",tcp_server_closed);

      runtest("TCP Server: Set description",tcp_server_description);
      
      runtest("TCP Server: Get current user count",tcp_server_usercount);
      runtest("TCP Server: Obtain userlist",tcp_server_userlist);
      runtest("TCP Server: Test server password",tcp_server_password);
      runtest("TCP Server: Count Messages",tcp_server_messagecount);
      runtest("TCP Server: Send to one user",tcp_server_messagetoone);
      runtest("TCP Server: Send to all users",tcp_server_messagetoall);
      runtest("TCP Server: Test Message via callbacks",tcp_server_callbacks);
      runtest("TCP Server: Disconnect a client",tcp_server_disconnectclient);
      runtest("TCP Server: Ping test",tcp_server_ping);
      runtest("TCP Server: Autoping test",tcp_server_autoping);
      
      runtest("TCP Server: Create a group",tcp_server_newgroup);
      
      runtest("TCP Server: Obtain grouplist",tcp_server_grouplist);
      runtest("TCP Server: Obtain grouplist from client",tcp_server_clientgrouplist);
      runtest("TCP Server: Add a user to a group",tcp_server_addgroup);
      
      runtest("TCP Server: Obtain groupmemberlist",tcp_server_groupmemberlist);
      runtest("TCP Server: Obtain groupmemberlist from client",tcp_server_groupmemberlistclient);
      
      runtest("TCP Server: Group Enumeration",tcp_server_groupenum);
      runtest("TCP Server: Groupmember Enumeration",tcp_server_groupmemberenum);
      
      runtest("TCP Server: Send to a group",tcp_server_sendgroup);
      runtest("TCP Server: Send to a group containing a group",tcp_server_sendgroupgroup);
      
      runtest("TCP Server: Remove a user from a group",tcp_server_removegroup);
      runtest("TCP Server: Delete a group",tcp_server_deletegroup);
      
      runtest("TCP Server: Send with Confirm to one user",tcp_server_sendconfirmone);
      runtest("TCP Server: Send with Confirm to everyone",tcp_server_sendconfirmeveryone);
      runtest("TCP Server: Send with Confirm to a group",tcp_server_sendconfirmgroup);
      runtest("TCP Server: Send with Confirm to a group containing a group",tcp_server_sendconfirmgroupgroup);
      ///////////////////CLIENTS TCP
      
      runtest("TCP Client: Stop and restart a client",tcp_client_restart);
      runtest("TCP Client: Connected user enumeration",tcp_client_enumusers);
      runtest("TCP Client: Change Name",tcp_client_changename);
      runtest("TCP Client: Obtain userlist",tcp_client_userlist);
      runtest("TCP Client: Count Messages",tcp_client_messagecount);
      runtest("TCP Client: Send to the server",tcp_client_sendtoserver);
      runtest("TCP Client: Send to one user",tcp_client_sendtoone);
      runtest("TCP Client: Send to all other users",tcp_client_sendtoallother);
      runtest("TCP Client: Send to all users",tcp_client_sendtoall);
      
      runtest("TCP Client: Test Message via callbacks",tcp_client_callbacks);
      
      runtest("TCP Client: Ping test",tcp_client_ping);
      
      runtest("TCP Client: Create a group",tcp_client_groupcreate);
      
      runtest("TCP Client: Obtain grouplist",tcp_client_grouplist);
      runtest("TCP Client: Obtain grouplist from other client",tcp_client_grouplistother);
      
      runtest("TCP Client: Add a user to a group",tcp_client_groupadd);
      
      runtest("TCP Client: Obtain groupmemberlist",tcp_client_groupmemberlist);
      runtest("TCP Client: Obtain groupmemberlist from other client",tcp_client_groupmemberlistother);
      
      runtest("TCP Client: Group Enumeration",tcp_client_groupenum);
      runtest("TCP Client: Groupmember Enumeration",tcp_client_groupmemberenum);
      
      runtest("TCP Client: Send to a group",tcp_client_sendtogroup);
      runtest("TCP Client: Send to a group containing a group",tcp_client_sendtogroupgroup);
      
      
      runtest("TCP Client: Remove a user from a group",tcp_client_groupremove);
      runtest("TCP Client: Delete a group",tcp_client_groupdelete);
      
      runtest("TCP Client: Send with Confirm to the server",tcp_client_sendconfirmserver);
      runtest("TCP Client: Send with Confirm to one user",tcp_client_sendconfirmone);
      runtest("TCP Client: Send with Confirm to everyone",tcp_client_sendconfirmall);
      runtest("TCP Client: Send with Confirm to everyone else",tcp_client_sendconfirmallother);
      runtest("TCP Client: Send with Confirm to a group",tcp_client_sendconfirmgroup);
      runtest("TCP Client: Send with Confirm to a group containing a group",tcp_client_sendconfirmgroupgroup);

      runtest("TCP Client: Test Synchronised int",tcp_client_sync_int);
      runtest("TCP Client: Test Synchronised double",tcp_client_sync_double);
      runtest("TCP Client: Test Synchronised data",tcp_client_sync_data);

      runtest("TCP Encryption: Connect with no supplied keys",tcp_encyption_connect_nokeys);
      runtest("TCP Encryption: Connect with server only has key",tcp_encyption_connect_serverkeys);
      runtest("TCP Encryption: Connect with client only has key",tcp_encyption_connect_clientkeys);
      runtest("TCP Encryption: Connect with both sides with a key",tcp_encyption_connect_bothkeys);

      runtest("TCP Encryption: Connect with keys and client valid ca",tcp_encyption_connect_clientkeysca);
      runtest("TCP Encryption: Connect with keys and server valid ca",tcp_encyption_connect_serverkeysca);

      //runtest("TCP Encryption: Connect with keys and client bad ca",tcp_encyption_connect_clientkeysbadca);
      //runtest("TCP Encryption: Connect with keys and server bad ca",tcp_encyption_connect_serverkeysbadca);

      ///////////////////SERVERS UDP
      runtest("UDP: Connect a client to a server",udp_basicconnect);
      runtest("UDP Server: Pull Messages",udp_server_messagepull);
      runtest("UDP Client: Pull Messages",udp_client_messagepull);
      
      runtest("UDP: Fail to connect a client to a different server",udp_basicfailconnect);
      
      runtest("UDP Server: Detect server running",udp_server_detectrunning);
      runtest("UDP Server: Stop and restart a server",udp_server_restart);
      
      //Out of order, need to test first
      runtest("UDP Client: Detect if client connected",udp_client_connected);
      
      runtest("UDP Server: Connected user enumeration",udp_server_userenumeraion);
      runtest("UDP Server: Set maximum connected users",udp_server_maxusers);
      runtest("UDP Server: Set closed",udp_server_closed);
      
      runtest("UDP Server: Set description",udp_server_description);

      runtest("UDP Server: Get current user count",udp_server_usercount);
      
      runtest("UDP Server: Obtain userlist",udp_server_userlist);
      
      runtest("UDP Server: Test server password",udp_server_password);
      
      runtest("UDP Server: Count Messages",udp_server_messagecount);
      
      runtest("UDP Server: Send to one user",udp_server_messagetoone);
      runtest("UDP Server: Send to all users",udp_server_messagetoall);

      runtest("UDP Server: Test Message via callbacks",udp_server_callbacks);

      runtest("UDP Server: Disconnect a client",udp_server_disconnectclient);
      
      runtest("UDP Server: Ping test",udp_server_ping);
      runtest("UDP Server: Autoping test",udp_server_autoping);
      
      runtest("UDP Server: Create a group",udp_server_newgroup);
      
      runtest("UDP Server: Obtain grouplist",udp_server_grouplist);
      runtest("UDP Server: Obtain grouplist from client",udp_server_clientgrouplist);
      
      runtest("UDP Server: Add a user to a group",udp_server_addgroup);
      
      runtest("UDP Server: Obtain groupmemberlist",udp_server_groupmemberlist);
      runtest("UDP Server: Obtain groupmemberlist from client",udp_server_groupmemberlistclient);
      
      runtest("UDP Server: Group Enumeration",udp_server_groupenum);
      runtest("UDP Server: Groupmember Enumeration",udp_server_groupmemberenum);
      
      runtest("UDP Server: Send to a group",udp_server_sendgroup);
      runtest("UDP Server: Send to a group containing a group",udp_server_sendgroupgroup);
      
      runtest("UDP Server: Remove a user from a group",udp_server_removegroup);
      runtest("UDP Server: Delete a group",udp_server_deletegroup);
      
      runtest("UDP Server: Send with Confirm to one user",udp_server_sendconfirmone);
      runtest("UDP Server: Send with Confirm to everyone",udp_server_sendconfirmeveryone);
      runtest("UDP Server: Send with Confirm to a group",udp_server_sendconfirmgroup);
      runtest("UDP Server: Send with Confirm to a group containing a group",udp_server_sendconfirmgroupgroup);
      
      ///////////////////CLIENTS UDP
      
      runtest("UDP Client: Stop and restart a client",udp_client_restart);
      
      runtest("UDP Client: Connected user enumeration",udp_client_enumusers);
      
      runtest("UDP Client: Change Name",udp_client_changename);
      
      runtest("UDP Client: Obtain userlist",udp_client_userlist);
      
      runtest("UDP Client: Count Messages",udp_client_messagecount);
      
      runtest("UDP Client: Send to the server",udp_client_sendtoserver);
      runtest("UDP Client: Send to one user",udp_client_sendtoone);
      runtest("UDP Client: Send to all other users",udp_client_sendtoallother);
      runtest("UDP Client: Send to all users",udp_client_sendtoall);
      
      runtest("UDP Client: Test Message via callbacks",udp_client_callbacks);
      
      runtest("UDP Client: Ping test",udp_client_ping);
      
      runtest("UDP Client: Create a group",udp_client_groupcreate);
      
      runtest("UDP Client: Obtain grouplist",udp_client_grouplist);
      runtest("UDP Client: Obtain grouplist from other client",udp_client_grouplistother);
      
      runtest("UDP Client: Add a user to a group",udp_client_groupadd);
      
      runtest("UDP Client: Obtain groupmemberlist",udp_client_groupmemberlist);
      runtest("UDP Client: Obtain groupmemberlist from other client",udp_client_groupmemberlistother);
      
      runtest("UDP Client: Group Enumeration",udp_client_groupenum);
      
      
      runtest("UDP Client: Groupmember Enumeration",udp_client_groupmemberenum);
      runtest("UDP Client: Send to a group",udp_client_sendtogroup);
      runtest("UDP Client: Send to a group containing a group",udp_client_sendtogroupgroup);
      
      runtest("UDP Client: Remove a user from a group",udp_client_groupremove);
      runtest("UDP Client: Delete a group",udp_client_groupdelete);
      
      runtest("UDP Client: Send with Confirm to the server",udp_client_sendconfirmserver);
      runtest("UDP Client: Send with Confirm to one user",udp_client_sendconfirmone);
      runtest("UDP Client: Send with Confirm to everyone",udp_client_sendconfirmall);
      runtest("UDP Client: Send with Confirm to everyone else",udp_client_sendconfirmallother);
      runtest("UDP Client: Send with Confirm to a group",udp_client_sendconfirmgroup);
      runtest("UDP Client: Send with Confirm to a group containing a group",udp_client_sendconfirmgroupgroup);

      runtest("UDP Client: Test Synchronised int",udp_client_sync_int);
      runtest("UDP Client: Test Synchronised double",udp_client_sync_double);
      runtest("UDP Client: Test Synchronised data",udp_client_sync_data);

      ///////////////////LOBBY
      
      runtest("Lobby: Connect a client to a server",lobby_basicconnect);
      runtest("Lobby Client: Getting a message",lobbyclient_getmessage);
      
      runtest("Lobby Client: Creating a room",lobbyclient_roomcreate);
      runtest("Lobby Client: Getting a list of users in the room",lobbyclient_roomusers);
      runtest("Lobby Client: Getting a list of rooms",lobbyclient_roomlist);
      runtest("Lobby Client: Joining a room",lobbyclient_roomjoin);
      runtest("Lobby Client: Leaving a room",lobbyclient_leaveroombasic);
      runtest("Lobby Client: Leaving a room (not last out)",lobbyclient_leaveroomnotlast);
      runtest("Lobby Client: Leaving a room (last out)",lobbyclient_leaveroomlast);
      runtest("Lobby Client: Room chat in main room",lobbyclient_mainchat);
      runtest("Lobby Client: Room chat in other room",lobbyclient_otherchat);

      runtest("Lobby Client: Room chat in different rooms",lobbyclient_differentchat);
      runtest("Lobby Client: Registering a game",lobbyclient_gameregister);

      runtest("Lobby Client: Getting a list of games in the room",lobbyclient_gamelist);
      runtest("Lobby Client: Joining a game",lobbyclient_gamejoin);
      runtest("Lobby Client: Testing game server submessage thread",lobbyclient_gameserversubthread);

      runtest("Lobby Client: Leaving a game",lobbyclient_leavegame);
      runtest("Lobby Client: Testing game client submessage thread",lobbyclient_gameclientsubthread);
      runtest("Lobby Client: Finishing a game (nobody connected)",lobbyclient_finishgameempty);
      runtest("Lobby Client: Finishing a game (people connected)",lobbyclient_finishgamefull);
      runtest("Lobby Client: Starting a game in a room",lobbyclient_gamestartroom);
      runtest("Lobby Client: Leaving a room (last out, game running)",lobbyclient_leaveroomlastbutgame);
      runtest("Lobby Client: Disconnect with game running",lobbyclient_gameserverdisconnect);

      runtest("Lobby Client: Messages via callback",lobbyclient_callbacks);
      /**/

      gettimeofday(&endtime,NULL);
      
      printf("%d passes\n",loopa);
      
      diff.tv_sec=endtime.tv_sec-thislooptime.tv_sec;
      diff.tv_usec=endtime.tv_usec-thislooptime.tv_usec;
      while (diff.tv_usec < 0)
	{
	  diff.tv_usec+=1000000;
	  diff.tv_sec--;
	}
      
      printf("This pass:          %5ld.%.06ld seconds\n",diff.tv_sec,diff.tv_usec);
      
      diff.tv_sec=endtime.tv_sec-starttime.tv_sec;
      diff.tv_usec=endtime.tv_usec-starttime.tv_usec;
      while (diff.tv_usec < 0)
	{
	  diff.tv_usec+=1000000;
	  diff.tv_sec--;
	}
      
      printf("Total time taken:   %5ld.%.06ld seconds\n",diff.tv_sec,diff.tv_usec);
      
      dtime=(double)diff.tv_sec / loopa;
      diff.tv_sec /= loopa;
      diff.tv_usec /=loopa;
      diff.tv_usec+=((dtime-diff.tv_sec)*1000000);
      
      printf("Average time taken: %5ld.%.06ld seconds\n",diff.tv_sec,diff.tv_usec);
      
      printf("RESULT: %d pass, %d fail\n",staticpass,staticfail);
    }
  
  return 0;
}
