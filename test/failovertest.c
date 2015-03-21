#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "grapple.h"

int main(int argc,char **argv)
{
  int isserver=0;
  grapple_client client=0;
  grapple_server server;
  grapple_message *message;
  int lastadd=0;
  int loopa=0,group=0,groupcount=0;

  if (argc<2)
    {
      printf("Usage: %s [server|client]\n",argv[0]);
      return 0;
    }
  
  if (!strcmp("server",argv[1]))
    isserver=1;

  if (isserver)
    {

      server=grapple_server_init("testgame","1");
      grapple_server_port_set(server,1234);
      grapple_server_protocol_set(server,GRAPPLE_PROTOCOL_UDP);
      grapple_server_session_set(server,"Play my game");
      if (grapple_server_start(server)!=GRAPPLE_OK)
	{
	  printf("SERVER FAILED: %s\n",
		 grapple_error_text(grapple_server_error_get(server)));
	  return 0;
	}
      
      printf("SERVER STARTED\n");
    }

  //Start a client
  client=grapple_client_init("testgame","1");
  grapple_client_address_set(client,"81.168.26.50");
  grapple_client_port_set(client,1234);
  grapple_client_protocol_set(client,GRAPPLE_PROTOCOL_UDP);
  if (grapple_client_start(client,0)!=GRAPPLE_OK)
    {
      printf("CLIENT FAILED: %s\n",
	     grapple_error_text(grapple_client_error_get(client)));
      return 0;
    }
  grapple_client_name_set(client,"Player");

  

  printf("CLIENT STARTED\n");

  if (isserver)
    {
      group=grapple_client_group_create(client,"tester");
      printf("Group %d formed\n",group);
    }

  while (1)
    {
      loopa++;
      if (grapple_client_messagecount_get(client))
	{
	  message=grapple_client_message_pull(client);

	  switch (message->type)
	    {
	    case GRAPPLE_MSG_NEW_USER:
	      printf("MESSAGE: New User %d\n",message->NEW_USER.id);
	      if (isserver)
		{
		  if (groupcount==0)
		    lastadd=message->NEW_USER.id;
		  else
		    {
		      grapple_client_group_add(client,group,message->NEW_USER.id);
		      grapple_client_group_add(client,group,lastadd);
		    }
		  groupcount++;
		}
	      break;
	    case GRAPPLE_MSG_NEW_USER_ME:
	      printf("MESSAGE: New User Me\n");
	      break;
	    case GRAPPLE_MSG_USER_NAME:
	      printf("MESSAGE: User Name\n");
	      break;
	    case GRAPPLE_MSG_USER_MSG:
	      printf("MESSAGE: User Message %d bytes long\n",message->USER_MSG.length);
	      break;
	    case GRAPPLE_MSG_SESSION_NAME:
	      printf("MESSAGE: Session Name\n");
	      break;
	    case GRAPPLE_MSG_USER_DISCONNECTED:
	      printf("MESSAGE: User Disconnected %d\n",message->USER_DISCONNECTED.id);
	      break;
	    case GRAPPLE_MSG_SERVER_DISCONNECTED:
	      printf("MESSAGE: Server Disconnected\n");
	      break;
	    case GRAPPLE_MSG_CONNECTION_REFUSED:
	      printf("MESSAGE: Connection Refused\n");
	      break;
	    case GRAPPLE_MSG_PING:
	      printf("MESSAGE: Ping\n");
	      break;
	    case GRAPPLE_MSG_GROUP_CREATE:
	      printf("MESSAGE: Group %s (%d) Created\n",
		     message->GROUP.name,message->GROUP.groupid);
	      break;
	    case GRAPPLE_MSG_GROUP_ADD:
	      printf("MESSAGE: Group Add user %d to group %d\n",
		     message->GROUP.memberid,message->GROUP.groupid);
	      break;
	    case GRAPPLE_MSG_GROUP_REMOVE:
	      printf("MESSAGE: Group Remove\n");
	      break;
	    case GRAPPLE_MSG_GROUP_DELETE:
	      printf("MESSAGE: Group Delete\n");
	      break;
	    case GRAPPLE_MSG_YOU_ARE_HOST:
	      printf("MESSAGE: You are Host\n");
	      break;
	    case GRAPPLE_MSG_CONFIRM_RECEIVED:
	      printf("MESSAGE: Confirm received message %d\n",message->CONFIRM.messageid);
	      break;
	    case GRAPPLE_MSG_CONFIRM_TIMEOUT:
	      printf("MESSAGE: Confirm timeout message\n");
	      break;
	    }
	  grapple_message_dispose(message);
	}
      else
	sleep (1);

      if (isserver && groupcount==2)
	{
	  printf("Now sending a test message\n");
	  //Send a test message to the group
	  grapple_client_send(0,group,GRAPPLE_RELIABLE,(char *)"hello",5);
	  groupcount=0;
	}
    }


  return 0;
}
