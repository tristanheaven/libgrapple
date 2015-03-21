#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "grapple.h"
#include "grapple_lobby.h"

int main(int argc,char **argv)
{
  int isserver=0;
  grapple_lobbyclient client=0;
  grapple_lobby server;
  grapple_server clientserver;
  grapple_lobbymessage *message;
  int loopa=0,target;
  char name[128];

  if (argc<2)
    {
      printf("Usage: %s [server|client]\n",argv[0]);
      return 0;
    }
  
  if (!strcmp("server",argv[1]))
    isserver=1;

  if (isserver)
    {
      server=grapple_lobby_init("testgame","1");
      grapple_lobby_port_set(server,1234);
      if (grapple_lobby_start(server)!=GRAPPLE_OK)
	{
	  printf("SERVER FAILED: %s\n",
		 grapple_error_text(grapple_lobby_error_get(server)));
	  return 0;
	}
      
      printf("SERVER STARTED\n");
    }

  //Start a client
  client=grapple_lobbyclient_init("testgame","1");
  grapple_lobbyclient_address_set(client,"81.168.26.50");
  grapple_lobbyclient_port_set(client,1234);
  srand(time(NULL));
  sprintf(name,"Player %d\n",rand()%1000000);
  grapple_lobbyclient_name_set(client,name);

  if (grapple_lobbyclient_start(client)!=GRAPPLE_OK)
    {
      printf("CLIENT FAILED: %s\n",
	     grapple_error_text(grapple_lobbyclient_error_get(client)));
      return 0;
    }

  printf("CLIENT STARTED\n");


  target=loopa+rand()%10;

  while (1)
    {
      loopa++;

      message=grapple_lobbyclient_message_pull(client);

      if (message)
	{
	  switch (message->type)
	    {
	    case GRAPPLE_LOBBYMSG_ROOMLEAVE:
	      printf("MESSAGE: %d left the room\n",message->ROOM.roomid);
	      break;
	    case GRAPPLE_LOBBYMSG_ROOMENTER:
	      printf("MESSAGE: %d entered the room\n",message->ROOM.roomid);
	      break;
	    case GRAPPLE_LOBBYMSG_ROOMCREATE:
	      printf("MESSAGE: created room %s\n",message->ROOM.name);
	      break;
	    case GRAPPLE_LOBBYMSG_ROOMDELETE:
	      printf("MESSAGE: removed room %s\n",message->ROOM.name);
	      break;
	    case GRAPPLE_LOBBYMSG_CHAT:
	      printf("MESSAGE: %d said %s\n",message->CHAT.id,
		     message->CHAT.message);
	      break;
	    case GRAPPLE_LOBBYMSG_NEWGAME:
	      printf("MESSAGE: New Game %d - %s\n",message->GAME.id,
		     message->GAME.name);
	      break;
	    case GRAPPLE_LOBBYMSG_DISCONNECTED:
	      printf("MESSAGE: DISCONNECT\n");
	      break;
	    }
	  grapple_lobbymessage_dispose(message);
	}
      else
	sleep (1);

      if (!isserver)
	{
	  if (loopa==15)
	    {
	      clientserver=grapple_server_init("testgame","1");
	      grapple_server_port_set(clientserver,12345);
	      grapple_server_protocol_set(clientserver,GRAPPLE_PROTOCOL_UDP);
	      grapple_server_session_set(clientserver,"Play my game");
	      grapple_server_start(clientserver);

	      printf("Registration returned %d\n",
		     grapple_lobbyclient_game_register(client,clientserver));
	    }
	}
    }


  return 0;
}
