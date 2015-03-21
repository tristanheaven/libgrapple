#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "test.h"
#include "../src/tools.h"
#include "grapple.h"

extern char *strdup(const char *);

serveruser *serverusers[10];
clientuser *clientusers[10];

char globalquestion='A';

static int datafound(basedata *data)
{
  if (!data->name)
    return 0;

  if (!data->serveraddr)
    return 0;
  
  if (!data->serverport)
    return 0;

  return 1;
}

static int getData(basedata *data)
{
  int inchar;
  int maxlen=0;
  char *ptr;
  char intbuf[30];

  mvprintw(1,1,"Name : ");
  if (!data->name)
    {
      mvprintw(1,8,data->indata);

      mvprintw(1,8+strlen(data->indata),"  ");
      
      maxlen=20;
    }
  else
    {
      mvprintw(1,8,data->name);

      mvprintw(2,1,"Addr : ");
      if (!data->serveraddr)
	{
	  mvprintw(2,8,data->indata);
	  
	  mvprintw(2,8+strlen(data->indata),"  ");
	  
	  maxlen=70;
	}
      else
	{
	  if (!strcmp(data->serveraddr," "))
	    mvprintw(2,8,"Running Server");
	  else
	    mvprintw(2,8,data->serveraddr);
	  
	  mvprintw(3,1,"Port : ");
	  if (!data->serverport)
	    {
	      mvprintw(3,8,data->indata);
	      
	      mvprintw(3,8+strlen(data->indata),"  ");
	      
	      maxlen=5;
	    }
	  else
	    {
	      sprintf(intbuf,"%d",data->serverport);
	      mvprintw(3,8,intbuf);
	    }
	}
    }

  mvprintw(LINES-1,COLS-1,(char *)"");
  refresh();

  inchar=getch();

  if (inchar==ERR || !inchar)
    return 0;

  ptr=strchr(data->indata,0);

  if (inchar==8 || inchar==127)
    {
      if (ptr > data->indata)
	{
	  ptr--;
	  *ptr=0;
	}
      return 1;
    }

  if ((char)inchar=='\n')
    {
      if (!data->name)
	{
	  if (*data->indata)
	    {
	      data->name=strdup(data->indata);
	      data->indata[0]=0;
	    }
	  return 1;
	}
      if (!data->serveraddr)
	{
	  if (*data->indata)
	    {
	      data->serveraddr=strdup(data->indata);
	      data->indata[0]=0;
	    }
	  else
	    {
	      data->serveraddr=strdup(" ");
	    }
	  return 1;
	}
      if (!data->serverport)
	{
	  if (*data->indata)
	    {
	      data->serverport=atoi(data->indata);
	      data->indata[0]=0;
	    }
	  return 1;
	}
    }


  if (!isprint((char)inchar))
    return 0;

  if (ptr-data->indata>maxlen)
    return 0;

  *ptr++=(char)inchar;
  *ptr=0;

  return 0;
}

static int client_add_user(grapple_message *message,int me)
{
  int loopa;

  for (loopa=0;loopa<10;loopa++)
    {
      if (clientusers[loopa]->id==0)
	{
	  clientusers[loopa]->id=message->NEW_USER.id;
	  clientusers[loopa]->me=message->NEW_USER.me;
	  return 1;
	}
    }
  return 0;
}

static int client_user_name(grapple_message *message)
{
  int loopa;

  for (loopa=0;loopa<10;loopa++)
    {
      if (clientusers[loopa]->id==message->USER_NAME.id)
	{
	  if (clientusers[loopa]->name)
	    free(clientusers[loopa]->name);
	  clientusers[loopa]->name=
	    (char *)malloc(strlen(message->USER_NAME.name)+1);
	  strcpy(clientusers[loopa]->name,message->USER_NAME.name);
	  return 1;
	}
    }
  return 0;
}

static int client_message(grapple_message *message)
{
  int loopa;
  intchar val;

  memcpy(val.c,message->USER_MSG.data,4);
  if (val.i==0)
    {
      globalquestion=((char *)message->USER_MSG.data)[4];

      //Its the next question
    }
  else
    {
      //Setting someones score
      for (loopa=0;loopa<10;loopa++)
	{
	  if (clientusers[loopa]->id==val.i)
	    {
	      memcpy(val.c,message->USER_MSG.data+4,4);
	      
	      clientusers[loopa]->score=val.i;

	      return 1;
	    }
	}
    }
  return 0;
}

static int client_disconnected(grapple_message *message)
{
  int loopa;

  for (loopa=0;loopa<10;loopa++)
    {
      if (clientusers[loopa]->id==message->USER_DISCONNECTED.id)
	{
	  if (clientusers[loopa]->name)
	    {
	      free(clientusers[loopa]->name);
	      clientusers[loopa]->name=0;
	    }
	  clientusers[loopa]->id=0;
	  clientusers[loopa]->score=0;

	  return 1;
	}
    }
  return 0;
}

static int handle_client_loop(grapple_client client)
{
  grapple_message *message;

  while (grapple_client_messages_waiting(client))
    {
      message=grapple_client_message_pull(client);

      switch (message->type)

	{
	case GRAPPLE_MSG_NEW_USER:
	  client_add_user(message,0);
	  break;
	case GRAPPLE_MSG_NEW_USER_ME:
	  client_add_user(message,1);
	  break;
	case GRAPPLE_MSG_USER_NAME:
	  client_user_name(message);
	  break;
	case GRAPPLE_MSG_USER_MSG:
	  client_message(message);
	  break;
	case GRAPPLE_MSG_USER_DISCONNECTED:
	  client_disconnected(message);
	  break;
	case GRAPPLE_MSG_SERVER_DISCONNECTED:
	case GRAPPLE_MSG_CONNECTION_REFUSED:
	  endwin();
	  exit(0);
	  break;
	case GRAPPLE_MSG_SESSION_NAME:
	case GRAPPLE_MSG_PING:
	  break;
	}
      grapple_message_dispose(message);
    }
  return 1;
}

static int server_add_user(int userid)
{
  int loopa;
  for (loopa=0;loopa<10;loopa++)
    {
      if (serverusers[loopa]->id==0)
	{
	  serverusers[loopa]->id=userid;
	  return 1;
	}
    }
  return 0;
}

static int server_message(grapple_message *message)
{
  int loopa;
  for (loopa=0;loopa<10;loopa++)
    {
      if (serverusers[loopa]->id==message->USER_MSG.id)
	{
	  serverusers[loopa]->answer=((char *)message->USER_MSG.data)[0];
	  gettimeofday(&serverusers[loopa]->answerat,NULL);
	  return 1;
	}
    }
  

  return 0;
}

static int server_disconnected(grapple_message *message)
{
  int loopa;

  for (loopa=0;loopa<10;loopa++)
    {
      if (serverusers[loopa]->id==message->USER_DISCONNECTED.id)
	{
	  serverusers[loopa]->id=0;
	  serverusers[loopa]->score=0;

	  return 1;
	}
    }
  return 0;
}

static int handle_server_loop(grapple_client server)
{
  grapple_message *message;
  static struct timeval lastval;
  static char question=0;
  struct timeval tv;
  int v1,v2,loopa;
  char data[128];
  intchar val;

  if (!question)
    {
      srand(time(NULL));
      question='a';
      lastval.tv_sec=0;
      lastval.tv_usec=0;
    }

  while (grapple_server_messages_waiting(server))
    {
      message=grapple_server_message_pull(server);

      switch (message->type)
	{
	case GRAPPLE_MSG_NEW_USER:
	  server_add_user(message->NEW_USER.id);
	  break;
	case GRAPPLE_MSG_USER_NAME:
	  //We dont care for this server
	  break;
	case GRAPPLE_MSG_USER_MSG:
	  server_message(message);
	  break;
	case GRAPPLE_MSG_USER_DISCONNECTED:
	  server_disconnected(message);
	  break;
	case GRAPPLE_MSG_NEW_USER_ME:
	case GRAPPLE_MSG_SERVER_DISCONNECTED:
	case GRAPPLE_MSG_CONNECTION_REFUSED:
	case GRAPPLE_MSG_SESSION_NAME:
	  //NEVER HAPPENS TO THE SERVER
	case GRAPPLE_MSG_PING:
	  //Not used in this test
	  break;
	}
      grapple_message_dispose(message);
    }

  gettimeofday(&tv,NULL);


  if ((tv.tv_sec==lastval.tv_sec+1 && tv.tv_usec>=lastval.tv_usec) ||
      tv.tv_sec>lastval.tv_sec+1)
    {
      //Current winners and losers
	
      for (loopa=0;loopa<10;loopa++)
	{
	  if (serverusers[loopa]->id)
	    {
	      if (serverusers[loopa]->answer!=question)
		{
		  serverusers[loopa]->score-=20;
		  if (serverusers[loopa]->score<0)
		    serverusers[loopa]->score=0;
		}
	      else
		{
		  v1=serverusers[loopa]->answerat.tv_sec-lastval.tv_sec;
		  v1*=100;
		  v2=serverusers[loopa]->answerat.tv_usec-lastval.tv_usec;
		  v2/=10000;
		  v1+=v2;

		  v1=100-v1;
		  if (v1<1)
		    v1=1;
		    
		  serverusers[loopa]->score+=v1;
		}
	      serverusers[loopa]->answer=0;
	      val.i=serverusers[loopa]->id;
	      memcpy(data,val.c,4);
	      val.i=serverusers[loopa]->score;
	      memcpy(data+4,val.c,4);
	      grapple_server_send(server,GRAPPLE_EVERYONE,0,data,8);
	    }
	}

      //Generate a new value
      question='A'+(rand()%26);

      lastval.tv_sec=tv.tv_sec;
      lastval.tv_usec=tv.tv_usec;
      val.i=0;
      memcpy(data,val.c,4);
      data[4]=question;
      grapple_server_send(server,GRAPPLE_EVERYONE,0,data,5);
    }

  return 1;
}

static int run_main_loop(grapple_server server,grapple_client client)
{
  char buf[80];
  int loopa,inchar;
  static int frames=0;

  if (server)
    {
      handle_server_loop(server);
    }

  handle_client_loop(client);

  for (loopa=0;loopa<10;loopa++)
    {
      if (clientusers[loopa]->id)
	{
	  if (clientusers[loopa]->name)
	    sprintf(buf," %-30s %10d",
		    clientusers[loopa]->name,clientusers[loopa]->score);
	  else
	    sprintf(buf," Unknown - %-20d %10d",
		    clientusers[loopa]->id,clientusers[loopa]->score);
	  
	  if (clientusers[loopa]->me)
	    buf[0]='*';
	  
	  mvprintw(loopa,0,buf);
	}
      else
	{
	  sprintf(buf,"%79s"," ");
	  mvprintw(loopa,0,buf);
	}
    }

  sprintf(buf,"-=> %c <=-",globalquestion);
  mvprintw(15,(COLS/2)-5,buf);

  frames++;

  sprintf(buf,"%d",frames);
  mvprintw(LINES-1,0,buf);

  mvprintw(LINES-1,COLS-1,(char *)"");
  refresh();

  inchar=getch();

  if (inchar==ERR || !inchar)
    return 0;

  if (isalpha(inchar))
    {
      buf[0]=toupper(inchar);
      //Send the value to the server
      grapple_client_send(client,GRAPPLE_SERVER,0,buf,1);
    }
  else if (inchar=='1')
    return 1;

  return 0;
}

int main(int argc,char **argv)
{
  WINDOW *win;
  basedata *data;
  grapple_server server=0;
  grapple_client client=0;
  grapple_error error;
  int finished=0,loopa;

  win=initscr();
  cbreak();
  noecho();
  halfdelay(1);

  clear();
  refresh();

  data=(basedata *)calloc(1,sizeof(basedata));

  while (!datafound(data))
    {
      getData(data);
    }

  /*Now do network things*/

  if (!strcmp(data->serveraddr," "))
    {
      //We're running a server, create one

      server=grapple_server_init("testgame","1");
      grapple_server_port_set(server,data->serverport);
      grapple_server_protocol_set(server,GRAPPLE_PROTOCOL_UDP);
      grapple_server_session_set(server,"Join my game");
      grapple_server_start(server);
      
      client=grapple_client_init("testgame","1");
      grapple_client_address_set(client,NULL);
      grapple_client_port_set(client,data->serverport);
      grapple_client_protocol_set(client,GRAPPLE_PROTOCOL_UDP);
      grapple_client_start(client,0);
    }
  else
    {
      client=grapple_client_init("testgame","1");
      grapple_client_address_set(client,data->serveraddr);
      grapple_client_port_set(client,data->serverport);
      grapple_client_protocol_set(client,GRAPPLE_PROTOCOL_UDP);
      grapple_client_start(client,0);
    }

  if (server)
    {
      for (loopa=0;loopa<10;loopa++)
	serverusers[loopa]=(serveruser *)calloc(1,sizeof(serveruser));
    }

  for (loopa=0;loopa<10;loopa++)
    clientusers[loopa]=(clientuser *)calloc(1,sizeof(clientuser));

  grapple_client_name_set(client,data->name);

  clear();
  refresh();

  error=grapple_client_error_get(client);
  if (error)
    {
      endwin();
      printf("Error: %s\n",grapple_error_text(error));
      return 0;
    }

  while (!finished)
    {
      finished=run_main_loop(server,client);
    }

  if (server)
    grapple_server_destroy(server);

  grapple_client_destroy(client);
  
  endwin();

  return 0;
}
