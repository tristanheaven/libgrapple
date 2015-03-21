#include <stdio.h>
#include <string.h>

#include "../src/socket.h"

static int count_rlist(socket_udp_rdata *list)
{
  int count=0;
  socket_udp_rdata *scan;
	
  scan=list;

  while (scan)
    {
      count++;
      scan=scan->next;
      if (scan==list)
	scan=0;
    }
  return count;
}

int main(int argc,char **argv)
{
  socketbuf *server,*client,*clientserverside=0;
  socket_processlist *list=0;
  int loopa;
  socket_intchar val;
  socket_udp_data *data;

  server=socket_create_inet_udp2way_listener(2111);
  client=socket_create_inet_udp2way_wait("argh",2111,1);

  list=socket_link(list,server);
  list=socket_link(list,client);

  loopa=0;
  while (1)
    {
      /*
      {
	printf("client in %d\n",
	       count_rlist(client->udp2w_rdata_in));
	printf("client out %d\n",
	       count_rlist(client->udp2w_rdata_out));
	
      if (clientserverside)
	{
	  printf("clientSS in %d\n",
		 count_rlist(clientserverside->udp2w_rdata_in));
	  printf("clientSS out %d\n",
		 count_rlist(clientserverside->udp2w_rdata_out));
	}
      }
      */

      loopa++;
      val.i=loopa;
      socket_write_reliable(client,val.c,4);
      //socket_write(client,val.c,4);

      socket_process_sockets(list,0);

      if (clientserverside)
	{
	  data=socket_udp_indata_pull(clientserverside);

	  if (data)
	    {
	      if (data->length==4)
		{
		  memcpy(val.c,data->data,4);
		  if (val.i%10000==0)
		    printf("DATA=%d\n",val.i);
		  
		  if (clientserverside)
		    {
		      val.i+=256;
		      socket_write_reliable(clientserverside,val.c,4);
		      //socket_write(clientserverside,val.c,4);
		    }
		}
	      socket_udp_data_free(data);
	    }
	}

      if (!clientserverside)
	{
	  clientserverside=socket_new(server);
	  if (clientserverside)
	    {
	      list=socket_link(list,clientserverside);
	    }
	}

      data=socket_udp_indata_pull(client);
      if (data)
	{
	  if (data->length==4)
	    {
	      memcpy(val.c,data->data,4);
	      if (val.i%10000==0)
		printf("BACK=%d\n",val.i);
	    }
	  
	  socket_udp_data_free(data);
	}
    }

  return 0;
}
