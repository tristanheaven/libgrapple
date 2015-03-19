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
#include <string.h>
#include <stdio.h>

#include "grapple_confirm.h"
#include "grapple_structs.h"
#include "grapple_comms_api.h"

//Create the confirm data
static grapple_confirm *grapple_confirm_aquire(void)
{
  grapple_confirm *returnval;

  returnval=(grapple_confirm *)calloc(1,sizeof(grapple_confirm));
  
  //By default add space for 50 receivers. If we need more this will expand
  //dynamically, but it isnt really likely.
  returnval->maxreceiver=50;
  returnval->receivers=(int *)malloc(50*sizeof(int));

  returnval->confirm_mutex=grapple_thread_mutex_init();

  return returnval;
}

//Delete the confirm struct and all memory associated with it
int grapple_confirm_dispose(grapple_confirm *target)
{
  free(target->receivers);

  grapple_thread_mutex_destroy(target->confirm_mutex);

  free(target);

  return 1;
}

//Link a confirm struct into a list of confirm structs
static grapple_confirm *grapple_confirm_link(grapple_confirm *list,
					     grapple_confirm *item)
{
  if (!list)
    {
      item->next=item;
      item->prev=item;
      return item;
    }

  item->next=list;
  item->prev=list->prev;

  item->next->prev=item;
  item->prev->next=item;

  return list;
}

//Unlink a confirm struct from a list of confirm structs
grapple_confirm *grapple_confirm_unlink(grapple_confirm *list,
					grapple_confirm *item)
{
  if (list->next==list)
    {
      return NULL;
    }

  item->next->prev=item->prev;
  item->prev->next=item->next;

  if (item==list)
    list=item->next;

  return list;
}

//Locate a confirm struct inside a list by its ID
static grapple_confirm *locate_confirm_message(grapple_confirm *list,
					       int messageid)
{
  grapple_confirm *scan;

  scan=list;

  while (scan)
    {
      if (scan->messageid==messageid)
	//IDs match, return the confirm
	return scan;

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  return NULL;
}

//Find the index in the int array of a specific receiver of a message
static int locate_confirm_message_receiver_index(grapple_confirm *confirm,
						 int target)
{
  int loopa;

  grapple_thread_mutex_lock(confirm->confirm_mutex,GRAPPLE_LOCKTYPE_SHARED);

  for (loopa=0;loopa<confirm->receivercount;loopa++)
    {
      if (confirm->receivers[loopa]==target)
	{
	  //Matches, return the index
	  grapple_thread_mutex_unlock(confirm->confirm_mutex);
	  return loopa;
	}
    }
     
  grapple_thread_mutex_unlock(confirm->confirm_mutex);

  //No match, return -1
  return -1;
}

//Add a new receiver to the int array
static int confirm_message_add_receiver(grapple_confirm *confirm,int target)
{
  //Incriment the count

  grapple_thread_mutex_lock(confirm->confirm_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  confirm->receivercount++;
  //If we dont have enough space, add more
  if (confirm->receivercount>confirm->maxreceiver)
    {
      confirm->maxreceiver*=2;
      confirm->receivers=(int *)realloc(confirm->receivers,
					confirm->maxreceiver*(sizeof(int)));
    }

  //Set the value into the array  
  confirm->receivers[confirm->receivercount-1]=target;

  grapple_thread_mutex_unlock(confirm->confirm_mutex);

  return 1;
}

//Remove a message from a confirm struct
static int confirm_message_remove_receiver(grapple_confirm *confirm,int target)
{
  int found=0,loopa,loopend;

  grapple_thread_mutex_lock(confirm->confirm_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  loopend=confirm->receivercount-1;

  //Loop through each one, if we have found the match start moving the rest
  //back one. Originally done with memmove but memmove had some issues
  for (loopa=0;loopa < loopend;loopa++)
    {
      if (found)
	{
	  confirm->receivers[loopa]=confirm->receivers[loopa+1];
	}
      else
	{
	  if (confirm->receivers[loopa]==target)
	    {
	      found=1;
	      confirm->receivers[loopa]=confirm->receivers[loopa+1];
	    }
	}
    }
  
  if (found || confirm->receivers[confirm->receivercount-1]==target)
    {
      //decriment the count
      confirm->receivercount--;
    }

  grapple_thread_mutex_unlock(confirm->confirm_mutex);

  return 1;
}

//Register that a user is expected to confirm to this message
int register_confirm(grapple_connection *origin,int messageid,int target)
{
  grapple_confirm *confirm;
  
  grapple_thread_mutex_lock(origin->confirm_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Locate the message
  confirm=locate_confirm_message(origin->confirm,messageid);

  if (!confirm)
    {
      //If we couldnt find it, make it
      confirm=grapple_confirm_aquire();

      //And link it in
      origin->confirm=grapple_confirm_link(origin->confirm,confirm);
      confirm->messageid=messageid;
      confirm->timeout=time(NULL)+GRAPPLE_CONFIRM_TIMEOUT;
    }
  else
    {
      //Dont add in duplicates
      if (locate_confirm_message_receiver_index(confirm,target)!=-1)
	{
	  grapple_thread_mutex_unlock(origin->confirm_mutex);
	  return 0;
	}
    }

  //Add the receiver
  confirm_message_add_receiver(confirm,target);

  grapple_thread_mutex_unlock(origin->confirm_mutex);

  return 0;
}

//Register the confirm for a user from a server message
int server_register_confirm(internal_server_data *server,
			    int messageid,int target)
{
  grapple_confirm *confirm;

  grapple_thread_mutex_lock(server->confirm_mutex,GRAPPLE_LOCKTYPE_SHARED);

  //Locate the message confirm list
  confirm=locate_confirm_message(server->confirm,messageid);

  if (!confirm)
    {
      grapple_thread_mutex_unlock(server->confirm_mutex);

      //Cant find it - make it
      confirm=grapple_confirm_aquire();
      confirm->messageid=messageid;
      confirm->timeout=time(NULL)+GRAPPLE_CONFIRM_TIMEOUT;

      grapple_thread_mutex_lock(server->confirm_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      server->confirm=grapple_confirm_link(server->confirm,confirm);
    }
  else
    {
      if (locate_confirm_message_receiver_index(confirm,target)!=-1)
	{
	  grapple_thread_mutex_unlock(server->confirm_mutex);
	  return 0;
	}
    }

  //Add the user into the list
  confirm_message_add_receiver(confirm,target);

  grapple_thread_mutex_unlock(server->confirm_mutex);

  return 0;
}

//Remove a user from the list of confirmations, usually cos they have confirmed
int unregister_confirm(internal_server_data *server,
		       grapple_connection *origin,int messageid,int target)
{
  grapple_confirm *confirm;
  int done=0;

  grapple_thread_mutex_lock(origin->confirm_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Locate the message
  confirm=locate_confirm_message(origin->confirm,messageid);

  if (!confirm)
    {
      grapple_thread_mutex_unlock(origin->confirm_mutex);
      return 0;
    }
  else
    {
      //And the receiver
      if (locate_confirm_message_receiver_index(confirm,target)==-1)
	{
	  grapple_thread_mutex_unlock(origin->confirm_mutex);
	  return 0;
	}
    }

  //Remove the receiver
  confirm_message_remove_receiver(confirm,target);

  if (confirm->receivercount==0)
    {
      //If there are no more receivers
      done=1;

      //Remove this message
      origin->confirm=grapple_confirm_unlink(origin->confirm,confirm);
      grapple_confirm_dispose(confirm);
    }

  grapple_thread_mutex_unlock(origin->confirm_mutex);

  if (done)
    //Let the user know the message is confirmed, if all have confirmed
    s2c_confirm_received(server,origin,messageid);

  return 0;
}

//Remove a user from the list of confirmations on a server message,
//usually cos they have confirmed
int server_unregister_confirm(internal_server_data *server,
			      int messageid,int target)
{
  grapple_confirm *confirm;
  int done=0;

  grapple_thread_mutex_lock(server->confirm_mutex,GRAPPLE_LOCKTYPE_SHARED);

  //Locate the message
  confirm=locate_confirm_message(server->confirm,messageid);

  if (!confirm)
    {
      grapple_thread_mutex_unlock(server->confirm_mutex);
      return 0;
    }
  else
    {
      //And the receiver

      if (locate_confirm_message_receiver_index(confirm,target)==-1)
	{
	  grapple_thread_mutex_unlock(server->confirm_mutex);
	  return 0;
	}
    }

  //Remove the receiver
  confirm_message_remove_receiver(confirm,target);

  if (confirm->receivercount==0)
    {
      grapple_thread_mutex_unlock(server->confirm_mutex);

      grapple_thread_mutex_lock(server->confirm_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);

      //If there are no more receivers
      done=1;

      //Remove this message
      server->confirm=grapple_confirm_unlink(server->confirm,confirm);
      grapple_confirm_dispose(confirm);
    }

  grapple_thread_mutex_unlock(server->confirm_mutex);

  if (done)
    {
      if (server->sendwait==messageid)
	server->sendwait=0;

      //Let the server user know the message is confirmed,
      //if all have confirmed
      s2SUQ_confirm_received(server,messageid);
    }

  return 0;
}

/*The following three functions handle what happens if someone disconnects
  from the server, while still having confirm messages outstanding. In
  effect the confirm and the disconnect messages cross paths.
  We cant check every confirm message every single time someone disconnects,
  that would be VERY expensive for a situation that almost never ever
  happens.
  Instead we work by looping through each send confirm to see if they
  are more than 2 seconds into their cycle. It checks to see if they have
  completely timed out (10 seconds) or just need to be checked (every
  2 seconds).
  Each check looks at all users still listed as unconfirmed, and checks
  to see if they have disconnected. If they HAVE, then it reports them
  as confirmed. A disconnected user is NOT a fail.
  Anything over 10 seconds is considered a fail and reported as such.
  This LOOKS like an expensive set of operations but in reality it isnt.
  Each user will only have their confirms checked once every 2 seconds at
  most, the confirms are in time order already so as soon as we
  hit one that isnt old (the vast majority) then we leave that user. All
  in all, this is quite cheap
*/
  

//Check to see if anyone on this confirm message has disconnected recently,
//And remove them from this list if they have.
static void process_server_confirm_disconnections(internal_server_data *server,
						  grapple_confirm *target)
{
  int loopa;
  grapple_connection *scan;
  int found;
  int targetid;
  
  //Loop for each user we are still waiting for
  for (loopa=0;loopa<target->receivercount;loopa++)
    {
      found=0;
      targetid=target->receivers[loopa];
      
      grapple_thread_mutex_lock(server->connection_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      
      //Now see if we can find a user to match it
      scan=server->userlist;
      while (scan)
	{
	  if (scan->serverid==targetid)
	    {
	      //We found the user, break out of the loop
	      found=1;
	      scan=NULL;
	    }
	  else
	    scan=scan->next;
	  
	  if (scan==server->userlist)
	    scan=NULL;
	}

      grapple_thread_mutex_unlock(server->connection_mutex);

      if (!found)
	{
	  //This user has disconnected
	  if (target->receivercount==1)
	    {
	      //This is the last one, handle differently
	      server_unregister_confirm(server,target->messageid,
					targetid);
	      //Now this target will be GONE - return
	      return;
	    }
	  else
	    {
	      //remove this user, more to go
	      server_unregister_confirm(server,target->messageid,
					targetid);
	      loopa--;
	    }
	}
    }

  return;
}

//Check to see if anyone on this confirm message has disconnected recently,
//And remove them from this list if they have.
static void process_user_confirm_disconnections(internal_server_data *server,
						grapple_connection *user,
						grapple_confirm *target)
{
  int loopa;
  grapple_connection *scan;
  int found;
  
  //Loop for each user we are still waiting for
  for (loopa=0;loopa<target->receivercount;loopa++)
    {
      found=0;
      
      grapple_thread_mutex_lock(target->confirm_mutex,
				GRAPPLE_LOCKTYPE_SHARED);
      
      //Now see if we can find a user to match it
      scan=server->userlist;
      while (scan)
	{
	  if (scan->serverid==target->receivers[loopa])
	    {
	      //We found the user, break out of the loop
	      found=1;
	      scan=NULL;
	    }
	  else
	    scan=scan->next;
	  
	  if (scan==server->userlist)
	    scan=0;
	}
      grapple_thread_mutex_unlock(target->confirm_mutex);

      if (!found)
	{
	  //This user has disconnected
	  if (target->receivercount==1)
	    {
	      //This is the last one, handle differently
	      unregister_confirm(server,user,target->messageid,
				 scan->serverid);
	      //Now this target will be GONE - return
	      return;
	    }
	  else
	    {
	      //Remove this entry
	      unregister_confirm(server,user,target->messageid,
				 scan->serverid);

	      //decriment loopa, so we will check the same index next time
	      loopa--;
	    }
	}
    }

  return;
}

//This is the controlling function for slow confirms
void process_slow_confirms(internal_server_data *server)
{
  grapple_confirm *scan,*target;
  grapple_connection *userscan;
  time_t this_second;

  this_second=time(NULL);

  //ONLY run this once a second  
  if (this_second==server->last_confirm_check)
    return;

  server->last_confirm_check=this_second;

  //first check the server
  grapple_thread_mutex_lock(server->confirm_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  //Loop through each confirm on the server - remember they are in time
  //order so we can stop as soon as we are less than 2 seconds
  scan=server->confirm;
  while (scan)
    {
      if (scan->timeout-this_second<(GRAPPLE_CONFIRM_TIMEOUT-1))
	{
	  if (scan->timeout<this_second)
	    {
	      //This one has timed out, send a timeout message and
	      //then remove it.
	      server->confirm=grapple_confirm_unlink(server->confirm,scan);
	      s2SUQ_confirm_timeout(server,scan);
	      grapple_confirm_dispose(scan);

	      //This will always be the first one being deleted, so reset scan
	      //to be the start of the list again
	      scan=server->confirm;
	    }
	  else
	    {
	      //This hasnt timed out, but has been over 2 seconds. Check for
	      //disconnections
	      if ((scan->timeout-this_second)%2==0)
		{
		  //we go to next then prev cos we dont know if the target will
		  //be deleted or not, this keeps us safely on the next one
		  //next loop
		  target=scan;
		  scan=scan->next;
		  if (scan==target)
		    scan=NULL;
		  //Now run the disconnect check
		  process_server_confirm_disconnections(server,target);
		  if (scan)
		    scan=scan->prev;
		}
	      
	      if (scan)
		scan=scan->next;
	      if (scan==server->confirm)
		scan=NULL;
	    }
	}
      else
	//This one wasnt over 2 seconds, so do nothing here
	scan=NULL;
    }

  grapple_thread_mutex_unlock(server->confirm_mutex);

  //Now we've handled the server, now we handle each user too - exactly the
  //same for EACH user

  grapple_thread_mutex_lock(server->connection_mutex,GRAPPLE_LOCKTYPE_SHARED);
  
  userscan=server->userlist;

  //Loop through each user
  while (userscan)
    {
      grapple_thread_mutex_lock(userscan->confirm_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

      scan=userscan->confirm;
      while (scan)
	{
	  if (scan->timeout-this_second<(GRAPPLE_CONFIRM_TIMEOUT-1))
	    {
	      if (scan->timeout<this_second)
		{
		  //This one has timed out, send a timeout message and
		  //then remove it.
		  userscan->confirm=grapple_confirm_unlink(userscan->confirm,
							   scan);
		  s2c_confirm_timeout(server,userscan,scan);
		  grapple_confirm_dispose(scan);

		  //This will always be the first one being deleted...
		  scan=userscan->confirm;
		}
	      else
		{
		  //This hasnt timed out, but has been over 2 seconds. Check for
		  //disconnections
		  if ((scan->timeout-this_second)%2==0)
		    {
		      //we go to next then prev cos we dont know if the 
		      //target will be deleted or not, this keeps us safely 
		      //on the next one next loop
		      target=scan;
		      scan=scan->next;
		      if (scan==target)
			scan=NULL;
		      //Check for disconnections now
		      process_user_confirm_disconnections(server,
							  userscan,target);
		      if (scan)
			scan=scan->prev;
		    }
		  
		  if (scan)
		    scan=scan->next;
		  if (scan==userscan->confirm)
		    scan=NULL;
		}
	    }
	  else
	    scan=NULL;
	}
      
      grapple_thread_mutex_unlock(userscan->confirm_mutex);

      userscan=userscan->next;
      if (userscan==server->userlist)
	userscan=NULL;
    }

  grapple_thread_mutex_unlock(server->connection_mutex);

}

