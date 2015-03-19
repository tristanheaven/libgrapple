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

#include "grapple_structs.h"
#include "grapple_failover.h"

//This file really only contains a few utilities for the failover
//functionality. The actual failover happens in grapple_client_thread.c


//Make a failover container
grapple_failover_host *failover_aquire(void)
{
  return (grapple_failover_host *)calloc(1,sizeof(grapple_failover_host));
}

//Get rid of a failover container including all its associated memory
void failover_dispose(grapple_failover_host *target)
{
  if (target->address)
    free(target->address);

  free(target);

  return;
}

//Remove the failover container from a list
grapple_failover_host *failover_unlink(grapple_failover_host *list,
				       grapple_failover_host *item)
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

//Link the failover into a list of failovers
grapple_failover_host *failover_link(grapple_failover_host *list,
				     grapple_failover_host *item)
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

//Locate a failover ID in a list
static grapple_failover_host *failover_locate(grapple_failover_host *list,
					      int id)
{
  grapple_failover_host *scan;

  scan=list;

  while (scan)
    {
      if (scan->id)
	//Got it
	return scan;
      
      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }
  
  return NULL;
}

//Unlink a failover based on its ID
grapple_failover_host *failover_unlink_by_id(grapple_failover_host *list,
					     int id)
{
  grapple_failover_host *target;

  target=failover_locate(list,id);

  if (target)
    {
      list=failover_unlink(list,target);

      failover_dispose(target);
    }

  return list;
}

//Create a failover and link it into the list
grapple_failover_host *failover_link_by_id(grapple_failover_host *list,
					   int id,const char *hostname)
{
  grapple_failover_host *newhost;

  //In case its already linked, remove it. This SHOULD never happen, but
  //best to be safe
  failover_unlink_by_id(list,id);

  newhost=failover_aquire();

  newhost->id=id;
  newhost->address=(char *)malloc(strlen(hostname)+1);
  strcpy(newhost->address,hostname);

  list=failover_link(list,newhost);

  return list;
}

//Find the lowest numbered failover.
grapple_failover_host *failover_locate_lowest_id(grapple_failover_host *list)
{
  grapple_failover_host *scan,*lowest;

  scan=list;
  lowest=list;

  while (scan)
    {
      if (scan->id< lowest->id)
	lowest=scan;

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  return lowest;
}
