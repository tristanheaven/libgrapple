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

#include "grapple_queue.h"
#include "grapple_callback_internal.h"

//Allocate a new queue object.
grapple_queue *queue_struct_aquire(void)
{
  return (grapple_queue *)calloc(1,sizeof(grapple_queue));
}

//Dispose of a queue object, including all of its associated memory
void queue_struct_dispose(grapple_queue *queue)
{
  if (queue->data)
    free(queue->data);

  free (queue);

  return;
}

//Link a queue object into a list of queue objects
grapple_queue *queue_link(grapple_queue *queue,grapple_queue *item)
{
  if (!queue)
    {
      item->next=item;
      item->prev=item;
      return item;
    }

  item->next=queue;
  item->prev=queue->prev;

  item->next->prev=item;
  item->prev->next=item;

  return queue;
}

//Unlink a queue object from a list of queue objects
grapple_queue *queue_unlink(grapple_queue *queue,grapple_queue *item)
{
  if (queue->next==queue)
    {
      if (queue!=item)
	return queue;

      return NULL;
    }
  
  item->prev->next=item->next;
  item->next->prev=item->prev;

  if (item==queue)
    queue=item->next;

  return queue;
}

//Count the number of items in a queue list
int grapple_queue_count(grapple_queue *queue)
{
  grapple_queue *scan;
  int count=0;
  
  scan=queue;
  
  while (scan)
    {
      count++;
      scan=scan->next;
      if (scan==queue)
	scan=0;
    }

  return count;
}
