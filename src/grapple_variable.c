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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "grapple_structs.h"
#include "grapple_variable.h"
#include "grapple_comms_api.h"
#include "tools.h"

//Link a variable object into a list of variable objects

static grapple_variable *grapple_variable_link(grapple_variable *variable,
				               grapple_variable *item)
{
  if (!variable)
    {
      item->next=item;
      item->prev=item;
      return item;
    }

  item->next=variable;
  item->prev=variable->prev;

  item->next->prev=item;
  item->prev->next=item;

  return variable;
}

//Unlink a variable object from a list of variable objects
static grapple_variable *grapple_variable_unlink(grapple_variable *variable,
						 grapple_variable *item)
{
  if (variable->next==variable)
    {
      if (variable!=item)
	return variable;

      return NULL;
    }
  
  item->prev->next=item->next;
  item->next->prev=item->prev;

  if (item==variable)
    variable=item->next;

  return variable;
}


grapple_variable_hash *grapple_variable_hash_init(int size)
{
  grapple_variable_hash *returnval;
  int loopa;

  returnval=(grapple_variable_hash *)malloc(sizeof(grapple_variable_hash));
  returnval->bucket_count=size;

  returnval->bucket=(grapple_variable **)calloc(1,sizeof(grapple_variable *)*size);
  returnval->bucket_mutex=(grapple_thread_mutex **)calloc(1,sizeof(grapple_thread_mutex *)*size);

  //Create the mutexes
  for (loopa=0;loopa < size;loopa++)
    {
      returnval->bucket_mutex[loopa]=grapple_thread_mutex_init();
    }


  return returnval;
}

void grapple_variable_hash_dispose(grapple_variable_hash *target)
{
  int loopa;
  grapple_variable *var;

  //When we are here we are destroying it all, no need to get mutex locks,
  //if anything has a lock still there are way bigger problems

  for (loopa=0;loopa < target->bucket_count;loopa++)
    {
      while (target->bucket[loopa])
	{
	  var=target->bucket[loopa];
	  target->bucket[loopa]=grapple_variable_unlink(var,var);
	  if (var->data)
	    free(var->data);
	  free(var->name);
	  grapple_thread_mutex_destroy(var->mutex);
	  free(var);
	}
      grapple_thread_mutex_destroy(target->bucket_mutex[loopa]);
    }

  free(target->bucket);
  free(target->bucket_mutex);

  free(target);

  return;
}

static grapple_variable *grapple_variable_get(grapple_variable_hash *hash,
					      const char *name)
{
  //Find the hash bucket
  int sum=0,bucket;
  const char *ptr;
  grapple_variable *scan;

  ptr=name;

  while (*ptr)
    sum+=(int)(*ptr++);
  
  bucket=sum%hash->bucket_count;
  
  grapple_thread_mutex_lock(hash->bucket_mutex[bucket],
                            GRAPPLE_LOCKTYPE_SHARED);

  scan=hash->bucket[bucket];

  while (scan)
    {
      if (!strcmp(name,scan->name))
	{
	  grapple_thread_mutex_lock(scan->mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
	  grapple_thread_mutex_unlock(hash->bucket_mutex[bucket]);
	  return scan;
	}
      scan=scan->next;
      if (scan==hash->bucket[bucket])
	scan=NULL;
    }

  grapple_thread_mutex_unlock(hash->bucket_mutex[bucket]);
  
  return NULL;
}

static grapple_variable *grapple_variable_create(grapple_variable_hash *hash,
						 const char *name)
{
  grapple_variable *var;
  int sum=0,bucket;
  const char *ptr;

  ptr=name;

  while (*ptr)
    sum+=(int)(*ptr++);
  
  bucket=sum%hash->bucket_count;
  
  var=(grapple_variable *)calloc(1,sizeof(grapple_variable));
  var->name=(char *)malloc(strlen(name)+1);
  strcpy(var->name,name);
  var->mutex=grapple_thread_mutex_init();
  grapple_thread_mutex_lock(var->mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  grapple_thread_mutex_lock(hash->bucket_mutex[bucket],
                            GRAPPLE_LOCKTYPE_EXCLUSIVE);

  hash->bucket[bucket]=grapple_variable_link(hash->bucket[bucket],var);

  grapple_thread_mutex_unlock(hash->bucket_mutex[bucket]);

  return var;
}

int grapple_variable_timeset_int(grapple_variable_hash *hash,
				 const char *name,int val,int sec,int usec)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (var)
    {
      if (var->sec > sec || 
	  (var->sec==sec && var->usec > usec))
	{
	  grapple_thread_mutex_unlock(var->mutex); 

	  return 1;
	}
    }
  else
    {
      var=grapple_variable_create(hash,name);
      var->vartype=GRAPPLE_VARIABLE_TYPE_INT;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_INT)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return 0;
    }

  var->intdata=val;

  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}
		     
int grapple_variable_timeset_double(grapple_variable_hash *hash,
				    const char *name,double val,int sec,int usec)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (var)
    {
      if (var->sec > sec || 
	  (var->sec==sec && var->usec > usec))
	{
	  grapple_thread_mutex_unlock(var->mutex); 

	  return 1;
	}
    }
  else
    {
      var=grapple_variable_create(hash,name);
      var->vartype=GRAPPLE_VARIABLE_TYPE_DOUBLE;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_DOUBLE)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return 0;
    }

  var->doubledata=val;

  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}
		     
int grapple_variable_timeset_data(grapple_variable_hash *hash,
				  const char *name,void *data,size_t len,
				  int sec,int usec)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (var)
    {
      if (var->sec > sec || 
	  (var->sec==sec && var->usec > usec))
	{
	  grapple_thread_mutex_unlock(var->mutex); 

	  return 1;
	}
    }
  else
    {
      var=grapple_variable_create(hash,name);
      var->vartype=GRAPPLE_VARIABLE_TYPE_DATA;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_DATA)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return 0;
    }

  if (var->data)
    free(var->data);
  var->data=(void *)malloc(len);
  memcpy(var->data,data,len);
  var->length=len;

  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}
		     
int grapple_variable_set_int(grapple_variable_hash *hash,
			     const char *name,int val)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (!var)
    {
      var=grapple_variable_create(hash,name);
      var->vartype=GRAPPLE_VARIABLE_TYPE_INT;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_INT)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return 0;
    }

  var->intdata=val;

  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}
		     
int grapple_variable_set_double(grapple_variable_hash *hash,
				const char *name,double val)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (!var)
    {
      var=grapple_variable_create(hash,name);
      var->vartype=GRAPPLE_VARIABLE_TYPE_DOUBLE;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_DOUBLE)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return 0;
    }

  var->doubledata=val;

  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}
		     
int grapple_variable_set_data(grapple_variable_hash *hash,
			      const char *name,void *data,size_t len)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (!var)
    {
      var=grapple_variable_create(hash,name);
      var->vartype=GRAPPLE_VARIABLE_TYPE_DATA;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_DATA)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return 0;
    }

  if (var->data)
    free(var->data);
  var->data=(void *)malloc(len);
  memcpy(var->data,data,len);
  var->length=len;

  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}
		     
grapple_error grapple_variable_get_int(grapple_variable_hash *hash,
				       const char *name,int *val)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (!var)
    {
      return GRAPPLE_ERROR_NO_SUCH_VARIABLE;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_INT)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return GRAPPLE_ERROR_INCORRECT_VARIABLE_TYPE;
    }

  *val=var->intdata;

  grapple_thread_mutex_unlock(var->mutex); 

  return GRAPPLE_NO_ERROR;
}
		     
grapple_error grapple_variable_get_double(grapple_variable_hash *hash,
				const char *name,double *val)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (!var)
    {
      return GRAPPLE_ERROR_NO_SUCH_VARIABLE;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_DOUBLE)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return GRAPPLE_ERROR_INCORRECT_VARIABLE_TYPE;
    }

  *val=var->doubledata;

  grapple_thread_mutex_unlock(var->mutex); 

  return GRAPPLE_NO_ERROR;
}
		     
grapple_error grapple_variable_get_data(grapple_variable_hash *hash,
			      const char *name,void *data,size_t *len)
{
  grapple_variable *var;

  var=grapple_variable_get(hash,name);

  if (!var)
    {
      return GRAPPLE_ERROR_NO_SUCH_VARIABLE;
    }

  if (var->vartype!=GRAPPLE_VARIABLE_TYPE_DATA)
    {
      grapple_thread_mutex_unlock(var->mutex); 
      return GRAPPLE_ERROR_INCORRECT_VARIABLE_TYPE;
    }

  if (data==NULL)
    {
      *len=var->length;
      grapple_thread_mutex_unlock(var->mutex); 
      return GRAPPLE_NO_ERROR;
    }

  if (*len < var->length)
    {
      *len=var->length;
      grapple_thread_mutex_unlock(var->mutex); 
      return GRAPPLE_ERROR_INSUFFICIENT_SPACE;
    }

  memcpy(data,var->data,var->length);
  *len=var->length;

  grapple_thread_mutex_unlock(var->mutex); 

  return GRAPPLE_NO_ERROR;
}
		     
int grapple_variable_client_sync(internal_client_data *clientdata,
				 const char *name)
{
  grapple_variable *var;

  var=grapple_variable_get(clientdata->variables,name);

  if (!var)
    {
      return 0;
    }
  
  c2s_variable_send(clientdata,var);
  
  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}

int grapple_variable_server_sync(internal_server_data *serverdata,
				 const char *name)
{
  grapple_variable *var;
  struct timeval tv;
  grapple_connection *scan;

  var=grapple_variable_get(serverdata->variables,name);

  if (!var)
    {
      return 0;
    }
  
  gettimeofday(&tv,NULL);

  var->sec=tv.tv_sec;
  var->usec=tv.tv_usec;

  //Sending a message to ALL players
  grapple_thread_mutex_lock(serverdata->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  
  //Loop through all players
  scan=serverdata->userlist;
  while (scan)
    {
      //Send a message to this one
      s2c_variable_send(serverdata,scan,var);
      
      scan=scan->next;
      if (scan==serverdata->userlist)
	scan=0;
    }

  grapple_thread_mutex_unlock(serverdata->connection_mutex);
  
  grapple_thread_mutex_unlock(var->mutex); 

  return 1;
}

int grapple_variable_server_syncall(internal_server_data *server,
				    grapple_connection *user)
{
  //Find the hash bucket
  int loopa;
  grapple_variable *scan;

  for (loopa=0;loopa < server->variables->bucket_count;loopa++)
    {
      grapple_thread_mutex_lock(server->variables->bucket_mutex[loopa],
				GRAPPLE_LOCKTYPE_SHARED);

      scan=server->variables->bucket[loopa];

      while (scan)
	{
	  grapple_thread_mutex_lock(scan->mutex,GRAPPLE_LOCKTYPE_SHARED);

	  s2c_variable_send(server,user,scan);

	  grapple_thread_mutex_unlock(scan->mutex);

	  scan=scan->next;
	  if (scan==server->variables->bucket[loopa])
	    scan=NULL;
	}

      grapple_thread_mutex_unlock(server->variables->bucket_mutex[loopa]);
    }
  
  return 1;
}

