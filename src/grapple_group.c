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

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#undef _XOPEN_SOURCE

#include "grapple_connection.h"
#include "grapple_error_internal.h"
#include "grapple_group.h"
#include "grapple_group_internal.h"
#include "grapple_structs.h"

char *group_crypt(grapple_user group,const char *password)
{
  char salt[3];
  char *cpassword;
  char *buf;

  if (!password || !*password)
    return NULL;

  buf=(char *)malloc(20+1);

  salt[0]='a'+(group%26);
  salt[1]='a'+((group>>1)%26);
  salt[2]=0;
  cpassword=crypt(password,salt);

  strncpy(buf,cpassword,20);
  buf[20]=0;

  return buf;
}

char *group_crypt_twice(grapple_user group,const char *password)
{
  char salt[3];
  char *cpassword;
  char *buf;

  if (!password || !*password)
    return NULL;

  buf=(char *)malloc(20+1);

  salt[0]='a'+(group%26);
  salt[1]='a'+((group>>1)%26);
  salt[2]=0;
  cpassword=crypt(password,salt);

  strncpy(buf,cpassword,20);
  buf[20]=0;

  cpassword=crypt(buf,salt);

  strncpy(buf,cpassword,20);
  buf[20]=0;

  return buf;
}

//Allocate the memory for a group container. This is what sits in a group,
//one each per member of the group.
//When allocating, set the ID of the container user
grapple_group_container *group_container_aquire(int id)
{
  grapple_group_container *container;

  container=(grapple_group_container *)calloc(1,sizeof(grapple_group_container));

  container->id=id;

  return container;
}

//Free the container memory
int group_container_dispose(grapple_group_container *item)
{
  free(item);

  return 0;
}

//Link a group into a list of groups
static internal_grapple_group *group_link(internal_grapple_group *list,
					  internal_grapple_group *item)
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

//Unlink a group from a list of groups
internal_grapple_group *group_unlink(internal_grapple_group *list,
				     internal_grapple_group *item)
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

//Link a group container into a list of group containers
grapple_group_container *group_container_link(grapple_group_container *list,
					      grapple_group_container *item)
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

//Unlink a group container from a list of group containers
grapple_group_container *group_container_unlink(grapple_group_container *list,
						grapple_group_container *item)
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

//Allocate the memory for the group structure, and assign it a groupID
static internal_grapple_group *group_aquire(int id)
{
  internal_grapple_group *group;

  group=(internal_grapple_group *)calloc(1,sizeof(internal_grapple_group));

  group->id=id;
  group->container_mutex=grapple_thread_mutex_init();

  return group;
}

//Free all memory associated with a group, including all subcontainers
int group_dispose(internal_grapple_group *group)
{
  grapple_group_container *target;

  while (group->contents)
    {
      grapple_thread_mutex_lock(group->container_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      target=group->contents;
      if (target)
	group->contents=group_container_unlink(group->contents,target);
      grapple_thread_mutex_unlock(group->container_mutex);
      group_container_dispose(target);
    }


  grapple_thread_mutex_destroy(group->container_mutex);

  if (group->name)
    free(group->name);

  if (group->password)
    free(group->password);

  free(group);

  return 0;
}


//Locate a group by its ID number from a list
internal_grapple_group *group_locate(internal_grapple_group *list,
				     int id)
{
  internal_grapple_group *scan;

  scan=list;

  while (scan)
    {
      if (scan->id == id)
	//It is the correct one
	return scan;

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  return NULL;
}

//Find the container holding a specific user ID in a group
static grapple_group_container *group_locate_id_in_group(grapple_group_container *list,int id)
{
  grapple_group_container *scan;

  scan=list;

  while (scan)
    {
      if (scan->id == id)
	//It matches
	return scan;

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  return NULL;
}

//Check the password is corrrect for this group, we dont encrypt
//group passwords.
static int group_check_password(internal_grapple_group *group,
				const char *password)
{
  //No password, no check needed
  if (!group->password)
    return 1;

  //We have a password but none was sent, always fail
  if (!password)
    return 0;

  //Check, succede if matched
  if (!strcmp(password,group->password))
    return 1;

  //Failed match
  return 0;
}


//Create a group for a client
int create_client_group(internal_client_data *client,int id,const char *name,
			const char *cryptpassword)
{
  internal_grapple_group *group;

  group=group_aquire(id);

  //Assign the name
  group->name=(char *)malloc(strlen(name)+1);
  strcpy(group->name,name);
  
  if (cryptpassword)
    {
      group->password=(char *)malloc(strlen(cryptpassword)+1);
      strcpy(group->password,cryptpassword);
    }

  grapple_thread_mutex_lock(client->group_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  //Link it in
  client->groups=group_link(client->groups,group);
  grapple_thread_mutex_unlock(client->group_mutex);

  return GRAPPLE_OK;
}

//Create a group for the server
int create_server_group(internal_server_data *server,int id,const char *name,
			const char *password)
{
  internal_grapple_group *group;

  server->groupcount++;

  group=group_aquire(id);

  //Allocate the name
  group->name=(char *)malloc(strlen(name)+1);
  strcpy(group->name,name);

  if (password && *password)
    {
      group->password=(char *)malloc(strlen(password)+1);
      strcpy(group->password,password);
    }

  grapple_thread_mutex_lock(server->group_mutex,GRAPPLE_LOCKTYPE_SHARED);
  server->groups=group_link(server->groups,group);
  grapple_thread_mutex_unlock(server->group_mutex);
  
  return GRAPPLE_OK;
}

//Add a user or another group to a group
static int client_group_add_intforce(internal_client_data *client,int groupid,int add,
				  const char *password,int force)
{
  internal_grapple_group *group;
  grapple_group_container *item;
  grapple_connection *user;

  grapple_thread_mutex_lock(client->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Find the group by its ID
  group=group_locate(client->groups,groupid);

  if (!group)
    {
      //No such group
      grapple_thread_mutex_unlock(client->group_mutex);
      grapple_client_error_set(client,GRAPPLE_ERROR_NO_SUCH_GROUP);

      return 0;
    }

  //We have the group, now see if this target is already in the group
  grapple_thread_mutex_lock(group->container_mutex,GRAPPLE_LOCKTYPE_SHARED);
  item=group_locate_id_in_group(group->contents,add);
  grapple_thread_mutex_unlock(group->container_mutex);

  if (item)
    {
      //It is - return true cos its already there
      grapple_thread_mutex_unlock(client->group_mutex);
      return 1;
    }

  //Check the password is OK
  if (!force && !group_check_password(group,password))
    {
      grapple_thread_mutex_unlock(client->group_mutex);
      grapple_client_error_set(client,GRAPPLE_ERROR_BAD_PASSWORD);
      return 0;
    }


  //Add the new container into the group
  item=group_container_aquire(add);

  grapple_thread_mutex_lock(group->container_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  group->contents=group_container_link(group->contents,item);
  grapple_thread_mutex_unlock(group->container_mutex);

  grapple_thread_mutex_unlock(client->group_mutex);

  //Now we add this to the connection grouplist, the list of groups that the
  //user is connected to
  grapple_thread_mutex_lock(client->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=connection_from_serverid(client->userlist,add);

  if (user)
    {
      item=group_container_aquire(groupid);
      
      grapple_thread_mutex_lock(user->group_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      user->groups=group_container_link(user->groups,item);
      grapple_thread_mutex_unlock(user->group_mutex);
    }
  grapple_thread_mutex_unlock(client->connection_mutex);


  return 1;
}

int client_group_forceadd(internal_client_data *client,int groupid,int add)
{
  return client_group_add_intforce(client,groupid,add,NULL,1);
}

int client_group_add(internal_client_data *client,int groupid,int add,
		     const char *password)
{
  return client_group_add_intforce(client,groupid,add,password,0);
}


//Add a member to a group on the server
int server_group_add(internal_server_data *server,int groupid,int add,
		     const char *password)
{
  internal_grapple_group *group;
  grapple_group_container *item;
  grapple_connection *user;

  grapple_thread_mutex_lock(server->group_mutex,GRAPPLE_LOCKTYPE_SHARED);

  //Find the group
  group=group_locate(server->groups,groupid);

  if (!group)
    {
      grapple_thread_mutex_unlock(server->group_mutex);
      return 0;
    }

  //We have the group, now see if this target is already in the group
  grapple_thread_mutex_lock(group->container_mutex,GRAPPLE_LOCKTYPE_SHARED);
  item=group_locate_id_in_group(group->contents,add);
  grapple_thread_mutex_unlock(group->container_mutex);

  if (item)
    {
      grapple_thread_mutex_unlock(server->group_mutex);
      return 1;
    }

  if (!group_check_password(group,password))
    {
      grapple_thread_mutex_unlock(server->group_mutex);
      return 0;
    }

  item=group_container_aquire(add);

  //Now add it to the group

  grapple_thread_mutex_lock(group->container_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
  group->contents=group_container_link(group->contents,item);
  grapple_thread_mutex_unlock(group->container_mutex);

  grapple_thread_mutex_unlock(server->group_mutex);

  //Now we add this to the connection grouplist
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=connection_from_serverid(server->userlist,add);

  if (user)
    {
      item=group_container_aquire(groupid);

      grapple_thread_mutex_lock(user->group_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      user->groups=group_container_link(user->groups,item);
      grapple_thread_mutex_unlock(user->group_mutex);
    }
  grapple_thread_mutex_unlock(server->connection_mutex);

  return 1;
}

//Remove a user from a group on the client
int client_group_remove(internal_client_data *client,int groupid,int removeid)
{
  internal_grapple_group *group;
  grapple_group_container *item=NULL;
  grapple_connection *user;
  int returnval=1;

  grapple_thread_mutex_lock(client->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Find the group
  group=group_locate(client->groups,groupid);

  if (group)
    {
      //We have the group, now see if this target is still in the group
      grapple_thread_mutex_lock(group->container_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      item=group_locate_id_in_group(group->contents,removeid);

      if (item)
	{
	  //Remove from the group
	  group->contents=group_container_unlink(group->contents,item);
	}
      grapple_thread_mutex_unlock(group->container_mutex);
    }
  else
    {
      returnval=0;
      grapple_client_error_set(client,GRAPPLE_ERROR_NO_SUCH_GROUP);
    }

  grapple_thread_mutex_unlock(client->group_mutex);

  if (item)
    {
      group_container_dispose(item);
      item=NULL;
    }
  else
    returnval=0;

  //Now we remove this from the connection grouplist
  grapple_thread_mutex_lock(client->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=connection_from_serverid(client->userlist,removeid);
  if (user)
    {
      grapple_thread_mutex_lock(user->group_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      item=group_locate_id_in_group(user->groups,groupid);

      if (item)
	{
	  user->groups=group_container_unlink(user->groups,item);
	}
      grapple_thread_mutex_unlock(user->group_mutex);
    }
  grapple_thread_mutex_unlock(client->connection_mutex);

  if (item)
    group_container_dispose(item);
  else
    returnval=0;

  return returnval;
}

//Remove a member of a group on the server
int server_group_remove(internal_server_data *server,int groupid,int removeid)
{
  internal_grapple_group *group;
  grapple_group_container *item=NULL;
  grapple_connection *user;
  int returnval=1;

  grapple_thread_mutex_lock(server->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Find the group
  group=group_locate(server->groups,groupid);

  if (!group)
    {
      grapple_thread_mutex_unlock(server->group_mutex);
    }
  else
    {
      //We have the group, now see if this target is still in the group
      grapple_thread_mutex_lock(group->container_mutex,
				GRAPPLE_LOCKTYPE_EXCLUSIVE);
      item=group_locate_id_in_group(group->contents,removeid);
      
      if (item)
	{
	  //Remove it from the group
	  group->contents=group_container_unlink(group->contents,item);
	}
      grapple_thread_mutex_unlock(group->container_mutex);
      
      grapple_thread_mutex_unlock(server->group_mutex);

      if (item)
	{
	  group_container_dispose(item);
	  item=NULL;
	}
      else
	returnval=0;
    }

  //Now we remove this from the connection grouplist
  grapple_thread_mutex_lock(server->connection_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  user=connection_from_serverid(server->userlist,removeid);
  if (user)
    {
      grapple_thread_mutex_lock(user->group_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);
      item=group_locate_id_in_group(user->groups,groupid);
      if (item)
	{
	  user->groups=group_container_unlink(user->groups,item);
	}
      grapple_thread_mutex_unlock(user->group_mutex);
    }
  grapple_thread_mutex_unlock(server->connection_mutex);
  
  if (item)
    group_container_dispose(item);
  else
    returnval=0;

  return returnval;
}

//Delete a whole group from the client
int delete_client_group(internal_client_data *client,int id)
{
  internal_grapple_group *group;
  int contentid;

  grapple_thread_mutex_lock(client->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);

  //Find the group
  group=group_locate(client->groups,id);

  if (!group)
    {
      grapple_thread_mutex_unlock(client->group_mutex);
      grapple_client_error_set(client,GRAPPLE_ERROR_NO_SUCH_GROUP);
      return 0;
    }

  //While we have members, delete all the members
  while (group->contents)
    {
      grapple_thread_mutex_lock(group->container_mutex,GRAPPLE_LOCKTYPE_SHARED);
      if (group->contents)
	{
	  contentid=group->contents->id;
	  grapple_thread_mutex_unlock(group->container_mutex);
	  client_group_remove(client,id,contentid);
	}
      else
	grapple_thread_mutex_unlock(group->container_mutex);
    }

  grapple_thread_mutex_unlock(client->group_mutex);

  //Unlink it
  grapple_thread_mutex_lock(client->group_mutex,
			    GRAPPLE_LOCKTYPE_EXCLUSIVE);


  group=group_locate(client->groups,id);

  client->groups=group_unlink(client->groups,group);

  grapple_thread_mutex_unlock(client->group_mutex);

  //Delete it
  group_dispose(group);

  return 1;
}

//Delete a group from the server
int delete_server_group(internal_server_data *server,int id)
{
  internal_grapple_group *group;
  int contentid;

  server->groupcount--;

  grapple_thread_mutex_lock(server->group_mutex,GRAPPLE_LOCKTYPE_SHARED);

  //Locate the group
  group=group_locate(server->groups,id);

  if (!group)
    {
      grapple_thread_mutex_unlock(server->group_mutex);
      return 0;
    }

  //While we have members, delete all the members
  while (group->contents)
    {
      grapple_thread_mutex_lock(group->container_mutex,GRAPPLE_LOCKTYPE_SHARED);
      if (group->contents)
	{
	  contentid=group->contents->id;
	  grapple_thread_mutex_unlock(group->container_mutex);
	  server_group_remove(server,id,contentid);
	}
      else
	grapple_thread_mutex_unlock(group->container_mutex);
    }

  grapple_thread_mutex_unlock(server->group_mutex);

  //Unlink it
  grapple_thread_mutex_lock(server->group_mutex,GRAPPLE_LOCKTYPE_EXCLUSIVE);

  group=group_locate(server->groups,id);

  server->groups=group_unlink(server->groups,group);

  grapple_thread_mutex_unlock(server->group_mutex);

  //Delete it
  group_dispose(group);

  return 1;
}


//This function locates a member of an unpack array. An unpack array is
//an integer array in numerical order.
static int group_unpack_locate(int *data,int *size,int id)
{
  int max,min,mid;

  if (*size==0)
    return 0;

  max=(*size)-1;
  min=0;

  //Binary search
  while (min<=max)
    {
      mid=(min+max)/2;

      if (data[mid]>id)
	max=mid-1;
      else if (data[mid]<id)
	min=mid+1;
      else
	return 1;
    }

  return 0;
}

//Insert an id into an unpack array, finding where it needs to go and
//Adding it in
static int *group_unpack_insert(int *data,int *maxsize,int *size,int id)
{
  int max,min,mid,loopa;

  if (*size==0)
    {
      *size=1;
      data[0]=id;
      return data;
    }

  if (*maxsize == *size)
    {
      (*maxsize) *= 2;
      data=(int *)realloc(data,*maxsize);
    }


  //Binary search to the location
  if (id > data[(*size)-1])
    mid=(*size);
  else
    {
      max=(*size)-1;
      min=0;
      mid=0;
      
      while (min<max)
	{
	  mid=(min+max)/2;
	  
	  if (data[mid]>id)
	    max=mid-1;
	  else if (data[mid]<id)
	    min=mid+1;
	}
      
      mid=min;
    }

  //Now, mid is either the one we need to move up, or is
  //the one after it, so we check this, then move things
  while (mid > 0 && data[mid-1]>id)
    {
      mid--;
    }

  if (mid!=(*size))
    {
      //Memmove just seems very very broken, gives completely bad values
      //in this instance, so do it the slow way. Shouldnt be too slow
      //groups arent likely to get that big anyway
      for (loopa=(*size-1);loopa>=mid;loopa--)
	data[loopa+1]=data[loopa];
    }
  data[mid]=id;

  //Incriment the size
  (*size)++;

  return data;
}

//Unpack a group. Recursively burrow down into subgroups. Put all the
//data into an int* array, and return the size of that array as
//the int *size passed in here
static int *server_group_unpack(internal_server_data *server,
				internal_grapple_group *group,
				int *data,int *maxsize,int *size)
{
  grapple_group_container *scan;
  internal_grapple_group *newgroup;

  grapple_thread_mutex_lock(group->container_mutex,GRAPPLE_LOCKTYPE_SHARED);

  scan=group->contents;

  while (scan)
    {
      //Loop through each container in the group
      if (!group_unpack_locate(data,size,scan->id))
	{
	  //This isnt already in the group

	  //Insert it into the group
	  data=group_unpack_insert(data,maxsize,size,scan->id);

	  //Test if this is a group itself
	  newgroup=group_locate(server->groups,scan->id);

	  if (newgroup)
	    //It is, recursively call this function
	    data=server_group_unpack(server,newgroup,data,maxsize,size);
	}
      scan=scan->next;
      if (scan==group->contents)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(group->container_mutex);
  
  return data;
}

//function that the server calls to expand a group and return an int* array
//of members. The size of the aray is returned in the size int* that is
//passed in
int *server_group_unroll(internal_server_data *server,int groupid)
{
  static int targetmaxsize=100;
  int maxsize;
  int *returnval;
  int size;
  internal_grapple_group *group;

  maxsize=targetmaxsize;

  //now find the group, and then unroll it
  grapple_thread_mutex_lock(server->group_mutex,GRAPPLE_LOCKTYPE_SHARED);
  group=group_locate(server->groups,groupid);

  if (!group)
    {
      grapple_thread_mutex_unlock(server->group_mutex);
      return NULL;
    }
  
  size=0;
  returnval=(int *)malloc(maxsize * sizeof (int));

  returnval=server_group_unpack(server,group,returnval,&maxsize,&size);
  grapple_thread_mutex_unlock(server->group_mutex);

  if (maxsize == size)
    {
      maxsize *= 2;
      returnval=(int *)realloc(returnval,maxsize);
    }
  returnval[size]=0;

  if (maxsize>targetmaxsize)
    targetmaxsize=maxsize;

  return returnval;
}

//Unpack a group. Recursively burrow down into subgroups. Put all the
//data into an int* array, and return the size of that array as
//the int *size passed in here
static int *client_group_unpack(internal_client_data *client,
				internal_grapple_group *group,
				int *data,int *maxsize,int *size)
{
  grapple_group_container *scan;
  internal_grapple_group *newgroup;

  grapple_thread_mutex_lock(client->group_mutex,GRAPPLE_LOCKTYPE_SHARED);

  scan=group->contents;

  while (scan)
    {
      //Loop through each container in the group
      if (!group_unpack_locate(data,size,scan->id))
	{
	  //This isnt already in the group

	  //Insert it into the group
	  data=group_unpack_insert(data,maxsize,size,scan->id);

	  //Test if this is a group itself
	  newgroup=group_locate(client->groups,scan->id);

	  if (newgroup)
	    //It is, recursively call this function
	    data=client_group_unpack(client,newgroup,data,maxsize,size);
	}
      scan=scan->next;
      if (scan==group->contents)
	scan=NULL;
    }

  grapple_thread_mutex_unlock(client->group_mutex);

  return data;
}

//function that the client calls to expand a group and return an int* array
//of members. The size of the aray is returned in the size int* that is
//passed in
int *client_group_unroll(internal_client_data *client,int groupid)
{
  static int targetmaxsize=100;
  int maxsize;
  int *returnval;
  internal_grapple_group *group;
  int size;

  maxsize=targetmaxsize;

  //now find the group, and then unroll it
  grapple_thread_mutex_lock(client->group_mutex,
			    GRAPPLE_LOCKTYPE_SHARED);
  group=group_locate(client->groups,groupid);

  if (!group)
    {
      grapple_thread_mutex_unlock(client->group_mutex);
      grapple_client_error_set(client,GRAPPLE_ERROR_NO_SUCH_GROUP);
      return NULL;
    }
  
  size=0;
  returnval=(int *)malloc(maxsize * sizeof (int));

  returnval=client_group_unpack(client,group,returnval,&maxsize,&size);
  grapple_thread_mutex_unlock(client->group_mutex);

  if (maxsize == size)
    {
      maxsize *= 2;
      returnval=(int *)realloc(returnval,maxsize);
    }

  returnval[size]=0;

  if (maxsize > targetmaxsize)
    targetmaxsize=maxsize;

  return returnval;
}
