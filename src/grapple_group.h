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

#ifndef GRAPPLE_GROUP_H
#define GRAPPLE_GROUP_H

#include "grapple_structs.h"

extern grapple_group_container *group_container_aquire(int);
extern int group_container_dispose(grapple_group_container *);
extern grapple_group_container *group_container_link(grapple_group_container *,
						     grapple_group_container *);
extern grapple_group_container *group_container_unlink(grapple_group_container *,
						       grapple_group_container *);

extern int create_client_group(internal_client_data *,int,const char *,
			       const char *);

extern int create_server_group(internal_server_data *,int,const char *,
			       const char *);

extern int client_group_add(internal_client_data *,int,int,const char *);
extern int client_group_forceadd(internal_client_data *,int,int);
extern int server_group_add(internal_server_data *,int,int,const char *);

extern int client_group_remove(internal_client_data *,int,int);
extern int server_group_remove(internal_server_data *,int,int);

extern int delete_client_group(internal_client_data *,int);
extern int delete_server_group(internal_server_data *,int);

extern int *server_group_unroll(internal_server_data *,int);
extern int *client_group_unroll(internal_client_data *,int);

extern internal_grapple_group *group_locate(internal_grapple_group *,int);
extern internal_grapple_group *group_unlink(internal_grapple_group *,
					    internal_grapple_group *);
extern int group_dispose(internal_grapple_group *);

#endif
