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

#ifndef GRAPPLE_CONNECTION_H
#define GRAPPLE_CONNECTION_H

#include "grapple_client_internal.h"
#include "grapple_server_internal.h"
#include "grapple_structs.h"
#include "socket.h"

extern grapple_connection *connection_struct_aquire(void);
extern int connection_client_add(internal_client_data *,int,int);
extern int connection_server_add(internal_server_data *,socketbuf *);
extern int connection_client_rename(internal_client_data *,int,char *);
extern grapple_connection *connection_from_serverid(grapple_connection *,int);
extern void connection_struct_dispose(grapple_connection *);
extern grapple_connection *connection_link(grapple_connection *,
					   grapple_connection *);
extern grapple_connection *connection_unlink(grapple_connection *,
					   grapple_connection *);
extern int connection_client_remove_by_id(internal_client_data *,int);
extern int *connection_client_intarray_get(internal_client_data *);
extern int *connection_server_intarray_get(internal_server_data *);
extern int connection_client_count(internal_client_data *);
extern int connection_server_count(internal_server_data *);

extern int grapple_connection_spare_init(void);
extern int grapple_connection_spare_cleanup(void);


#endif
