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

#ifndef GRAPPLE_VARIABLE_H
#define GRAPPLE_VARIABLE_H

#include "grapple_structs.h"

#define GRAPPLE_VARIABLE_TYPE_DATA 0
#define GRAPPLE_VARIABLE_TYPE_INT 1
#define GRAPPLE_VARIABLE_TYPE_DOUBLE 2


extern grapple_variable_hash *grapple_variable_hash_init(int);
extern void grapple_variable_hash_dispose(grapple_variable_hash *);

extern int grapple_variable_set_int(grapple_variable_hash *,
				    const char *,int);
extern int grapple_variable_set_double(grapple_variable_hash *,
				       const char *,double);
extern int grapple_variable_set_data(grapple_variable_hash *,
				     const char *,void *,size_t);

extern int grapple_variable_timeset_int(grapple_variable_hash *,
					const char *,int,int,int);
extern int grapple_variable_timeset_double(grapple_variable_hash *,
					   const char *,double,int,int);
extern int grapple_variable_timeset_data(grapple_variable_hash *,
					 const char *,void *,size_t,int,int);

extern grapple_error grapple_variable_get_int(grapple_variable_hash *,
				    const char *,int *);
extern grapple_error grapple_variable_get_double(grapple_variable_hash *,
				       const char *,double *);
extern grapple_error grapple_variable_get_data(grapple_variable_hash *,
				     const char *,void *,size_t *);

extern int grapple_variable_client_sync(internal_client_data *,const char *);
extern int grapple_variable_server_sync(internal_server_data *,const char *);

extern int grapple_variable_server_syncall(internal_server_data *,
					   grapple_connection *);

#endif
