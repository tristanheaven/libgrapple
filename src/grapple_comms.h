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

#ifndef GRAPPLE_COMMS_H
#define GRAPPLE_COMMS_H

#include "grapple_enums.h"
#include "grapple_structs.h"

extern int s2c_send(internal_server_data *,
		    grapple_connection *,grapple_messagetype_internal,
		    const void *,size_t);
extern int s2c_send_int(internal_server_data *,
			grapple_connection *,grapple_messagetype_internal,
			int);
extern int s2c_send_double(internal_server_data *,
			   grapple_connection *,grapple_messagetype_internal,
			   double);
extern int s2SUQ_send(internal_server_data *,int,
		      grapple_messagetype_internal,const void *,size_t);
extern int s2SUQ_send_int(internal_server_data *,int,
			  grapple_messagetype_internal,int);
extern int s2SUQ_send_double(internal_server_data *,int,
			     grapple_messagetype_internal,double);

extern int c2s_send(internal_client_data *,grapple_messagetype_internal,
		    const void *,size_t);
extern int c2s_send_int(internal_client_data *,
			grapple_messagetype_internal,int);
extern int c2CUQ_send(internal_client_data *,grapple_messagetype_internal,
		      const void *,size_t);
extern int c2CUQ_send_int(internal_client_data *,
			  grapple_messagetype_internal,int);
extern int c2CUQ_send_double(internal_client_data *,
			     grapple_messagetype_internal,double);

#endif
