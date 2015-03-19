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

#ifndef GRAPPLE_COMMS_API_H
#define GRAPPLE_COMMS_API_H

#include "grapple_structs.h"
#include "grapple_comms.h"

extern int c2s_handshake(internal_client_data *);
extern int c2s_set_name(internal_client_data *,const char *);
extern int c2s_message(internal_client_data *,int,int,
		       const void *,size_t);
extern int c2s_relaymessage(internal_client_data *,int,
			    int,grapple_confirmid,
			    const void *,size_t);
extern int c2s_relayallmessage(internal_client_data *,int,grapple_confirmid,
			       const void *,size_t);
extern int c2s_relayallbutselfmessage(internal_client_data *,
				      int,grapple_confirmid,
				      const void *,size_t);
extern int c2s_ping(internal_client_data *,int);
extern int c2s_pingreply(internal_client_data *,int);
extern int c2s_disconnect(internal_client_data *);
extern int c2s_request_group(internal_client_data *);
extern int c2s_group_create(internal_client_data *,int,const char *,
			    const char *);
extern int c2s_group_add(internal_client_data *,int,int,const char *);
extern int c2s_group_remove(internal_client_data *,int,int);
extern int c2s_group_delete(internal_client_data *,int);
extern int c2s_failover_cant(internal_client_data *);
extern int c2s_failover_tryme(internal_client_data *);
extern int c2s_send_reconnection(internal_client_data *);
extern int c2s_confirm_received(internal_client_data *,int,int);
extern int c2s_set_notify_state(internal_client_data *client,int notify);
extern int c2s_variable_send(internal_client_data *,grapple_variable *);

extern int s2c_handshake_failed(internal_server_data *,grapple_connection *);
extern int s2c_password_failed(internal_server_data *,grapple_connection *);
extern int s2c_unique_protectionkey_failed(internal_server_data *,grapple_connection *);
extern int s2c_unique_name_failed(internal_server_data *,grapple_connection *);
extern int s2c_server_closed(internal_server_data *,grapple_connection *);
extern int s2c_server_full(internal_server_data *,grapple_connection *);
extern int s2c_session_name(internal_server_data *,
			    grapple_connection *,const char *session);
extern int s2c_user_connected(internal_server_data *,
			      grapple_connection *,grapple_connection *);
extern int s2c_user_setname(internal_server_data *,
			    grapple_connection *,grapple_connection *);
extern int s2c_message(internal_server_data *,
		       grapple_connection *,int,int,const void *,size_t);
extern int s2c_inform_disconnect(internal_server_data *,
				 grapple_connection *,grapple_connection *);
extern int s2c_relaymessage(internal_server_data *,
			    grapple_connection *,grapple_connection *,
			    int,int,void *,size_t);
extern int s2c_ping(internal_server_data *,grapple_connection *,int);
extern int s2c_pingreply(internal_server_data *,grapple_connection *,int);
extern int s2c_disconnect(internal_server_data *,grapple_connection *);
extern int s2c_ping_data(internal_server_data *,
			 grapple_connection *,grapple_connection *);
extern int s2c_failover_off(internal_server_data *,grapple_connection *);
extern int s2c_failover_on(internal_server_data *,grapple_connection *);
extern int s2c_failover_cant(internal_server_data *,grapple_connection *,int);
extern int s2c_failover_can(internal_server_data *,
			    grapple_connection *,int,const char *);
extern int s2c_send_nextgroupid(internal_server_data *,
				grapple_connection *,int);
extern int s2c_group_create(internal_server_data *,
			    grapple_connection *,int,const char *,
			    const char *);
extern int s2c_group_add(internal_server_data *,grapple_connection *,int,int);
extern int s2c_group_remove(internal_server_data *,
			    grapple_connection *,int,int);
extern int s2c_group_delete(internal_server_data *,grapple_connection *,int);
extern int s2c_confirm_received(internal_server_data *,
				grapple_connection *,int);
extern int s2c_confirm_timeout(internal_server_data *,
			       grapple_connection *,grapple_confirm *);
extern int s2c_variable_send(internal_server_data *,
			     grapple_connection *,grapple_variable *);

extern int s2c_description_change(internal_server_data *,
				  grapple_connection *,const void *,size_t);

extern int s2SUQ_user_connected(internal_server_data *,grapple_connection *);
extern int s2SUQ_user_setname(internal_server_data *,grapple_connection *);
extern int s2SUQ_user_disconnect(internal_server_data *,grapple_connection *);
extern int s2SUQ_confirm_received(internal_server_data *,int);
extern int s2SUQ_confirm_timeout(internal_server_data *,grapple_confirm *);
extern int s2SUQ_group_remove(internal_server_data *,grapple_connection *,
			      grapple_user,grapple_user);

#endif
