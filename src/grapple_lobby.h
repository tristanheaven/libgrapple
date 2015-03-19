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

#ifndef GRAPPLE_LOBBY_H
#define GRAPPLE_LOBBY_H

#include <sys/types.h>

#include "grapple_defines.h"
#include "grapple_error.h"
#include "grapple_message.h"
#include "grapple_protocols.h"
#include "grapple_types.h"
#include "grapple_server.h"

#include "grapple_lobby_types.h"
#include "grapple_lobbyclient.h"

#ifdef __cplusplus
extern "C" {
#endif

/////////////////////SERVER//////////////////////

extern grapple_lobby grapple_lobby_init(const char *,const char *);
extern int grapple_lobby_ip_set(grapple_lobby,const char *);
extern int grapple_lobby_port_set(grapple_lobby,int);
extern int grapple_lobby_password_set(grapple_lobby,const char *);
extern int grapple_lobby_protectionkeypolicy_set(grapple_lobby,
						 grapple_protectionkeypolicy);

extern int grapple_lobby_passwordhandler_set(grapple_lobby,
					     grapple_password_callback,
					     void *);

extern int grapple_lobby_connectionhandler_set(grapple_lobby,
					       grapple_connection_callback,
					       void *);

extern int grapple_lobby_start(grapple_lobby);


extern int grapple_lobby_destroy(grapple_lobby);

extern int grapple_lobby_callback_set(grapple_lobby,
				      grapple_lobbymessagetype,
				      grapple_lobbycallback,
				      void *);
extern int grapple_lobby_callback_setall(grapple_lobby,
					 grapple_lobbycallback,
					 void *);
extern int grapple_lobby_callback_unset(grapple_lobby,
					grapple_lobbymessagetype);
  
extern int grapple_lobby_message_send(grapple_lobby,grapple_user,
				      const void *,size_t);

extern int grapple_lobby_maxusers_set(grapple_lobby,int);
extern int grapple_lobby_maxusers_get(grapple_lobby);
extern int grapple_lobby_currentusers_get(grapple_lobby);
extern int grapple_lobby_roomlimit_set(grapple_lobby,int);
extern int grapple_lobby_roomlimit_get(grapple_lobby);

extern grapple_error grapple_lobby_error_get(grapple_lobby);

extern grapple_lobbygameid *grapple_lobby_gamelist_get(grapple_lobby,
						       grapple_lobbyroomid);

extern grapple_user *grapple_lobby_game_users_get(grapple_lobby,
						  grapple_lobbygameid);

extern grapple_user *grapple_lobby_users_get(grapple_lobby);
extern char *grapple_lobby_user_name_get(grapple_lobby,grapple_user);

extern int grapple_lobby_user_server_only_set(grapple_lobby,grapple_user);
extern int grapple_lobby_user_server_only_get(grapple_lobby,grapple_user);

extern int grapple_lobby_encryption_enable(grapple_lobby,
					   const char *,const char *,
					   const char *,const char *);

extern grapple_certificate *grapple_lobby_user_certificate_get(grapple_lobby,
							       grapple_user);

extern int grapple_lobby_disconnect_client(grapple_lobby,grapple_user);
extern grapple_lobbymessage *grapple_lobby_message_pull(grapple_lobby);

/////////////////////////OTHER//////////////////////
extern int grapple_lobbymessage_dispose(grapple_lobbymessage *);

#ifdef __cplusplus
}
#endif

#endif
