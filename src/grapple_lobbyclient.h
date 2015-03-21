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

#ifndef GRAPPLE_LOBBYCLIENT_H
#define GRAPPLE_LOBBYCLIENT_H

#include <sys/types.h>

#include "grapple_lobby.h"
#include "grapple_lobby_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#pragma GCC visibility push(default)
#endif

extern grapple_lobbyclient grapple_lobbyclient_init(const char *,const char *);
extern int grapple_lobbyclient_address_set(grapple_lobbyclient, const char *);
extern int grapple_lobbyclient_port_set(grapple_lobbyclient,int);
extern int grapple_lobbyclient_name_set(grapple_lobbyclient, const char *);
extern int grapple_lobbyclient_password_set(grapple_lobbyclient,const char *);
extern char *grapple_lobbyclient_name_get(grapple_lobbyclient,grapple_user);
extern int grapple_lobbyclient_protectionkey_set(grapple_lobbyclient,
						 const char *);

extern int grapple_lobbyclient_start(grapple_lobbyclient);
extern int grapple_lobbyclient_destroy(grapple_lobbyclient);

extern int grapple_lobbyclient_room_create(grapple_lobbyclient,const char *,
					   const char *);
extern int grapple_lobbyclient_room_enter(grapple_lobbyclient,
					  grapple_lobbyroomid,const char *);
extern int grapple_lobbyclient_room_leave(grapple_lobbyclient);
extern int grapple_lobbyclient_chat(grapple_lobbyclient,const char *);
extern int grapple_lobbyclient_message_send(grapple_lobbyclient,
					    const void *,size_t);

extern grapple_lobbymessage *grapple_lobbyclient_message_pull(grapple_lobbyclient);

extern grapple_lobbygameid grapple_lobbyclient_game_register(grapple_lobbyclient,
							     grapple_server);
extern int grapple_lobbyclient_game_unregister(grapple_lobbyclient);
extern int grapple_lobbyclient_game_join(grapple_lobbyclient,
					 grapple_lobbygameid, grapple_client);
extern int grapple_lobbyclient_game_leave(grapple_lobbyclient,grapple_client);

extern grapple_lobbyroomid grapple_lobbyclient_currentroomid_get(grapple_lobbyclient);

extern grapple_lobbyroomid *grapple_lobbyclient_roomlist_get(grapple_lobbyclient);
extern char *grapple_lobbyclient_roomname_get(grapple_lobbyclient,
					      grapple_lobbyroomid);
extern grapple_lobbyroomid grapple_lobbyclient_roomid_get(grapple_lobbyclient,
							  const char *);

extern grapple_user *grapple_lobbyclient_roomusers_get(grapple_lobbyclient,
						       grapple_lobbyroomid);
extern grapple_lobbygameid *grapple_lobbyclient_gamelist_get(grapple_lobbyclient,
							     grapple_lobbyroomid);

extern grapple_lobbygame *grapple_lobbyclient_game_get(grapple_lobbyclient,grapple_lobbygameid);
extern int grapple_lobbyclient_game_dispose(grapple_lobbygame *);

extern int grapple_lobbyclient_callback_set(grapple_lobbyclient,
					    grapple_lobbymessagetype,
					    grapple_lobbycallback,
					    void *);
extern int grapple_lobbyclient_callback_setall(grapple_lobbyclient,
					       grapple_lobbycallback,
					       void *);
extern int grapple_lobbyclient_callback_unset(grapple_lobbyclient,
					      grapple_lobbymessagetype);

extern grapple_error grapple_lobbyclient_error_get(grapple_lobbyclient);

extern int grapple_lobbyclient_room_passwordneeded(grapple_lobbyclient,
						   grapple_lobbyroomid);

extern int grapple_lobbyclient_connected(grapple_lobbyclient);

extern char *grapple_lobbyclient_gamesession_get(grapple_lobbyclient,
						 grapple_lobbygameid);
extern grapple_lobbygameid grapple_lobbyclient_gameid_get(grapple_lobbyclient,
							  const char *);
extern int grapple_lobbyclient_game_maxusers_get(grapple_lobbyclient,
						 grapple_lobbygameid);
extern int grapple_lobbyclient_game_currentusers_get(grapple_lobbyclient,
						     grapple_lobbygameid);
extern int grapple_lobbyclient_game_closed_get(grapple_lobbyclient,
					       grapple_lobbygameid);
extern int grapple_lobbyclient_game_description_get(grapple_lobbyclient,
						    grapple_lobbygameid,
						    void *,size_t *);
extern int grapple_lobbyclient_id_get(grapple_lobbyclient);

extern int grapple_lobbyclient_encryption_enable(grapple_lobbyclient,
						 const char *,const char *,
						 const char *,const char *);

#if defined(__GNUC__)
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
}
#endif

#endif
