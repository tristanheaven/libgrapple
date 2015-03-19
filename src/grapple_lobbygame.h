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

#ifndef GRAPPLE_LOBBYGAME_H
#define GRAPPLE_LOBBYGAME_H

#include "grapple_lobby_internal.h"


extern grapple_lobbygame_internal *grapple_lobbygame_internal_create(void);
extern grapple_lobbygame_internal *grapple_lobbygame_internal_link(grapple_lobbygame_internal *,
								   grapple_lobbygame_internal *);
extern grapple_lobbygame_internal *grapple_lobbygame_internal_unlink(grapple_lobbygame_internal *,
								     grapple_lobbygame_internal *);

grapple_lobbygame_internal *grapple_lobbyclient_game_internal_get(internal_lobbyclient_data *,
								  grapple_lobbygameid,
								  grapple_mutex_locktype);

grapple_lobbygame_internal *grapple_lobbyserver_game_internal_get(internal_lobby_data *,
								  grapple_lobbygameid,
								  grapple_mutex_locktype);

extern void grapple_lobbygame_internal_release(grapple_lobbygame_internal *);

extern int grapple_lobbygame_internal_dispose(grapple_lobbygame_internal *);

grapple_lobbygame_internal *grapple_lobbyclient_game_internal_get_byname(internal_lobbyclient_data *,
									 const char *,
									 grapple_mutex_locktype);


#endif
