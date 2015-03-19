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

#ifndef GRAPPLE_LOBBYCONNECTION_H
#define GRAPPLE_LOBBYCONNECTION_H

#include "grapple_lobby_internal.h"

extern grapple_lobbyconnection *grapple_lobbyconnection_create(void);
extern grapple_lobbyconnection *grapple_lobbyconnection_link(grapple_lobbyconnection *,
						     grapple_lobbyconnection *);
extern grapple_lobbyconnection *grapple_lobbyconnection_unlink(grapple_lobbyconnection *,
						       grapple_lobbyconnection *);
extern grapple_lobbyconnection *grapple_lobbyconnection_locate_by_name(grapple_lobbyconnection *,
							       const char *);
extern grapple_lobbyconnection *grapple_lobbyconnection_locate_by_id(grapple_lobbyconnection *,
								     grapple_user);
extern int grapple_lobbyconnection_dispose(grapple_lobbyconnection *);


#endif
