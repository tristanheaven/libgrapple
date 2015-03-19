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

#ifndef GRAPPLE_LOBBYCALLBACK_H
#define GRAPPLE_LOBBYCALLBACK_H

#include "grapple_lobby_internal.h"
#include "grapple_lobby.h"

extern grapple_lobbycallback_internal *grapple_lobbycallback_add(grapple_lobbycallback_internal *,
								 grapple_lobbymessagetype,
								 grapple_lobbycallback,
								 void *);

extern grapple_lobbycallback_internal *grapple_lobbycallback_remove(grapple_lobbycallback_internal *,
								    grapple_lobbymessagetype);

extern int grapple_lobbyclient_callback_process(internal_lobbyclient_data *,
						grapple_lobbymessage *);
extern int grapple_lobby_callback_process(internal_lobby_data *,
					  grapple_lobbymessage *);


#endif
