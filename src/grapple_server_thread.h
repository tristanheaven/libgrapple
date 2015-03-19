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

#ifndef GRAPPLE_SERVER_THREAD_H
#define GRAPPLE_SERVER_THREAD_H

#include "grapple_server_internal.h"

#define HANDSHAKE_FLAG_GRAPPLE_VERSION (1<<0)
#define HANDSHAKE_FLAG_PRODUCT_NAME (1<<1)
#define HANDSHAKE_FLAG_PRODUCT_VERSION (1<<2)
#define HANDSHAKE_FLAG_PASSWORD (1<<3)
#define HANDSHAKE_FLAG_USERNAME (1<<4)
#define HANDSHAKE_FLAG_PROTECTIONKEY (1<<5)

extern int grapple_server_thread_start(internal_server_data *);
extern int user_set_delete(internal_server_data *,
			   grapple_connection *);

#endif
