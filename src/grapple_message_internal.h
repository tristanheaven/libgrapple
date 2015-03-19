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

#ifndef GRAPPLE_MESSAGE_INTERNAL_H
#define GRAPPLE_MESSAGE_INTERNAL_H

#include "grapple_structs.h"
#include "grapple_message.h"

extern grapple_message *server_convert_message_for_user(grapple_queue *);
extern grapple_message *client_convert_message_for_user(grapple_queue *);

extern grapple_messagetype grapple_message_convert_to_usermessage_enum(grapple_messagetype_internal);

extern int grapple_message_spare_init(void);
extern int grapple_message_spare_cleanup(void);

#endif
