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

#ifndef GRAPPLE_CONFIRM_H
#define GRAPPLE_CONFIRM_H

#include "grapple_structs.h"

#define GRAPPLE_CONFIRM_TIMEOUT (10)

extern int register_confirm(grapple_connection *,int,int);
extern int unregister_confirm(internal_server_data*,
			      grapple_connection *,int,int);
extern int server_register_confirm(internal_server_data *,int,int);
extern int server_unregister_confirm(internal_server_data *,int,int);

extern void process_slow_confirms(internal_server_data *);

extern grapple_confirm *grapple_confirm_unlink(grapple_confirm *,
					       grapple_confirm *);

extern int grapple_confirm_spare_init(void);
extern int grapple_confirm_spare_cleanup(void);

extern int grapple_confirm_dispose(grapple_confirm *);

#endif
