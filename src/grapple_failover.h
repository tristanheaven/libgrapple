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

#ifndef GRAPPLE_FAILOVER_H
#define GRAPPLE_FAILOVER_H

#include "grapple_structs.h"

extern grapple_failover_host *failover_aquire(void);
extern void failover_dispose(grapple_failover_host *);

extern grapple_failover_host *failover_unlink(grapple_failover_host *,
					      grapple_failover_host *);
extern grapple_failover_host *failover_link(grapple_failover_host *,
					    grapple_failover_host *);

extern grapple_failover_host *failover_link_by_id(grapple_failover_host *,
						  int,const char *);
extern grapple_failover_host *failover_unlink_by_id(grapple_failover_host *,
						    int);

extern grapple_failover_host *failover_locate_lowest_id(grapple_failover_host *);

#endif
