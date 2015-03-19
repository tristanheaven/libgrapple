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

#ifndef GRAPPLE_QUEUE_H
#define GRAPPLE_QUEUE_H

#include "grapple_structs.h"

extern grapple_queue *queue_link(grapple_queue *,grapple_queue *);
extern grapple_queue *queue_struct_aquire(void);
extern grapple_queue *queue_unlink(grapple_queue *,grapple_queue *);
extern void queue_struct_dispose(grapple_queue *);
extern int grapple_queue_count(grapple_queue *);

extern int grapple_queue_spare_init(void);
extern int grapple_queue_spare_cleanup(void);

#endif
