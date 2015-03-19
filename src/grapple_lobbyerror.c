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

#include "grapple_configure_substitute.h"

#include "grapple_lobbyerror.h"
#include "grapple_lobby_internal.h"

//A local global variable that stores the last grapple error
static grapple_error global_lobby_error;

void grapple_lobbyerror_set(grapple_error error)
{
  global_lobby_error=error;
}

grapple_error grapple_lobbyerror_get()
{
  grapple_error returnval;

  returnval=global_lobby_error;

  //Now wipe the last error
  global_lobby_error=GRAPPLE_NO_ERROR;

  return returnval;
}
