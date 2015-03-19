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

#ifndef GRAPPLE_ENUMS_H
#define GRAPPLE_ENUMS_H

typedef enum
  {
    GRAPPLE_MESSAGE_GRAPPLE_VERSION        =  1,
    GRAPPLE_MESSAGE_PRODUCT_NAME           =  2,
    GRAPPLE_MESSAGE_PRODUCT_VERSION        =  3,
    GRAPPLE_MESSAGE_USER_CONNECTED         =  4,
    GRAPPLE_MESSAGE_USER_YOU_CONNECTED     =  5,
    GRAPPLE_MESSAGE_USER_NAME              =  6,
    GRAPPLE_MESSAGE_USER_MESSAGE           =  7,
    GRAPPLE_MESSAGE_USER_DISCONNECTED      =  8,
    GRAPPLE_MESSAGE_SERVER_DISCONNECTED    =  9,
    GRAPPLE_MESSAGE_HANDSHAKE_FAILED       = 10,
    GRAPPLE_MESSAGE_SESSION_NAME           = 11,
    GRAPPLE_MESSAGE_RELAY_TO               = 12,
    GRAPPLE_MESSAGE_RELAY_ALL              = 13,
    GRAPPLE_MESSAGE_RELAY_ALL_BUT_SELF     = 14,
    GRAPPLE_MESSAGE_SERVER_FULL            = 15,
    GRAPPLE_MESSAGE_SERVER_CLOSED          = 16,
    GRAPPLE_MESSAGE_PASSWORD               = 17,
    GRAPPLE_MESSAGE_PASSWORD_FAILED        = 18,
    GRAPPLE_MESSAGE_PING                   = 19,
    GRAPPLE_MESSAGE_PING_REPLY             = 20,
    GRAPPLE_MESSAGE_PING_DATA              = 21,
    GRAPPLE_MESSAGE_FAILOVER_OFF           = 22,
    GRAPPLE_MESSAGE_FAILOVER_ON            = 23,
    GRAPPLE_MESSAGE_FAILOVER_CANT          = 24,
    GRAPPLE_MESSAGE_FAILOVER_TRYME         = 25,
    GRAPPLE_MESSAGE_FAILOVER_CAN           = 26,
    GRAPPLE_MESSAGE_NEXT_GROUPID           = 27,
    GRAPPLE_MESSAGE_REQUEST_NEXT_GROUPID   = 28,
    GRAPPLE_MESSAGE_GROUP_CREATE           = 29,
    GRAPPLE_MESSAGE_GROUP_ADD              = 30,
    GRAPPLE_MESSAGE_GROUP_REMOVE           = 31,
    GRAPPLE_MESSAGE_GROUP_DELETE           = 32,
    GRAPPLE_MESSAGE_YOU_ARE_HOST           = 33,
    GRAPPLE_MESSAGE_RECONNECTION           = 34,
    GRAPPLE_MESSAGE_CONFIRM_RECEIVED       = 35,
    GRAPPLE_MESSAGE_CONFIRM_TIMEOUT        = 36,
    GRAPPLE_MESSAGE_NOTIFY_STATE           = 37,
    GRAPPLE_MESSAGE_NAME_NOT_UNIQUE        = 38,
    GRAPPLE_MESSAGE_VARIABLE               = 39,
    GRAPPLE_MESSAGE_GAME_DESCRIPTION       = 40,
    GRAPPLE_MESSAGE_PROTECTIONKEY          = 41,
    GRAPPLE_MESSAGE_PROTECTIONKEY_NOT_UNIQUE = 42,
  } grapple_messagetype_internal;


#endif
