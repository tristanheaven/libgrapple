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

#ifndef GRAPPLE_LOBBY_INTERNAL_H
#define GRAPPLE_LOBBY_INTERNAL_H

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "grapple_types.h"
#include "grapple_lobby.h"
#include "grapple_thread.h"

#define GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_DISCONNECTED 0
#define GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_PENDING 1
#define GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_REJECTED 2
#define GRAPPLE_LOBBYCLIENT_CONNECTSTATUS_CONNECTED 3

typedef enum
  {
    GRAPPLE_LOBBYMESSAGE_CHAT                = 1,
    GRAPPLE_LOBBYMESSAGE_REGISTERGAME        = 2,
    GRAPPLE_LOBBYMESSAGE_YOURGAMEID          = 3,
    GRAPPLE_LOBBYMESSAGE_DELETEGAME          = 4,
    GRAPPLE_LOBBYMESSAGE_GAME_USERCOUNT      = 5,
    GRAPPLE_LOBBYMESSAGE_GAME_MAXUSERCOUNT   = 6,
    GRAPPLE_LOBBYMESSAGE_GAME_CLOSED         = 7,
    GRAPPLE_LOBBYMESSAGE_USERMSG             = 8,
    GRAPPLE_LOBBYMESSAGE_REQUEST_GAMELIST    = 9,
    GRAPPLE_LOBBYMESSAGE_USER_JOINEDGAME     = 10,
    GRAPPLE_LOBBYMESSAGE_USER_LEFTGAME       = 11,
    GRAPPLE_LOBBYMESSAGE_GAME_DESCRIPTION    = 12,
  } grapple_lobbymessagetype_internal;

typedef struct _grapple_lobbygame_internal
{
  grapple_lobbygameid id;
  char *session;
  char *address;
  int port;
  grapple_protocol protocol;
  int currentusers;
  int maxusers;
  int needpassword;
  int room;
  int closed;
  size_t descriptionlen;
  void *description;

  grapple_user owner;

  grapple_thread_mutex *inuse;

  grapple_user *users;

  struct _grapple_lobbygame_internal *next;
  struct _grapple_lobbygame_internal *prev;
} grapple_lobbygame_internal;

typedef struct _grapple_lobbyconnection 
{
  char *name;
  grapple_user id;
  grapple_lobbygameid ownsgame;
  grapple_lobbygameid ingame;
  grapple_user currentroom;
  int server_only;
  struct _grapple_lobbyconnection *next;
  struct _grapple_lobbyconnection *prev;
} grapple_lobbyconnection;

typedef struct _grapple_lobbycallback_internal
{
  grapple_lobbymessagetype type;
  void *context;
  grapple_lobbycallback callback;
  struct _grapple_lobbycallback_internal *next;
  struct _grapple_lobbycallback_internal *prev;
} grapple_lobbycallback_internal;


typedef struct _internal_lobby_data
{
  grapple_server server;
  grapple_lobby lobbynum;
  grapple_user mainroom;
  int roomcount;
  int roommax;
  grapple_thread_mutex *userlist_mutex;
  grapple_lobbyconnection *userlist;
  grapple_thread_mutex *message_mutex;
  grapple_lobbymessage *messages;
  grapple_thread_mutex *games_mutex;
  grapple_lobbygame_internal *games;
  int gamecount;
  grapple_thread_mutex *callback_mutex;
  grapple_lobbycallback_internal *callbacks;
  grapple_thread_mutex *inuse;
  struct _internal_lobby_data *next;
  struct _internal_lobby_data *prev;
} internal_lobby_data;

typedef struct _internal_lobbyclient_data
{
  grapple_client client;
  grapple_lobbyclient lobbyclientnum;
  char *name;
  char *password;
  int connectstatus;
  grapple_lobbygameid gameid;
  int ingame;
  grapple_error last_error;
  grapple_thread *thread;
  int threaddestroy;
  grapple_server runninggame;
  grapple_client joinedgame;
  grapple_user currentroom;
  grapple_user firstroom;
  grapple_user serverid;
  char *currentroompassword;
  grapple_thread_mutex *userlist_mutex;
  grapple_lobbyconnection *userlist;
  grapple_thread_mutex *message_mutex;
  grapple_lobbymessage *messages;
  grapple_thread_mutex *games_mutex;
  grapple_lobbygame_internal *games;
  grapple_thread_mutex *callback_mutex;
  grapple_thread_mutex *inuse;
  grapple_lobbycallback_internal *callbacks;
  struct _internal_lobbyclient_data *next;
  struct _internal_lobbyclient_data *prev;
} internal_lobbyclient_data;

#ifndef GRAPPLE_INT_TYPE
#if (defined WIN32 && !defined HAVE_STDINT_H )
#define GRAPPLE_INT_TYPE __int32
#else
#define GRAPPLE_INT_TYPE int32_t
#endif
#endif

typedef union
{
  GRAPPLE_INT_TYPE i;
  char c[4];
} intchar;


#endif
