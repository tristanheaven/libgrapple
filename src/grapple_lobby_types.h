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

#ifndef GRAPPLE_LOBBY_TYPES_H
#define GRAPPLE_LOBBY_TYPES_H

#include <sys/types.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef int grapple_lobby;
typedef int grapple_lobbyclient;
typedef int grapple_lobbygameid;
typedef int grapple_lobbyroomid;

#define GRAPPLE_LOBBY_ENTRY_ROOM "Entry"

  //flags, 1<<0 1<<1
#define GRAPPLE_LOBBY_GAMETYPE_NORMAL 1
#define GRAPPLE_LOBBY_GAMETYPE_DUMMY  2

typedef enum
  {
    GRAPPLE_LOBBYMSG_ROOMLEAVE    = 1,
    GRAPPLE_LOBBYMSG_ROOMENTER,
    GRAPPLE_LOBBYMSG_ROOMCREATE,
    GRAPPLE_LOBBYMSG_ROOMDELETE,
    GRAPPLE_LOBBYMSG_CHAT,
    GRAPPLE_LOBBYMSG_DISCONNECTED,
    GRAPPLE_LOBBYMSG_NEWGAME,
    GRAPPLE_LOBBYMSG_DELETEGAME,
    GRAPPLE_LOBBYMSG_GAME_MAXUSERS,
    GRAPPLE_LOBBYMSG_GAME_USERS,
    GRAPPLE_LOBBYMSG_GAME_CLOSED,
    GRAPPLE_LOBBYMSG_USERMSG,
    GRAPPLE_LOBBYMSG_NEWUSER,
    GRAPPLE_LOBBYMSG_CONNECTION_REFUSED,
    GRAPPLE_LOBBYMSG_USER_DISCONNECTED,
    GRAPPLE_LOBBYMSG_USER_JOINEDGAME,
    GRAPPLE_LOBBYMSG_USER_LEFTGAME,
    GRAPPLE_LOBBYMSG_GAME_DESCRIPTION,
  } grapple_lobbymessagetype;

typedef struct _grapple_lobbymessage
{
  grapple_lobbymessagetype type;

#if !defined __GNUC__ || (__GNUC__ > 2)
  union
  {
#endif
    struct _GLM_USER
    {
      grapple_user id;
      char *name;
    } USER;
    struct _GLM_CHAT
    {
      grapple_user id;
      size_t length;
      char *message;
    } CHAT;
    struct _GLM_ROOM
    {
      grapple_lobbyroomid roomid;
      grapple_user userid;
      char *name;
    } ROOM;
    struct _GLM_GAME
    {
      grapple_lobbygameid id;
      char *name;
      void *description;
      size_t descriptionlen;
      int maxusers;
      int currentusers;
      int needpassword;
      int closed;
    } GAME;
    struct _GLM_USERMSG
    {
      grapple_user id;
      void *data;
      size_t length;
    } USERMSG;
    struct _GLM_CONNECTION_REFUSED
    {
      grapple_connection_refused reason;
    } CONNECTION_REFUSED;
    struct _GLM_USERGAME
    {
      grapple_user userid;
      grapple_lobbygameid gameid;
    } USERGAME;
#if !defined __GNUC__ || (__GNUC__ > 2)
  };
#endif

  struct _grapple_lobbymessage *next;
  struct _grapple_lobbymessage *prev;

} grapple_lobbymessage;

typedef struct
{
  grapple_lobbygameid gameid;
  char *name;
  int currentusers;
  int maxusers;
  int needpassword;
  grapple_lobbyroomid room;
  int closed;
  void *description;
  size_t descriptionlen;
} grapple_lobbygame;

//The callback typedef
typedef int(*grapple_lobbycallback)(grapple_lobbymessage *,void *);


#ifdef __cplusplus
}
#endif

#endif
