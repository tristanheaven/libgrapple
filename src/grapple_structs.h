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

#ifndef GRAPPLE_STRUCTS_H
#define GRAPPLE_STRUCTS_H

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "grapple_callback.h"
#include "grapple_client.h"
#include "grapple_server.h"
#include "grapple_protocols.h"
#include "grapple_enums.h"
#include "socket.h"
#include "grapple_thread.h"

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

typedef union
{
  double d;
  char c[8];
} doublechar;

typedef struct _grapple_queue
{
  grapple_messagetype_internal messagetype;
  void *data;
  size_t length;
  unsigned int id;
  int reliablemode;
  int from; //Matches grapple_connection->serverid
  struct _grapple_queue *next;
  struct _grapple_queue *prev;
} grapple_queue;

typedef struct _grapple_callback_list
{
  grapple_callback callback;
  void *context;
  grapple_messagetype type;
  struct _grapple_callback_list *next;
  struct _grapple_callback_list *prev;
} grapple_callback_list;

typedef struct _grapple_confirm
{
  int messageid;
  int *receivers;
  int receivercount;
  int maxreceiver;
  time_t timeout;
  grapple_thread_mutex *confirm_mutex;
  struct _grapple_confirm *next;
  struct _grapple_confirm *prev;
} grapple_confirm;


typedef struct _grapple_group_container
{
  int id;
  struct _grapple_group_container *next;
  struct _grapple_group_container *prev;
} grapple_group_container;

typedef struct _internal_grapple_group
{
  int id;
  char *name;
  char *password;
  grapple_thread_mutex *container_mutex;
  grapple_group_container *contents;
  struct _internal_grapple_group *next;
  struct _internal_grapple_group *prev;
} internal_grapple_group;

typedef struct _grapple_variable
{
  char *name;
  void *data;
  int intdata;
  double doubledata;
  int vartype;
  size_t length;
  int sec;
  int usec;
  grapple_thread_mutex *mutex;
  struct _grapple_variable *next;
  struct _grapple_variable *prev;
} grapple_variable;


typedef struct
{
  int bucket_count;
  grapple_variable **bucket;
  grapple_thread_mutex **bucket_mutex;
} grapple_variable_hash;

typedef struct _grapple_connection
{
  socketbuf *sock;
  socketbuf *failoversock;
  int sequential;
  char *name;
  int serverid;
  int reconnectserverid;
  int me;
  int deleted;
  int handshook;
  int handshakeflags;
  int reconnecting;
  int notify;
  char *protectionkey;
  struct timeval pingstart;
  int pingnumber;
  double pingtime;
  struct timeval pingend;
  grapple_protocol protocol;
  int reliablemode;
  grapple_group_container *groups;
  grapple_confirm *confirm;
  grapple_thread_mutex *confirm_mutex;
  grapple_thread_mutex *message_out_mutex;
  grapple_thread_mutex *message_in_mutex;
  grapple_thread_mutex *group_mutex;
  grapple_queue *message_in_queue;
  grapple_queue *message_out_queue;
  struct _grapple_connection *next;
  struct _grapple_connection *prev;
} grapple_connection;

typedef struct
{
  grapple_thread *thread;
  int finished;
  struct _internal_server_data *server;
  struct _internal_client_data *client;
} grapple_callback_dispatcher;

typedef struct _grapple_failover_host
{
  int id;
  char *address;
  struct _grapple_failover_host *next;
  struct _grapple_failover_host *prev;
} grapple_failover_host;

typedef struct _internal_server_data
{
  grapple_server servernum;
  int port;
  grapple_protocol protocol;
  socketbuf *sock;
  int sequential;
  int reliablemode;
  int closed;
  int usercount;
  int maxusers;
  int groupcount;
  int maxgroups;
  int dummymode;
  char *ip;
  char *productname;
  char *productversion;
  char *session;
  char *description;
  size_t descriptionlen;
  char *password;
  grapple_password_callback passwordhandler;
  void *passwordhandlercontext;
  grapple_connection_callback connectioncallbackhandler;
  void *connectioncallbackhandlercontext;
  grapple_thread *thread;
  int threaddestroy;
  int failover;
  int timeout;
  int user_serverid;
  char *nattrav_server_hostname;
  int nattrav_server_port;
  char *nattrav_server2_hostname;
  int nattrav_server2_port;
  int nattrav_server_port2;
  int nattrav_state;
  int nattrav_turn_enabled;
#ifdef SOCK_SSL
  int encrypted;
  char *public_key;
  char *private_key;
  char *private_key_password;
  char *cert_auth;
#endif
  socketbuf *wakesock;
  time_t reconnect_expire;
  grapple_error last_error;
  time_t last_confirm_check;
  grapple_confirmid sendwait;
  double autoping;
  grapple_confirm *confirm;
  grapple_namepolicy namepolicy;
  grapple_protectionkeypolicy protectionkeypolicy;
  grapple_thread_mutex *internal_mutex;
  grapple_thread_mutex *confirm_mutex;
  grapple_variable_hash *variables;
  grapple_failover_host *failoverhosts;
  internal_grapple_group *groups;
  grapple_thread_mutex *callback_mutex;
  grapple_callback_list *callbackanchor;
  grapple_thread_mutex *message_in_mutex;
  grapple_queue *message_in_queue;
  grapple_thread_mutex *connection_mutex;
  grapple_thread_mutex *group_mutex;
  grapple_thread_mutex *failover_mutex;
  grapple_thread_mutex *inuse;
  socket_processlist *socklist;
  grapple_connection *userlist;
  int notify;
  int dispatcher_count;
  grapple_callback_dispatcher **dispatcherlist;
  grapple_thread_mutex *dispatcher_mutex;
  struct _grapple_callbackevent *event_queue;
  grapple_thread_mutex *event_queue_mutex;
  struct _internal_server_data *next;
  struct _internal_server_data *prev;
} internal_server_data;

typedef struct _internal_client_data
{
  grapple_client clientnum;
  char *address;
  int port;
  int sourceport;
  grapple_protocol protocol;
  char *name_provisional;
  char *name;
  int serverid;
  char *session;
  char *password;
  socketbuf *sock;
  socketbuf *failoversock;
  socketbuf *reverse_stun_sock;
  int reverse_stun_port;
  char *nattrav_server_hostname;
  int nattrav_server_port;
  int sequential;
  int reliablemode;
  int next_group;
  char *productname;
  char *productversion;
  grapple_thread *thread;
  int connecting;
  int disconnected;
  int threaddestroy;
  int failover;
  int timeout;
  int notify;
  char *protectionkey;
#ifdef SOCK_SSL
  int encrypted;
  char *public_key;
  char *private_key;
  char *private_key_password;
  char *cert_auth;
#endif
  socketbuf *wakesock;
  grapple_error last_error;
  struct timeval pingstart;
  int pingnumber;
  double pingtime;
  socket_processlist *socklist;
  grapple_confirmid sendwait;
  struct timeval pingend;
  grapple_variable_hash *variables;
  grapple_failover_host *failoverhosts;
  internal_grapple_group *groups;
  grapple_thread_mutex *internal_mutex;
  grapple_thread_mutex *callback_mutex;
  grapple_callback_list *callbackanchor;
  grapple_thread_mutex *message_in_mutex;
  grapple_queue *message_in_queue;
  grapple_thread_mutex *message_out_mutex;
  grapple_queue *message_out_queue;
  grapple_thread_mutex *connection_mutex;
  grapple_thread_mutex *group_mutex;
  grapple_thread_mutex *failover_mutex;
  grapple_thread_mutex *inuse;
  grapple_connection *userlist;
  int dispatcher_count;
  grapple_callback_dispatcher **dispatcherlist;
  grapple_thread_mutex *dispatcher_mutex;
  struct _grapple_callbackevent *event_queue;
  grapple_thread_mutex *event_queue_mutex;
  struct _internal_client_data *next;
  struct _internal_client_data *prev;
} internal_client_data;

#endif
