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

#ifndef SOCKET_H
#define SOCKET_H

#include "grapple_configure_substitute.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#else
# ifdef HAVE_LIMITS_H
# include <limits.h>
# endif
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 255
#endif

#ifdef SOCK_SSL
#include <openssl/ssl.h>
#endif

#include "dynstring.h"

#ifndef SOCKET_INT_TYPE
#if (defined WIN32 && !defined HAVE_STDINT_H )
#define SOCKET_INT_TYPE __int32
#else
#define SOCKET_INT_TYPE int32_t
#endif
#endif

#ifdef _MSC_VER
#define SOCKET_FD_TYPE SOCKET
#else
#define SOCKET_FD_TYPE int
#endif

#define SOCKET_LISTENER (1<<0)
#define SOCKET_CONNECTING (1<<1)
#define SOCKET_CONNECTED (1<<2)

#define SOCKET_DELAYED_NOW_CONNECTED (1<<4)
#define SOCKET_DEAD (1<<5)
#define SOCKET_INCOMING (1<<6)

#define SOCKET_TCP (0)
#define SOCKET_UDP (1)
#define SOCKET_UNIX (2)
#define SOCKET_INTERRUPT (3)

#define SOCKET_MODE_UDP2W_SEQUENTIAL (1<<0)

//Internal
#define SOCKET_UDP2W_PROTOCOL_CONNECTION 0
#define SOCKET_UDP2W_PROTOCOL_DATA 1
#define SOCKET_UDP2W_PROTOCOL_CONNECTION_REPLY 2
#define SOCKET_UDP2W_PROTOCOL_RDATA 3
#define SOCKET_UDP2W_PROTOCOL_RCONFIRM 5
#define SOCKET_UDP2W_PROTOCOL_PING 7
#define SOCKET_UDP2W_PROTOCOL_CONNECTION_FROMLISTENER_REPLY 8
#define SOCKET_UDP2W_PROTOCOL_CONNECTION_ACKNOWLEDGE 9
#define SOCKET_UDP2W_PROTOCOL_OK_CONNECTION_ACKNOWLEDGE 10
#define SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA 11
#define SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA_FINAL 12
#define SOCKET_UDP2W_PROTOCOL_LISTENER_RELAY 13

#define SOCKET_UDP2W_STUN_PROTOCOL_MIN 99
#define SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC 100
#define SOCKET_UDP2W_STUN_REPLY_ADDRESS_BASIC 101
#define SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER 102
#define SOCKET_UDP2W_STUN_REPLY_FW_ADDRESS_FROM_ALT_SERVER 103
#define SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER 104
#define SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_SERVER 105
#define SOCKET_UDP2W_STUN_REQUEST_ALT_SERVER_ADDRESS 106
#define SOCKET_UDP2W_STUN_REPLY_ALT_SERVER_ADDRESS 107
#define SOCKET_UDP2W_STUN_REQUEST_ADDRESS_SECOND_BASIC 108
#define SOCKET_UDP2W_STUN_REPLY_ADDRESS_SECOND_BASIC 109
#define SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_PORT 110
#define SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_PORT 111
#define SOCKET_UDP2W_STUN_INT_SEND_ADDRESS_REPLY 112
#define SOCKET_UDP2W_STUN_KEEPALIVE 114
#define SOCKET_UDP2W_STUN_CONNECTBACK 115
#define SOCKET_UDP2W_STUN_CONNECT_REQUEST 116
#define SOCKET_UDP2W_STUN_PROTOCOL_MAX 117

#define SOCKET_UDP2W_TURN_PROTOCOL_MIN 150
#define SOCKET_UDP2W_TURN_DO 151
#define SOCKET_UDP2W_TURN_WILL 152
#define SOCKET_UDP2W_TURN_WONT 153
#define SOCKET_UDP2W_TURN_RELAY 154
#define SOCKET_UDP2W_TURN_RELAY_DATA 155
#define SOCKET_UDP2W_TURN_PROTOCOL_MAX 156


#define SOCKET_NAT_TYPE_UNKNOWN 0
#define SOCKET_NAT_TYPE_IN_PROCESS 1
#define SOCKET_NAT_TYPE_NONE 2
//This is a marker, anything numerically higher needs STUN used on
//client connection ports
#define SOCKET_NAT_TYPE_NEEDS_CLIENT_STUN 3
//End marker
#define SOCKET_NAT_TYPE_FULL_CONE 4
#define SOCKET_NAT_TYPE_RESTRICTED_CONE 5
#define SOCKET_NAT_TYPE_PORT_RESTRICTED_CONE 6
//This is a marker, anything numerically higher needs TURN used on
//client connection ports
#define SOCKET_NAT_TYPE_NEEDS_TURN 7
//End marker
#define SOCKET_NAT_TYPE_SYMMETRIC 8
#define SOCKET_NAT_TYPE_FW_SYMMETRIC 9


//

typedef struct _socket_udp_data
{
  struct sockaddr_in sa;
  char *data;
  size_t length;
} socket_udp_data;

typedef struct _socket_udp_rdata
{
  char *data;
  size_t length;
  int packetnum;
  int sent;
  int resend_count;
  int received_this_send;
  int split_index;
  struct timeval sendtime;
  size_t *range_starts;
  char **range_received;
  int ranges_left;
  int ranges_size;
  int found_last_range;
  struct _socket_udp_rdata *next;
  struct _socket_udp_rdata *prev;
} socket_udp_rdata;

typedef struct _socketbuf
{
  SOCKET_FD_TYPE fd;

#if defined WIN32 && defined HAVE_WINSOCK2_H
  WSAEVENT event;
#endif

  int debug;

  time_t connect_time;

  size_t bytes_in;
  size_t bytes_out;

  dynstring *indata;
  dynstring *outdata;

  int flags;

  int protocol;

  char *host;
  int port;
  char *path;
  int sendingport;

  int mode;

  struct sockaddr_in udp_sa;

  int interrupt_fd;

  //2 way UDP extras
  
  int udp2w;
  int udp2w_routpacket;
  int udp2w_rinpacket;
  long long udp2w_averound;
  time_t udp2w_nextping;
  time_t udp2w_lastmsg;
  char udp2w_unique[HOST_NAME_MAX+60+1];
  int udp2w_uniquelen;
  int udp2w_directport;
  struct sockaddr_in connect_sa;
  int udp2w_connectcounter;
  size_t udp2w_maxsend;
  size_t udp2w_minsend;
  size_t udp2w_fromserver_counter;
  int udp2w_relaying_via_connector;
  int udp2w_relay_by_listener;

  struct _socket_udp_rdata *udp2w_rdata_out;
  struct _socket_udp_rdata *udp2w_rdata_in;

  /////STUN data
  int stunserver;
  char *stun_host;
  char *stun2_host;
  int stun_port;
  int stun_port2; //Second sender on this machine
  int stun2_port; //Sender on second machine
  struct sockaddr_in stun_sa;
  struct sockaddr_in stun2_sa; //Sender on second machine
  SOCKET_FD_TYPE stun_fd2;
  char stun_unique[5+HOST_NAME_MAX+60+1]; //'STUN-' host port_and_time NULL

  char *published_address;
  int published_port;
  int stun_nat_type;
  int stun_connectcounter;
  int turn_connectcounter;
  int turn_refused;
  int turn_enabled;      //Stun server which will relay turn
  int use_turn;          //Any socket communicating via turn
  int stun_reconnectcounter;
  time_t stun_starttime;
  int stun_last_msg;
  int stun_stage;
  time_t stun_keepalive;

#ifdef SOCK_SSL
  //Encryption stuff
  int encrypted;
  SSL *ssl;
  SSL_CTX *ctx;

  char *private_key;
  char *private_key_password;
  char *public_key;
  char *ca;
#endif

  struct _socketbuf *parent;

  struct _socketbuf *new_children;
  struct _socketbuf *connected_children;


  struct _socketbuf *new_child_next;
  struct _socketbuf *new_child_prev;
  struct _socketbuf *connected_child_next;
  struct _socketbuf *connected_child_prev;
} socketbuf;  

typedef struct _socket_processlist
{
  socketbuf *sock;
  struct _socket_processlist *next;
  struct _socket_processlist *prev;
} socket_processlist;

typedef union 
{
  SOCKET_INT_TYPE i;
  char c[4];
} socket_intchar;

typedef struct
{
  char *serial;
  time_t not_before;
  time_t not_after;
  char *issuer;
  char *subject;
} socket_certificate;

extern size_t        socket_bytes_out(socketbuf *);
extern size_t        socket_bytes_in(socketbuf *);
extern int           socket_connected(socketbuf *);
extern socketbuf    *socket_create_inet_tcp(const char *,int);
extern socketbuf    *socket_create_inet_tcp_listener_on_ip(const char *,int);
extern socketbuf    *socket_create_inet_tcp_listener(int);
extern socketbuf    *socket_create_inet_udp_listener_on_ip(const char *,int);
extern socketbuf    *socket_create_inet_udp_listener(int);
extern socketbuf    *socket_create_inet_udp2way_listener_on_ip(const char *,int);
extern socketbuf    *socket_create_inet_udp2way_listener(int);
extern socketbuf    *socket_create_inet_tcp_wait(const char *,int,int);
extern socketbuf    *socket_create_inet_udp_wait(const char *,int,int);
extern socketbuf    *socket_create_inet_udp2way_wait(const char *,int,int);
extern socketbuf    *socket_create_inet_udp2way_wait_onport(const char *,int,
							    int,int);
#ifdef HAVE_SYS_UN_H
extern socketbuf    *socket_create_unix(const char *);
extern socketbuf    *socket_create_unix_wait(const char *,int);
extern socketbuf    *socket_create_unix_listener(const char *);
#endif
extern socketbuf    *socket_create_interrupt(void);
extern int          socket_interrupt(socketbuf *);
extern int           socket_dead(socketbuf *);
extern void          socket_destroy(socketbuf *);
extern int           socket_get_port(socketbuf *);
extern int           socket_get_sending_port(socketbuf *);
extern void          socket_indata_drop(socketbuf *,size_t);
extern size_t        socket_indata_length(socketbuf *);
extern size_t        socket_outdata_length(socketbuf *);
extern time_t        socket_connecttime(socketbuf *);
extern char         *socket_indata_pull(socketbuf *,size_t);
extern const char   *socket_indata_view(socketbuf *);
extern socket_udp_data *socket_udp_indata_pull(socketbuf *);
extern socket_udp_data *socket_udp_indata_view(socketbuf *);
extern int           socket_just_connected(socketbuf *);
extern socketbuf    *socket_new(socketbuf *);
extern int           socket_process(socketbuf *,long int);
extern int           socket_process_sockets(socket_processlist *,long int);
extern void          socket_debug_off(socketbuf *);
extern void          socket_debug_on(socketbuf *);
extern void          socket_write(socketbuf *,const char *,size_t);
extern void          socket_write_reliable(socketbuf *,const char *,size_t);

extern int           socket_udp_data_free(socket_udp_data *);

extern int           socket_mode_set(socketbuf *sock,unsigned int mode);
extern int           socket_mode_unset(socketbuf *sock,unsigned int mode);
extern unsigned int  socket_mode_get(socketbuf *sock);

extern const char   *socket_host_get(socketbuf *sock);

extern void          socket_relocate_data(socketbuf *from,socketbuf *to);

#ifdef SOCK_SSL
extern void          socket_set_encrypted(socketbuf *);
extern void          socket_set_private_key(socketbuf *,
					    const char *,const char *);
extern void          socket_set_public_key(socketbuf *,const char *);
extern void          socket_set_ca(socketbuf *,const char *);
#endif

extern socket_processlist *socket_link(socket_processlist *,socketbuf *);
extern socket_processlist *socket_unlink(socket_processlist *,socketbuf *);

extern const char **socket_get_interface_list(void);

extern socket_certificate *socket_certificate_get(socketbuf *);

//////////////STUN functions
extern int socket_inet_udp2way_listener_stun(socketbuf *,const char *,int);
extern int socket_inet_udp2way_listener_stun_complete(socketbuf *);
extern int socket_inet_udp2way_listener_stun_type_get(socketbuf *);
extern int socket_inet_udp2way_listener_stun_enable(socketbuf *,const char *,
						    int,int);
extern int socket_inet_udp2way_listener_turn_enable(socketbuf *);

extern socketbuf *socket_create_inet_udp2way_wait_onport_stun(const char *,
							      int,
							      int,int,
							      const char *,
							      int);


#endif
