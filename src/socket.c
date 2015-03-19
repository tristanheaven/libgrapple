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

/*
  IMPORTANT NOTE ABOUT THREAD SAFETY IN SOCKET.C
  
  socket.c is only threadsafe when a listener and all of its children are
  handled in the same thread. If you hand off a thread to each listener and
  process it, then there will be problems is the listener or server are
  behind a firewall or NAT and you use UDP
  
  If this is not the case, then there is no race condition. The only
  problem is when a firewall or NAT is present on the client AND server
  side, and the server is half cone and the client is symmetric.
*/

#define _XOPEN_SOURCE 500

#include "grapple_configure_substitute.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <string.h>
#include <ctype.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <time.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif
#include "socket.h"

#ifdef WIN32
#define ioctl(x,y,z) ioctlsocket(x,y,z)
#define close(x) closesocket(x)
#endif

#ifdef HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#else
# ifdef HAVE_LIMITS_H
# include <limits.h>
# endif
#endif

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif


#ifdef SOCK_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif

#include "dynstring.h"
#include "socket.h"
#include "tools.h"

//#define SSL_DEBUG
//#define UDP_PROTOCOL_DEBUG
//#define STUN_DEBUG
//#define TURN_DEBUG

#ifndef HAVE_INET_NTOP
static const char *inet_ntop(int af, const void *src, char *dst, 
			     socklen_t cnt)      
{                                                                             
  if (af == AF_INET)                                                      
    {                                                                       
      char* tmp = inet_ntoa(*((struct in_addr*) src));                
      memcpy(dst, tmp, cnt);                                          
      return dst;                                                     
    }                                                                       
  return NULL;                                                            
}                                                                             
#endif

#ifndef HAVE_INET_PTON
static int inet_pton(int af, const char *src, void *dst)
{
  if (af == AF_INET)
    {
      ((struct in_addr*) dst)->s_addr = inet_addr(src);
      return 1;
    }
  return -1;
}
#endif

static int udp_replyport=20000;

extern FILE *popen(const char *,const char *);

static int socket_udp2way_connectmessage(socketbuf *);
static int socket_udp2way_listener_data_process(socketbuf *,
						struct sockaddr_in *,
						socklen_t,signed char *,int);
static int socket_udp2way_reader_data_process(socketbuf *,
					      struct sockaddr_in *,
					      socklen_t,signed char *,int);

static int socket_udp2way_stun_start(socketbuf *);
static int socket_udp2way_stun_start_stage1(socketbuf *);
static int socket_udp2way_reader_stun_process(socketbuf *,
					      struct sockaddr_in *,socklen_t,
					      signed char *,int,int);
static int socket_udp2way_reader_turn_process(socketbuf *,
					      struct sockaddr_in *,socklen_t,
					      signed char *,int,int);
static int socket_udp2way_stun_ping(socketbuf *);
static int socket_client_request_connect_via_stun(socketbuf *);
static int socket_client_request_connect_via_turn(socketbuf *);

//Most basic function, read/write. This is abstracted out as it needs
//some ifdefs and the code looks pretty ugly if itsleft inline. However leave
//the compiler a request to put it back where it belongs by inline'ing it

#ifdef WIN32
static int write_fn(SOCKET_FD_TYPE fd, const void *buf, size_t count)
{
  return send(fd,(const char *)buf,(int)count,0);
}
#else
static inline ssize_t write_fn(SOCKET_FD_TYPE fd, const void *buf, size_t count)
{
  return write(fd,buf,count);
}
#endif  

#ifdef WIN32
static int read_fn(SOCKET_FD_TYPE fd, void *buf, int count)
{
  return recv(fd,(char *)buf,count,0);
}
#else
static inline ssize_t read_fn(SOCKET_FD_TYPE fd, void *buf, size_t count)
{
  return read(fd,buf,count);
}
#endif  

#ifdef SOCK_SSL

//Handle the SSL errors

static int ssl_process_error(SSL *ssl,int rv)
{
  switch (SSL_get_error(ssl,rv))
    {
    case SSL_ERROR_WANT_READ:      
#ifdef SSL_DEBUG
      printf("Error=want_read\n");
#endif
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_NONE:
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_X509_LOOKUP:
      rv=0;      //Set rv (the retutn value) to 0 for each of these errors
      break;
    case SSL_ERROR_ZERO_RETURN:
#ifdef SSL_DEBUG
      printf("Error: Zero Return\n");
#endif
      rv=-1;
      break;
    case SSL_ERROR_SSL:
#ifdef SSL_DEBUG
      {
	printf("%s\n",ERR_error_string(ERR_get_error(),NULL));
      }
#endif
      rv=-1;
      break;
    case SSL_ERROR_SYSCALL:
      if (rv==-1)
        { 
          if (errno==EAGAIN)
            rv=0;
        }
      else
        rv=-1;
      break;
    }
  return rv;
}

static int ssl_key_password_callback(char* buf, int buf_size,
                                     int x, void* password)
{
  int len;
  if (!password)
    {
      strcpy(buf, "");
      return 0;
    }

  len = strlen((char*)password);
  if (len >= buf_size)
    len = buf_size-1;
  memcpy(buf, (char*)password, len);
  buf[len] = '\0';
  return len;
}

static BIO *memory_buf_BIO(const char* buf, int len)
{
  BIO* bio;
  BUF_MEM* mem;

  if (!buf)
    return NULL;

  if (len == -1)
    len = strlen(buf);

  bio = BIO_new(BIO_s_mem());
  if (!bio)
    return NULL;

  mem = BUF_MEM_new();
  if (!mem)
    {
      BIO_free(bio);
      return NULL;
    }

  if (!BUF_MEM_grow(mem, len))
    {
      BUF_MEM_free(mem);
      BIO_free(bio);
      return NULL;
    }

  memcpy(mem->data, buf, len);
  BIO_set_mem_buf(bio, mem, 0);
  return bio;
}

socket_certificate *socket_certificate_get(socketbuf *sock)
{
  X509 *cert;
  X509_NAME *subject;
  X509_NAME *issuer;
  X509_NAME_ENTRY *entry;
  int pos;
  unsigned char *ustr,*uptr;
  char *str;
  socket_certificate *returnval;
  BIGNUM *bignum;
  ASN1_TIME *timenum;
  struct tm timestruct;

  if (sock->encrypted!=1)
    return NULL;

  cert=SSL_get_peer_certificate(sock->ssl);

  if (!cert)
    return NULL;

  returnval=(socket_certificate *)calloc(1,sizeof(socket_certificate));

  subject=X509_get_subject_name(cert);
  pos=-1;
  pos=X509_NAME_get_index_by_NID(subject, NID_commonName, pos);
  entry=X509_NAME_get_entry(subject, pos);
  ASN1_STRING_to_UTF8(&ustr, X509_NAME_ENTRY_get_data(entry));
  returnval->subject=(char *)malloc(strlen(ustr)+1);
  strcpy(returnval->subject,ustr);

  issuer=X509_get_issuer_name(cert);
  pos=-1;
  pos=X509_NAME_get_index_by_NID(issuer, NID_commonName, pos);
  entry=X509_NAME_get_entry(issuer, pos);
  ASN1_STRING_to_UTF8(&ustr, X509_NAME_ENTRY_get_data(entry));
  returnval->issuer=(char *)malloc(strlen(ustr)+1);
  strcpy(returnval->issuer,ustr);

  bignum=ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
  str=BN_bn2dec(bignum);
  returnval->serial=(char *)malloc(strlen(str)+1);
  strcpy(returnval->serial,str);

  timenum=X509_get_notBefore(cert);
  ASN1_STRING_to_UTF8(&ustr, timenum);
  //Now using this string to make a time structure
  if (ustr && *ustr)
    {
      //Second
      uptr=ustr+10;
      timestruct.tm_sec=atoi(uptr);
      //Minute
      *uptr=0;
      uptr-=2;
      timestruct.tm_min=atoi(uptr);
      //Hour
      *uptr=0;
      uptr-=2;
      timestruct.tm_hour=atoi(uptr);
      //Date
      *uptr=0;
      uptr-=2;
      timestruct.tm_mday=atoi(uptr);
      //Month
      *uptr=0;
      uptr-=2;
      timestruct.tm_mon=atoi(uptr)-1;
      //Year
      *uptr=0;
      uptr-=2;
      timestruct.tm_year=atoi(uptr)+100;

      returnval->not_before=mktime(&timestruct);
    }
      
  timenum=X509_get_notAfter(cert);
  ASN1_STRING_to_UTF8(&ustr, timenum);
  //Now using this string to make a time structure
  if (ustr && *ustr)
    {
      //Second
      uptr=ustr+10;
      timestruct.tm_sec=atoi(uptr);
      //Minute
      *uptr=0;
      uptr-=2;
      timestruct.tm_min=atoi(uptr);
      //Hour
      *uptr=0;
      uptr-=2;
      timestruct.tm_hour=atoi(uptr);
      //Date
      *uptr=0;
      uptr-=2;
      timestruct.tm_mday=atoi(uptr);
      //Month
      *uptr=0;
      uptr-=2;
      timestruct.tm_mon=atoi(uptr)-1;
      //Year
      *uptr=0;
      uptr-=2;
      timestruct.tm_year=atoi(uptr)+100;

      returnval->not_after=mktime(&timestruct);
    }
  
  return returnval;
}

//Function to initialise the socket to be encrypted
static int socket_set_encrypted_keys(socketbuf *sock)
{
  int rv;
  EVP_PKEY *key=NULL;
  X509 *cert=NULL;
  RSA *rsakey=NULL;
  BIO* bio = NULL;
  char ca_filename[128+1];
  int fd=0;

  SSL_METHOD *ssl_meth=0;

  if (sock->flags & SOCKET_LISTENER ||
      sock->flags & SOCKET_INCOMING)
    ssl_meth=SSLv23_server_method();
  else
    ssl_meth=SSLv23_client_method();
    
  sock->ctx = SSL_CTX_new(ssl_meth);
  if (!sock->ctx)
    {
#ifdef SSL_DEBUG
      printf("Failed making CTX\n");
#endif
      sock->encrypted=0;
      sock->flags |= SOCKET_DEAD;
      return 0;
    }

  //First load the CA
  if (sock->ca)
    {
      sprintf(ca_filename,"/tmp/.grapple_ca_file_XXXXXX");
      fd=mkstemp(ca_filename);

      if (fd>0)
	{
	  write(fd,sock->ca,strlen(sock->ca));
	  close(fd);
	  //SOMEONE tell me how to do this with a BIO
	  rv=SSL_CTX_load_verify_locations(sock->ctx,
					   ca_filename,NULL);
	  unlink(ca_filename);
	}
      else
	rv=0;
      
#ifdef SSL_DEBUG	  
      if (rv)
	printf("CA file loaded OK\n");
#endif
      if (!rv)
	{
	  SSL_CTX_free(sock->ctx);
	  sock->ctx=0;
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Failed to load CA\n");
#endif
	  return 0;
	}

      //The CA loaded, now tell this context to always verify
      //      if (sock->flags & SOCKET_LISTENER)
	{
	  SSL_CTX_set_verify(sock->ctx,SSL_VERIFY_PEER,NULL);
	  SSL_CTX_set_verify_depth(sock->ctx,10);
	}
    }
  
  if (sock->private_key && *sock->private_key)
    {
      //Extract private key
      bio = memory_buf_BIO(sock->private_key, -1);
      if (bio)
        {
	  if (sock->private_key_password && *sock->private_key_password)
	    {
	      key=PEM_read_bio_PrivateKey(bio,NULL, ssl_key_password_callback,
					  (void*)sock->private_key_password);
	      if (!key)
		{
		  //Invalid password
		  sock->encrypted=0;
		  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
		  printf("Bad Password\n");
#endif
		  return 0;
		}
	    }
	  else
	    key=PEM_read_bio_PrivateKey(bio,NULL, NULL, NULL);

          BIO_free(bio);
        }
    }

  if (sock->public_key && *sock->public_key)
    {
      //Extract Public Key
      bio = memory_buf_BIO(sock->public_key, -1);
      if (bio)
        {
          cert = PEM_read_bio_X509(bio,NULL,NULL,NULL);
          BIO_free(bio);
        }
    }

  if (!key)
    {
      /*Here we generate a new temporary key*/
#ifdef SSL_DEBUG
      printf("Generating keys\n");
#endif

      unsigned char *str;
      unsigned char *certbuf;
      RSA *pubrsa;
      int len;
      size_t required_size;
      EVP_PKEY *tmp_pkey=NULL;
      ASN1_INTEGER *serial;
      BIGNUM *bignum;
      ASN1_TIME *timebound;
      time_t t;
      X509_NAME *subject;
      char name[10];
      
      //Generate the key pair, this gives public and private keys
      rsakey=RSA_generate_key(1024,RSA_F4,NULL,NULL);

      //Now get the private key.
      key = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(key, rsakey);

      //This is all we need to do for the private key

      //Now find out how much space we need to store the public key buffer,
      //using NULL here does this.
      required_size = i2d_RSAPublicKey(rsakey,NULL);

      //Allocate the space
      certbuf=(unsigned char *)malloc(required_size+1);

      //Move str to certbuf. Str will move around a lot, and we need to
      //keep certbuf clean for free()ing later
      str=certbuf;

      //This puts the public key (generated earlier) into str, which is certbuf
      len = i2d_RSAPublicKey(rsakey,&str);

      //The above function moves str for some unknown reason, so reset it
      str=certbuf;

      //Now create a nbew RSA structure using the public key in certbuf
      pubrsa=d2i_RSAPublicKey(NULL,(const unsigned char **)&str,len);
      
      //We're done with certbuf now.
      free(certbuf);

      //Now we create a new EVP_PKEY based on the public key.
      tmp_pkey = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(tmp_pkey, pubrsa);

      //Create the certificate, blank
      cert=X509_new();


      //Finally set the public key into the X509 certificate
      X509_set_pubkey(cert,tmp_pkey);

      //Set random data into the key

      //Set version 3
      X509_set_version(cert,3);

      //Set a 64 bit number as the serial
      serial = ASN1_INTEGER_new();
      if (serial)
	{
	  bignum=BN_new();
	  if (bignum)
	    {
	      if (BN_pseudo_rand(bignum, 64, 0, 0))
		{
		  if (BN_to_ASN1_INTEGER(bignum, serial))
		    {
		      X509_set_serialNumber(cert, serial);
		    }
		}
	      BN_free(bignum);
	    }
	  ASN1_INTEGER_free(serial);
	}

      //Not before yesterday
      timebound = ASN1_TIME_new();
      ASN1_TIME_set(timebound,t=-(60*60*24));
      X509_set_notBefore(cert,timebound);
      ASN1_TIME_free(timebound);

      //Not after 10 years (ok for a temp cert)
      timebound = ASN1_TIME_new();
      ASN1_TIME_set(timebound,t=(60*60*24*365*10));
      X509_set_notAfter(cert,timebound);
      ASN1_TIME_free(timebound);


      strcpy(name,"Grapple");
      subject=X509_NAME_new();
      X509_NAME_add_entry_by_txt( subject, "CN", MBSTRING_ASC, 
				  (unsigned char *) name, 7, -1, 0);
      
      X509_set_subject_name(cert,subject);
      X509_set_issuer_name(cert,subject);
      X509_NAME_free(subject);

      X509_sign(cert, key, EVP_md5());

      //Free up the EVP_PKEY structure and we're done
      EVP_PKEY_free(tmp_pkey);
    }

  if (!key || !cert)
    {
      sock->encrypted=0;
      sock->flags |= SOCKET_DEAD;

      return 0;
    }

  rv=SSL_CTX_use_PrivateKey(sock->ctx,key);

  rv=SSL_CTX_use_certificate(sock->ctx,cert);
  
  if (!SSL_CTX_check_private_key(sock->ctx)) 
    {
      fprintf(stderr,"Private key does not match the certificate public key\n");
      sock->encrypted=0;
      sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
      printf("Key didnt match certificate\n");
#endif
      return 0;
    }

#ifdef SSL_DEBUG
  printf("Keys loaded\n");
#endif

  return 1;
}

//Set the socket to be a host type encrypted socket - so other sockets will
//verify against it.
static void socket_set_server_encrypted(socketbuf *sock)
{
  int rv;

  if (sock->encrypted==2)
    {
      sock->ctx = sock->parent->ctx;
      if (!sock->ctx)
	{
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;

	  return;
	}

      sock->ssl = SSL_new(sock->ctx);
      if (!sock->ssl)
	{
	  sock->ctx=0;
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Server failed to make SSL\n");
#endif
	  return;
	}

      if (!SSL_set_fd(sock->ssl,sock->fd))
	{
	  sock->ctx=0;
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Server failed to link fd to SSL\n");
#endif
	  return;
	}

      sock->encrypted=3;
    }
  
  if (sock->encrypted==3)
    {
      rv=SSL_accept(sock->ssl);

      if (rv<1)
	{
	  rv=ssl_process_error(sock->ssl,rv);
	}

      if (rv<0)
	{
	  sock->ctx=0;
	  
	  SSL_free(sock->ssl);
	  sock->ssl=0;

	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Servers accept failed\n");
#endif
	  return;
	}

      if (rv==0)
	return;

      sock->encrypted=4;
    }

  if (sock->encrypted==4)
    {
      if (!strcmp(SSL_get_cipher(sock->ssl),"(NONE)"))
	{
	  sock->ctx=0;
	  
	  SSL_free(sock->ssl);
	  sock->ssl=0;

	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Server failed to load cipher\n");
#endif
	  return;
	}
    }

  if (sock->ca)
    {
      //Now we verify that the cert we have is good
      SSL_set_verify_depth(sock->ssl,10);
      rv=SSL_get_verify_result(sock->ssl);
      
      if (rv != X509_V_OK)
	{
	  SSL_CTX_free(sock->ctx);
	  sock->ctx=0;
	  
	  SSL_free(sock->ssl);
	  sock->ssl=0;

	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;

#ifdef SSL_DEBUG
	  printf("Server failed to verify key with ca\n");
#endif
	  return;
	}
    }

  SSL_set_mode(sock->ssl,
	       SSL_get_mode(sock->ssl)|SSL_MODE_ENABLE_PARTIAL_WRITE);

  //It worked, note it as an encrypted socket
#ifdef SSL_DEBUG
  printf("server WORKING\n");
#endif
  sock->encrypted=1;

  return;
}

//Set this socket up to be an encryption client that will verift against the
//host
static void socket_set_client_encrypted(socketbuf *sock)
{
  int rv;

  if (sock->encrypted==2)
    {
      if (!socket_set_encrypted_keys(sock))
	{
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Client failed to set keys\n");
#endif
	  return;
	}
      
      sock->ssl=SSL_new(sock->ctx);
      if (!sock->ssl)
	{
	  SSL_CTX_free(sock->ctx);
	  sock->ctx=0;
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Client failed to make ssl\n");
#endif
	  return;
	}
      
      if (!SSL_set_fd(sock->ssl,sock->fd))
	{
	  SSL_CTX_free(sock->ctx);
	  sock->ctx=0;
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
#ifdef SSL_DEBUG
	  printf("Client failed to link fd to SSL\n");
#endif
	  return;
	}


      sock->encrypted=3;
    }
  
  if (sock->encrypted==3)
    {
      rv=SSL_connect(sock->ssl);

      if (rv<1)
	{
#ifdef SSL_DEBUG
	  printf("Connect error\n");
#endif
	  rv=ssl_process_error(sock->ssl,rv);
	}

      if (rv<0)
	{
	  SSL_CTX_free(sock->ctx);
	  sock->ctx=0;
	  
	  SSL_free(sock->ssl);
	  sock->ssl=0;

	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;

#ifdef SSL_DEBUG
	  printf("Client failed connect\n");
#endif
	  return;
	}

      if (rv==0)
	{
	  return;
	}

      sock->encrypted=4;
    }

  if (sock->encrypted==4)
    {
      if (!strcmp(SSL_get_cipher(sock->ssl),"(NONE)"))
	{
	  SSL_CTX_free(sock->ctx);
	  sock->ctx=0;
	  
	  SSL_free(sock->ssl);
	  sock->ssl=0;

	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
	  
#ifdef SSL_DEBUG
	  printf("Client failed to get cipher\n");
#endif
	  return;
	}
    }

  if (sock->ca)
    {
#ifdef SSL_DEBUG
      printf("Client about to test certifricate\n");
#endif
      //Now we verify that the cert we have is good
      SSL_set_verify_depth(sock->ssl,10);
      rv=SSL_get_verify_result(sock->ssl);
      
      if (rv!=X509_V_OK)
	{
	  SSL_CTX_free(sock->ctx);
	  sock->ctx=0;
	  
	  SSL_free(sock->ssl);
	  sock->ssl=0;
	  
	  sock->encrypted=0;
	  sock->flags |= SOCKET_DEAD;
	  
#ifdef SSL_DEBUG
	  printf("Client failed to verify key with ca\n");
#endif
	  return;
	}
    }

  SSL_set_mode(sock->ssl,
	       SSL_get_mode(sock->ssl)|SSL_MODE_ENABLE_PARTIAL_WRITE);

  //Successful
#ifdef SSL_DEBUG
  printf("client WORKED\n");
#endif
  sock->encrypted=1;

  return;
}

static void socket_process_ssl(socketbuf *sock)
{
  if (sock->flags & SOCKET_INCOMING)
    socket_set_server_encrypted(sock);
  else
    socket_set_client_encrypted(sock);
}  
#endif //SOCK_SSL

#ifdef DEBUG
//Simple debug function that reports all socket data to a file, the filename
//based on the fd number
static void socket_data_debug(socketbuf *sock,char *buf,int len,int writer)
{
  FILE *fp;
  int loopa;
  char filename[PATH_MAX+1];

  //Set the filename  
  if (writer)
    sprintf(filename,"/tmp/socket_%d.write",sock->fd);
  else
    sprintf(filename,"/tmp/socket_%d.read",sock->fd);

  //Open the file for appending
  fp=fopen(filename,"a");
  if (fp)
    {
      //Write the bytes into the file, on oneline. If the value is printable
      //also write the character, as this can help debugging some streams
      for (loopa=0;loopa<len;loopa++)
	{
	  if (isprint(buf[loopa]))
	    fprintf(fp,"%d(%c) ",buf[loopa],buf[loopa]);
	  else
	    fprintf(fp,"%d ",buf[loopa]);
	}

      //Finish off with a newline
      fprintf(fp,"\n");

      //Close the file, we're done
      fclose(fp);
    }
  return;
}
#endif

//Free a UDP data packet Fairly obvious
int socket_udp_data_free(socket_udp_data *data)
{
  if (data->data)
    free(data->data);
  free(data);

  return 1;
}


//Generic function to write data to the socket. This is called from
//outside. We do NOT actually write the data to the socket at this stage, we
//just add it to a buffer
void socket_write(socketbuf *sock,
		  const char *data,size_t len)
{
  socket_intchar udplen,udpdata;
  size_t newlen;

  //Sanity check
  if (len==0)
    return;

  //If we are using UDP we need to do it differently, as UDP sends discrete 
  //packets not a stream
  if (sock->protocol==SOCKET_UDP)
    {
      //Calculate how long the length will be of the UDP packet
      newlen=len;
      if (sock->udp2w)
	{
	  //It will be 4 extra bytes if it is a 2 way UDP
	  newlen+=4;
	}

      //So, the first data goes in, this is the length of the following data
      //This happens for all UDP packets, so the buffer knows how long to send
      //as the data packet
      udplen.i=(SOCKET_INT_TYPE)newlen;
      dynstringRawappend(sock->outdata,udplen.c,4);

      if (sock->udp2w)
	{
	  //Then for 2 way UDP, we send the protocol - we are sending user
	  //data not a low level protocol packet
	  udpdata.i=htonl(SOCKET_UDP2W_PROTOCOL_DATA);
	  dynstringRawappend(sock->outdata,udpdata.c,4);
	}
    }


  //Now we simply append the data itself. If this is TCP thats all we need
  //to do, as TCP sends a whole stream, its up to the client to rebuild
  //it, with UDP we have made and sent a header
  dynstringRawappend(sock->outdata,data,len);
  sock->bytes_out+=len;

  return;
}

//rdata is the resend data, used on reliable UDP packets to resend
//packets that may have gone missing. Here we delete one from a
//linked list. Any linked list, we dont care
static socket_udp_rdata *socket_rdata_delete(socket_udp_rdata *list,
					     socket_udp_rdata *target)
{
  if (target->next==target)
    {
      list=NULL;
    }
  else
    {
      target->next->prev=target->prev;
      target->prev->next=target->next;
      if (target==list)
	list=target->next;
    }

  if (target->data)
    free(target->data);

  if (target->range_starts)
    free(target->range_starts);

  if (target->range_received)
    free(target->range_received);

  free(target);
  
  return list;
}

//This function locates a rdata packet by its ID from a list
static socket_udp_rdata *socket_rdata_locate_packetnum(socket_udp_rdata *list,
						       int packetnum)
{
  socket_udp_rdata *scan;

  scan=list;

  //Scan through the list
  while (scan)
    {
      if (scan->packetnum==packetnum)
	//We have a match, return it
	return scan;

      scan=scan->next;
      if (scan==list)
	//Come to the end of the list (it is circular)
	scan=NULL;
    }
  
  //No match, return NULL
  return NULL;
}

//Allocate an rdata packet and put it into a list
static socket_udp_rdata *rdata_allocate(socket_udp_rdata *list,
					int packetnum,
					const char *data,size_t len,int sent)
{
  socket_udp_rdata *newpacket;

  //Allocate the memory
  newpacket=(socket_udp_rdata *)calloc(1,sizeof(socket_udp_rdata));

  //Allocate the data segment memory
  newpacket->data=(char *)malloc(len);
  memcpy(newpacket->data,data,len);
  
  newpacket->length=len;
  newpacket->sent=sent;

  //Set the send time
  gettimeofday(&newpacket->sendtime,NULL);
  
  newpacket->packetnum=packetnum;

  //Link this into the list we have supplied
  if (list)
    {
      newpacket->next=list;
      newpacket->prev=list->prev;
      newpacket->prev->next=newpacket;
      newpacket->next->prev=newpacket;
      
      return list;
    }

  newpacket->next=newpacket;
  newpacket->prev=newpacket;

  return newpacket;
}

//This function returns the best it can for the IP addresses connected to the
//current machine
const char **socket_get_interface_list()
{
  char ipaddr[HOST_NAME_MAX+1];
  static char **interfaces=NULL;
  static int found_interfaces=0;
  int interface_count=0;

  //If we have already looked, dont look again, as this is an expensive
  //task to run. Store the data, it isnt going to change
  if (found_interfaces)
    return (const char **)interfaces;

  //Set this value to ensure that the search will only be done once
  found_interfaces=1;

#ifdef HAVE_IFADDRS_H
  {
    //This set of functionality simply loops through all interfaces.
    //Nice and simple. However it isnt alwats present.
    struct ifaddrs *interface_scan = NULL, *interface_list = NULL;
    
    //Get the interface list
    if (getifaddrs(&interface_list) < 0)
      {
	//We cant get the list of interfaces
	return NULL;
      }
    
    interface_scan=interface_list;

    //Loop through the discovered interfaces    
    while (interface_scan)
      {
	//Only loop at Inet interfaces
	if (interface_scan->ifa_addr->sa_family == AF_INET)
	  {
	    //Resolve the data into an IP address
	    if (getnameinfo(interface_scan->ifa_addr, 
			    sizeof(struct sockaddr_in),
			    ipaddr, HOST_NAME_MAX, 
			    NULL, 0, NI_NUMERICHOST) == 0)
	      {
		//Now add this into the interface list, adding a new entry or
		//creating a whole new structure
		if (interfaces)
		  interfaces=(char **)realloc(interfaces,
					     (interface_count+2)*sizeof(char *));
		else
		  interfaces=(char **)malloc(2*sizeof(char *));
		
		//Copy the IP address into the aray
		interfaces[interface_count]=(char *)malloc(strlen(ipaddr)+1);
		strcpy(interfaces[interface_count],ipaddr);
		
		//Incriment the array count
		interfaces[++interface_count]=NULL;
	      }
	  }
	interface_scan=interface_scan->ifa_next;
      }

    //Free the allocated memory    
    freeifaddrs(interface_list);
  }
#else
  {
    //We dont have the system we SHOULD use. Here we instead use a medly of
    //various other methods to try and find the IP addresses on this
    //machine.
    
    
    
    //First we do a nasty thing, run ifconfig in a shell, and see what the
    //result is. Its horrible, Im sorry, but if we dont have the tools, I
    //am not quite sure what else to do to give us a good starting position
    
    interface_count=0;
    
#ifdef WIN32
    //This is for windows and calls the ipconfig command
    {
      FILE *fp;
      char line[1024+1],*ptr,*endptr;
      
      //Run the command
#ifdef WIN32
      fp=_popen("ipconfig","r");
#else
      fp=popen("ipconfig","r");
#endif
      
      if (fp)
	{
	  //Loop through the data returned by the command
	  while (!feof(fp))
	    {
	      line[0]=0;
	      fgets(line,1024,fp);
	      if (line[0])
		{
		  //This is the line we need
		  ptr=strstr(line,"IP Address");
		  if (ptr)
		    {
		      ptr+=10;
		      //Skip to the numbers
		      while (*ptr && !(*ptr>47 && *ptr<58))
			ptr++;
		      endptr=ptr;
		      while ((*endptr>47 && *endptr<58) || *endptr=='.')
			endptr++;

		      //We now have an IP address

		      if (endptr>ptr)
			{
			  //If we have an IP address, add it to the interfaces
			  //list
			  if (interfaces)
			    interfaces=(char **)realloc(interfaces,
							(interface_count+2)*sizeof(char *));
			  else
			    interfaces=(char **)malloc(2*sizeof(char *));
			  
			  memcpy(ipaddr,ptr,endptr-ptr);
			  ipaddr[endptr-ptr]=0;
			  
			  interfaces[interface_count]=(char *)malloc(strlen(ipaddr)+1);
			  strcpy(interfaces[interface_count],ipaddr);
			  
			  interfaces[++interface_count]=NULL;
			}
		    }
		}
	    }
	  fclose(fp);
	}
    }
#else
    {
      //The unix way of doing things, run ifconfig
      FILE *fp;
      char line[1024+1],*ptr,*endptr;
      
      fp=popen("/sbin/ifconfig","r");

      if (fp)
	{
	  //Loop through all lines of ifconfig output
	  while (!feof(fp))
	    {
	      line[0]=0;
	      fgets(line,1024,fp);

	      if (line[0])
		{
		  //An IP address
		  ptr=strstr(line,"inet addr:");
		  if (ptr)
		    {
		      ptr+=10;
		      endptr=ptr;

		      while ((*endptr>47 && *endptr<58) || *endptr=='.')
			endptr++;

		      //We now have an IP address
		      
		      if (endptr>ptr)
			{
			  if (interfaces)
			    interfaces=(char **)realloc(interfaces,
							(interface_count+2)*sizeof(char *));
			  else
			    interfaces=(char **)malloc(2*sizeof(char *));
			  
			  memcpy(ipaddr,ptr,endptr-ptr);
			  ipaddr[endptr-ptr]=0;
			  
			  interfaces[interface_count]=(char *)malloc(strlen(ipaddr)+1);
			  strcpy(interfaces[interface_count],ipaddr);
			  
			  interfaces[++interface_count]=NULL;
			}
		    }
		}
	    }
	  fclose(fp);
	}
    }
#endif //WIN32
    {
      //Method 2, which will add to this list in case the first failed, which
      //is more than possible. Method two is a simple gethostbyname. It will
      //probably only return what is in /etc/hosts but may use DNS and get
      //us the correct name.
      char hostname[HOST_NAME_MAX+1];
      struct hostent *hp;
      struct in_addr inet_address;
      int ifscan,scan,found;

      //Get the current hostname      
      gethostname(hostname,HOST_NAME_MAX);

      hp=gethostbyname(hostname);
      
      if (!hp)
	return NULL;
      
      ifscan=0;
      //Loop through all aliases found for the address we found
      while (hp->h_addr_list[ifscan])
	{
	  memcpy((char *)&inet_address,hp->h_addr_list[ifscan],
		 sizeof(struct in_addr));
	  //Get the readable IP address
	  strcpy(ipaddr,inet_ntoa(inet_address));
	  
	  //Check if this has been found already
	  scan=0;
	  found=0;
	  while (!found && scan < interface_count)
	    {
	      if (!strcmp(interfaces[scan],ipaddr))
		{
		  found=1;
		}
	      else
		{
		  scan++;
		}
	    }

	  //If this is an unknown address
	  if (!found)
	    {
	      //Add it to the list of interfaces
	      if (interfaces)
		interfaces=(char **)realloc(interfaces,
					    (interface_count+2)*sizeof(char *));
	      else
		interfaces=(char **)malloc(2*sizeof(char *));
	      
	      interfaces[interface_count]=(char *)malloc(strlen(ipaddr)+1);
	      strcpy(interfaces[interface_count],ipaddr);
	  
	      interfaces[++interface_count]=NULL;
	    }
	  ifscan++;
	}    
    }
#ifdef SIOCGIFADDR
#ifdef HAVE_NET_IF_H
    {
      //We can get addresses based on the hardare devices. This is only run in
      //circumstances where the system has SIOCGIFADDR present
      struct if_nameindex *hw_ints;
      struct ifreq ifr; 
      struct sockaddr_in saddr;
      int fd,ifscan,ifsubloop,finished,scan,found;
      char host[20],ifsubname[128+1];
      
      //Get the list of interfaces
      hw_ints=if_nameindex();
      ipaddr[0]=0;

      ifscan=0;
      //Loop through them
      while (hw_ints[ifscan].if_index>0)
	{
	  //Now we have the interface name	  
	  //Convert this to an IP address
	  strcpy(ifr.ifr_name,hw_ints[ifscan].if_name);
	  fd=socket(PF_INET,SOCK_STREAM,0);

	  //Use ioctl to find the interface information
	  if (ioctl(fd,SIOCGIFADDR,&ifr)==0)
	    {
	      //Copy the interface address data into a structure we can use
	      memcpy (&saddr, &(ifr.ifr_addr), sizeof(saddr));
	  
	      //Convert it into a readable address
	      strcpy(host,inet_ntoa(saddr.sin_addr));

	      //Check if this has been found already
	      scan=0;
	      found=0;
	      while (!found && scan < interface_count)
		{
		  if (!strcmp(interfaces[scan],host))
		    {
		      found=1;
		    }
		  else
		    {
		      scan++;
		    }
		}
	      
	      //If it is a new address
	      if (!found)
		{
		  //Add it to the interfaces
		  if (interfaces)
		    interfaces=(char **)realloc(interfaces,
						(interface_count+2)*sizeof(char *));
		  else
		    interfaces=(char **)malloc(2*sizeof(char *));
	      
		  interfaces[interface_count]=(char *)malloc(strlen(host)+1);
		  strcpy(interfaces[interface_count],host);
		  
		  interfaces[++interface_count]=NULL;
		}
	    }
	    
	  close(fd);

	  //This section takes a little explaining. We have checked an
	  //interface, for example eth0. However interfaces can be split
	  //so one ethernet card can have multiple addresses. These should,
	  //but are NOT showing up on the interface list, so we have to try
	  //and guess to see if they are available. The addresses of the
	  //interfaces, for the eth0 example would be eth0:0 eth0:1 etc.
	  //There is no requirement for these to be starting at 0 or to be
	  //sequential. However they USUALLY are. For this case we check
	  //indexes 0 and 1, and anything that is sequential afterwards.
	  //This MAY miss some but this is only one in a series of methods
	  //we are using to try and get addresses so this is, while not ideal,
	  //it is acceptable
	  finished=0;
	  ifsubloop=0;
	  while (!finished)
	    {
	      //Check if this addres DOES have a : in, if it does, dont check
	      //for subs
	      if (strchr(hw_ints[ifscan].if_name,':'))
		{
		  finished=1;
		}
	      else
		{
		  //Create the new name, for example eth0:0
		  sprintf(ifsubname,"%s:%d",hw_ints[ifscan].if_name,ifsubloop);

		  //Convert this to an IP address
	  
		  strcpy(ifr.ifr_name,ifsubname);
		  fd=socket(PF_INET,SOCK_STREAM,0);
		  if (ioctl(fd,SIOCGIFADDR,&ifr)==0)
		    {
		      //The interfaces was found, add it in
		      memcpy (&saddr, &(ifr.ifr_addr), sizeof(saddr));
		      
		      strcpy(host,inet_ntoa(saddr.sin_addr));

		      //Check if this has been found already
		      scan=0;
		      found=0;
		      while (!found && scan < interface_count)
			{
			  if (!strcmp(interfaces[scan],host))
			    {
			      found=1;
			    }
			  else
			    {
			      scan++;
			    }
			}
		      
		      if (!found)
			{
			  //Add it to the list to return
			  if (interfaces)
			    interfaces=(char **)realloc(interfaces,
							(interface_count+2)*sizeof(char *));
			  else
			    interfaces=(char **)malloc(2*sizeof(char *));
			  
			  interfaces[interface_count]=(char *)malloc(strlen(host)+1);
			  strcpy(interfaces[interface_count],host);
			  
			  interfaces[++interface_count]=NULL;
			}
		    }
		  else
		    {
		      //The interface wasnt present. If this is an index more
		      //than 0, then we are finished testing
		      if (ifsubloop>0)
			finished=1;
		    }
		  ifsubloop++;
	    
		  close(fd);
		}
	    }

	  ifscan++;
	}
      //Free the interface data
      if_freenameindex(hw_ints);
    }
#endif //HAVE_NET_IF_H
#endif //SIOCGIFADDR
  }
#endif

  //Here we have done all we can, return what we have
  return (const char **)interfaces;
}


//Write a data packet in reliable mode
void socket_write_reliable(socketbuf *sock,
			   const char *data,size_t len)
{
  socket_intchar udplen,udpdata;
  size_t newlen;
  SOCKET_INT_TYPE packetnum;

  //Sanity check
  if (len==0)
    return;

  //If we arent using 2 way UDP, we just send, as we cant have reliable one way
  //UDP and UDP is the only protocol we support that is unreliable
  if (sock->protocol!=SOCKET_UDP || !sock->udp2w)
    {
      socket_write(sock,
		   data,len);
      return;
    }

  //Incriment the outbound packet number
  packetnum=sock->udp2w_routpacket++;

  //Calculate the length of the data
  newlen=len;
  newlen+=8;

  //Send the length first //This does NOT get htonl'd as it gets stripped
  //before actually sending it
  udplen.i=(int)newlen;
  dynstringRawappend(sock->outdata,udplen.c,4);

  //Then the protocol
  udpdata.i=htonl(SOCKET_UDP2W_PROTOCOL_RDATA);

  dynstringRawappend(sock->outdata,udpdata.c,4);

  //Then the packet number, so the other end keeps in sync
  udpdata.i=htonl(packetnum);
  dynstringRawappend(sock->outdata,udpdata.c,4);

  //Then the data itself
  dynstringRawappend(sock->outdata,data,len);
  sock->bytes_out+=len;

  //Add this packet to the RDATA out list, so we know to resend it if we
  //dont get a confirmation of the receipt
  sock->udp2w_rdata_out=rdata_allocate(sock->udp2w_rdata_out,
				       packetnum,
				       data,len,0);

  return;
}

//Just a user accessible function to return the number of bytes received
size_t socket_bytes_in(socketbuf *sock)
{
  return sock->bytes_in;
}

//Just a user accessible function to return the number of bytes sent
size_t socket_bytes_out(socketbuf *sock)
{
  return sock->bytes_out;
}

//Sockets are processed out of a 'processlist' - which is a linked list
//of socketbuf's. This function adds a socketbuf to a processlist. It creates
//a processlist object to hold the socketbuf
socket_processlist *socket_link(socket_processlist *list,socketbuf *sock)
{
  socket_processlist *newitem;
  newitem=(socket_processlist *)malloc(sizeof(socket_processlist));
  newitem->sock=sock;

  if (!list)
    {
      newitem->next=newitem;
      newitem->prev=newitem;

      return newitem;
    }

  newitem->next=list;
  newitem->prev=list->prev;

  newitem->next->prev=newitem;
  newitem->prev->next=newitem;
  
  return list;
}

//And this function unlinks a socketbuf from a processlist. It also frees the
//processlist container that held the socketbuf
socket_processlist *socket_unlink(socket_processlist *list,socketbuf *sock)
{
  socket_processlist *scan;

  if (list->next==list)
    {
      if (list->sock!=sock)
	return list;

      free(list);
      return NULL;
    }
  
  scan=list;

  while (scan)
    {
      if (scan->sock==sock)
	{
	  scan->prev->next=scan->next;
	  scan->next->prev=scan->prev;
	  if (scan==list)
	    list=scan->next;
	  free(scan);
	  return list;
	}
      scan=scan->next;
      if (scan==list)
	return list;
    }

  return list;
}

//This is the basic function for creating a socketbuf object around a
//file descriptor
static socketbuf *socket_create(SOCKET_FD_TYPE fd)
{
  socketbuf *returnval;

#ifdef WIN32
  static int sock_init_done=0;

  if (!sock_init_done)
    {
      WSADATA wsa;

      WSAStartup(MAKEWORD(2,0),&wsa);

      sock_init_done=1;
    }

#endif

  //Allocate the memory for the socket
  returnval=(socketbuf *)calloc(1,sizeof(socketbuf));

  //Give it a small in and out buffer - these resize dynamically so it doesnt
  //really matter what size we give it. 128 is a fairly small number in case
  //the socket only sends small bits of data, this saves over-allocating.
  returnval->indata=dynstringInit(128);
  returnval->outdata=dynstringInit(128);

  //Set the file descriptor into the structure
  returnval->fd=fd;

  //Set the maximum packet size
  returnval->udp2w_maxsend=1024*1024;

#if defined WIN32 && defined HAVE_WINSOCK2_H
  //Add an event manager, which will take the place of the readers and writers
  //on windows
  returnval->event=WSACreateEvent();
#endif

  //Thats it, we have our socketbuf. Much more wil happen to this depending
  //on what the type of socket being made is, this data will be filled in
  //by the function that calls this one.
  return returnval;
}

//We are destroying a socket. We are also however needing to be careful that
//we destroy any connecting sockets if this is a listener.
void socket_destroy(socketbuf *sock)
{
  socketbuf *scan;

  while (sock->new_children)
    {
      //Now we MUST destroy this, they are connecting sockets who have
      //no parent, if we dont destroy now we will leak memory
      //This will, incidentally, cascade down, destroying always the last
      //one in the tree, and then roll back up to here
      socket_destroy(sock->new_children);
    }

  //Here we must now also disconnect all connected children. These have been
  //accessed by the parent program and so it is not our responsibility to
  //keep track of them. Why did we keep them in a list in the first place?
  //Well, things like UDP, all data comes in on the listener, not on a
  //socket dedicated to the other end, so we need to have a list of all
  //who have connected, so we know who to send the data to/
  scan=sock->connected_children;
  while (scan)
    {
      if (scan->parent==sock)
	scan->parent=NULL;
      
      scan=scan->connected_child_next;
      if (scan==sock->connected_children)
	scan=NULL;
    }

  //If we have a parent, then unlink ourselves from the parent, so that
  //this socket is no longer in contention for any data received by the
  //parent socket, if it is UDP
  if (sock->parent)
    {
      if (sock->new_child_next)
	{
	  if (sock->parent->new_children==sock)
	    sock->parent->new_children=sock->new_child_next;
	  if (sock->parent->new_children==sock)
	    sock->parent->new_children=NULL;
	}
      
      if (sock->connected_child_next)
	{
	  if (sock->parent->connected_children==sock)
	    sock->parent->connected_children=sock->connected_child_next;
	  if (sock->parent->connected_children==sock)
	    sock->parent->connected_children=NULL;
	}
    }

  //Unlink ourselves from the list of sockets connected to the same
  //parent, which can be intact even if the parent is gone.
  if (sock->new_child_next)
    {
      sock->new_child_next->new_child_prev=sock->new_child_prev;
      sock->new_child_prev->new_child_next=sock->new_child_next;
    }
  
  if (sock->connected_child_next)
    {
      sock->connected_child_next->connected_child_prev=sock->connected_child_prev;
      sock->connected_child_prev->connected_child_next=sock->connected_child_next;
    }

  //Finally we have done the internal management, we need to actually
  //destroy the socket!
  if (sock->fd)
    {
      //If we have the socket, kill it

      if (sock->flags & SOCKET_CONNECTED)
	//shutdown, if its connected
	shutdown(sock->fd,0);

      //Then close the socket
      close(sock->fd);
    }

#if defined WIN32 && defined HAVE_WINSOCK2_H
  //Close down the windows event manager
  WSACloseEvent(sock->event);
#endif

  //The data socket itself is now disconnected.

  //On an interrupt socket we have a different one
  if (sock->interrupt_fd)
    {
      //If we have the socket, kill it

      //shutdown, if its connected
      shutdown(sock->interrupt_fd,0);

      //Then close the socket
      close(sock->interrupt_fd);
    }
  
  //Free the memory used in the transmit and receive queues
  if (sock->indata)
    dynstringUninit(sock->indata);

  if (sock->outdata)
    dynstringUninit(sock->outdata);

  //Free the resend data queues, we dont need them any more, any data that
  //still hasnt made it isnt going to now.
  while (sock->udp2w_rdata_out)
    sock->udp2w_rdata_out=socket_rdata_delete(sock->udp2w_rdata_out,
					      sock->udp2w_rdata_out);
  while (sock->udp2w_rdata_in)
    sock->udp2w_rdata_in=socket_rdata_delete(sock->udp2w_rdata_in,
					     sock->udp2w_rdata_in);

  //Free the hostname
  if (sock->host)
    free(sock->host);

  //Free STUN data
  if (sock->stun_host)
    free(sock->stun_host);
  if (sock->stun2_host)
    free(sock->stun2_host);
  if (sock->published_address)
    free(sock->published_address);

  //Free the pathname (applies to unix sockets only)
  if (sock->path)
    {
#ifdef _MSC_VER
      if (sock->flags & SOCKET_LISTENER)
	_unlink(sock->path);
#else
      if (sock->flags & SOCKET_LISTENER)
	unlink(sock->path);
#endif
      free(sock->path);
    }

#ifdef SOCK_SSL
  if (sock->ssl)
    SSL_free(sock->ssl);

  if (sock->ctx)
    { 
      if (sock->flags & SOCKET_LISTENER ||
          !(sock->flags & SOCKET_INCOMING))
        { 
          SSL_CTX_free(sock->ctx);
        }
    }
#endif

  //Free the socket data, we are done
  free(sock);

  return;
}

#ifdef HAVE_SYS_UN_H
//Create the listener socket for a unix connection
socketbuf *socket_create_unix_wait(const char *path,int wait)
{
  int fd;
  socketbuf *returnval;
  struct sockaddr_un sa;
  unsigned long int dummy,errorval,errorlen;
  int selectnum;
  fd_set writer;

#ifndef FIONBIO
# ifdef O_NONBLOCK
  int flags;
# endif
#endif

  //We must specify a path in the filesystem, that is where the socket lives.
  //Without it, no way to create it.
  if (!path || !*path)
    return 0;

  //create the sockets file descriptor
  fd=socket(PF_UNIX,SOCK_STREAM,0);

  if (fd<1)
    {
      //Socket creation failed.
      return 0;
    }

  memset(&sa,0,sizeof(struct sockaddr_in));

  //Set the fd as a UNIX socket
  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path,path);

  //Set non-blocking, so we can check for a data without freezing. If we
  //fail to set non-blocking we must abort, we require it.
#ifdef FIONBIO
  dummy=1;

  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      close(fd);
      return 0;
    }
#else
# ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);

  if (flags<0)
    {
      close(fd);
      return 0;
    }

  if (fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)
    {
      close(fd);
      return 0;
    }

# else
#  error No valid non-blocking method - cannot build;
  // next is end of O_NONBLOCK
# endif
  // next is end of FIONBIO
#endif


  //We have the good file descriptor, set it into a socketbuf structure
  returnval=socket_create(fd);

  //Note the protocol
  returnval->protocol=SOCKET_UNIX;

  //And store the path
  returnval->path=(char *)malloc(strlen(path)+1);
  strcpy(returnval->path,path);

  //Up to now this has all been preparation, now we actually connect to the
  //socket
  if (connect(fd,(struct sockaddr *)&sa,sizeof(sa))==0)
    {
      //Connect was successful, we can finish this here
      returnval->flags |= SOCKET_CONNECTED;
      returnval->connect_time=time(NULL);

      return returnval;
    }
  
  //The connection is 'in progress'
  if (GRAPPLE_SOCKET_ERRNO_IS_EINPROGRESS)
    {
      //Connect was possibly OK, but we havent finished, come back
      //and check later with select
      returnval->flags|=SOCKET_CONNECTING;

      if (!wait)
	{
	  //We were called with the option NOT to wait for it to connect, so
	  //we return here. It is now the responsibility of the caller to
	  //process this socket occasionally and see if it has now connected
	  //or if the connection failed.

	  return returnval;
	}
      else
	{
	  //We were asked to keep waiting for the socket to connect
	  while (returnval->flags & SOCKET_CONNECTING)
	    {
	      //To test if we have connected yet, we select on the socket,
	      //to see if its writer returns

	      FD_ZERO(&writer);
	      FD_SET(returnval->fd,&writer);
	      //We need to wait, as long as it takes, so we set no timeout
	      selectnum=select(FD_SETSIZE,0,&writer,0,NULL);

	      //The select failed, this means an error, we couldnt connect
	      if (selectnum<0)
		{
		  socket_destroy(returnval);

		  return 0;
		}
	      if (selectnum>0)
		{
		  //At least one socket (it has to be us) returned data
		  if (FD_ISSET(returnval->fd,&writer))
		    {
		      //Check for an error in the connection
		      errorlen=sizeof(errorval);
		      if (getsockopt(returnval->fd,SOL_SOCKET,SO_ERROR,&errorval,(socklen_t *)&errorlen)==0)
			{
			  if (errorval==0)
			    {
			      //We have connected
			      returnval->flags &=~ SOCKET_CONNECTING;
			      returnval->flags |= SOCKET_CONNECTED;
			      returnval->connect_time=time(NULL);
			      return returnval;
			    }
			}
		      //if we get here, then teh getsockopt returned a value
		      //we dont like, and we failed to connect unless the error
		      //is einprogress
		      if (errorval!=EINPROGRESS)
			{
			  socket_destroy(returnval);
			  return 0;
			}
		    }
		}
	    }
	}
    }

  //It was an error, and a bad one, close this
  socket_destroy(returnval);

  return 0;
}
#endif

//Create a wakeup socket
socketbuf *socket_create_interrupt(void)
{
  socketbuf *returnval;
#if !defined WIN32 || !defined HAVE_WINSOCK2_H
  int fd[2];
  unsigned long int dummy;
#ifndef FIONBIO
# ifdef O_NONBLOCK
  int flags;
# endif
#endif
  //Ending win32/winsock define
#endif


#if defined WIN32 && defined HAVE_WINSOCK2_H
  returnval=socket_create(0);
#else
  //create the sockets file descriptor
  if (pipe(fd)==-1)
    return 0;

  //Set non-blocking, so we can check for a data without freezing. If we
  //fail to set non-blocking we must abort, we require it.
#ifdef FIONBIO
  dummy=1;

  if (ioctl(fd[0],FIONBIO,&dummy)<0)
    {
      close(fd[0]);
      close(fd[1]);
      return 0;
    }

  dummy=1;

  if (ioctl(fd[1],FIONBIO,&dummy)<0)
    {
      close(fd[0]);
      close(fd[1]);
      return 0;
    }
#else
# ifdef O_NONBLOCK

  flags=fcntl(fd[0],F_GETFL,0);

  if (flags<0)
    {
      close(fd[0]);
      close(fd[1]);
      return 0;
    }

  if (fcntl(fd[0],F_SETFL,flags|O_NONBLOCK)<0)
    {
      close(fd[0]);
      close(fd[1]);
      return 0;
    }

  flags=fcntl(fd[1],F_GETFL,0);

  if (flags<0)
    {
      close(fd[0]);
      close(fd[1]);
      return 0;
    }

  if (fcntl(fd[1],F_SETFL,flags|O_NONBLOCK)<0)
    {
      close(fd[0]);
      close(fd[1]);
      return 0;
    }

# else
#  error No valid non-blocking method - cannot build;
  // next is end of O_NONBLOCK
# endif
  // next is end of FIONBIO
#endif


  //We have the good file descriptor, set it into a socketbuf structure
  returnval=socket_create(fd[0]);
  returnval->interrupt_fd=fd[1];

  //Closing the win32 if/else define
#endif 

  //Note the protocol
  returnval->protocol=SOCKET_INTERRUPT;

  returnval->flags |= SOCKET_CONNECTED;

  returnval->connect_time=time(NULL);

  return returnval;
}

int socket_interrupt(socketbuf *sock)
{
  if (sock->protocol==SOCKET_INTERRUPT)
    {
#if defined WIN32 && defined HAVE_WINSOCK2_H
      if (sock->event)
	{
	  WSASetEvent(sock->event);
	}
#else
      if (sock->interrupt_fd)
	{
	  write_fn(sock->interrupt_fd,"0",1);
	  sock->bytes_out++;
	}
#endif
    }

  return 0;
}

#if defined WIN32 && defined HAVE_WINSOCK2_H
static long enumEvent(SOCKET s,WSAEVENT hEventObject)
{
  WSANETWORKEVENTS NetworkEvents;
  WSAEnumNetworkEvents(s,hEventObject,&NetworkEvents);
  return NetworkEvents.lNetworkEvents;
}
#endif

//Create a TCPIP connection to a remote socket
socketbuf *socket_create_inet_tcp_wait(const char *host,int port,int wait)
{
  SOCKET_FD_TYPE fd;
  socketbuf *returnval;
  struct sockaddr_in sa;
  unsigned long int dummy;
  int selectnum;
  struct in_addr inet_address;
  struct hostent *hp;
#if defined WIN32 && defined HAVE_WINSOCK2_H
  WSAEVENT events[FD_SETSIZE];
#else
  fd_set writer;
#endif
  struct sockaddr_in peername;
  socklen_t peersize;
#ifndef FIONBIO
# ifdef O_NONBLOCK
  int flags;
# endif
#endif

  //We need the hostname, where will we connect without one
  if (!host || !*host)
    return 0;

  //Create the socket
  fd=socket(AF_INET,SOCK_STREAM,0);

  if (fd<1)
    {
      //Basic socket connection failed, this really shouldnt happen
      return 0;
    }

  memset(&sa,0,sizeof(struct sockaddr_in));

  //Find the hostname
  hp=gethostbyname(host);
  if (!hp)
    //We cant resolve the hostname
    inet_address.s_addr=-1;
  else
    //We have the hostname
    memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));

  //The hostname was unresolvable, we cant connect to it
  if (inet_address.s_addr==-1)
    {
      close(fd);
      return 0;
    }

  //Set the socket data
  sa.sin_family=AF_INET;
  sa.sin_port=htons(port);
  sa.sin_addr=inet_address;

  //Set reuseaddr
  dummy=1;
  setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&dummy,sizeof(dummy));


  //Set non-blocking, so we can check for a data without freezing

#ifdef FIONBIO
  dummy=1;

  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      close(fd);
      return 0;
    }
#else
#  ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);

  if (flags<0)
    {
      close(fd);
      return 0;
    }

  if (fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)
    {
      close(fd);
      return 0;
    }

# else
#  error No valid non-blocking method - cannot build;
  // next is end of O_NONBLOCK
# endif
  // next is end of FIONBIO
#endif


  //We have a valid socket, now we wrap a socketbuf around it
  returnval=socket_create(fd);

  //Note the protocol
  returnval->protocol=SOCKET_TCP;

  //Note the hostname and the portnumber in the structure
  returnval->host=(char *)malloc(strlen(host)+1);
  strcpy(returnval->host,host);
  returnval->port=port;

  //Now try and actually connect to the remote address
  if (connect(fd,(struct sockaddr *)&sa,sizeof(sa))==0)
    {
      //Connect was successful, we can finish this here
      returnval->flags |= SOCKET_CONNECTED;
      returnval->connect_time=time(NULL);

      return returnval;
    }

  //We have an in-progress connection
  if (GRAPPLE_SOCKET_ERRNO_IS_EINPROGRESS)
    {
      //Connect was possibly OK, but we havent finished, come back
      //and check later with select
      returnval->flags|=SOCKET_CONNECTING;

      if (!wait)
	{
	  //The caller requested we do not wait for the connection to finish, 
	  //it will now be the callers responsibility to check this using
	  //process_socket
	  return returnval;
	}
      else
	{
	  //We have been requested to keep on waiting for the connection
	  while (returnval->flags & SOCKET_CONNECTING)
	    {
	      //We do this by selecting on the socket, see what the
	      //writer returns
#if defined WIN32 && defined HAVE_WINSOCK2_H
	      WSAEventSelect(returnval->fd,returnval->event,FD_WRITE);
	      events[0]=returnval->event;
#else
	      FD_ZERO(&writer);
	      FD_SET(returnval->fd,&writer);
#endif

	      //Wait forever if needbe
#if defined WIN32 && defined HAVE_WINSOCK2_H
	      selectnum=(unsigned)WSAWaitForMultipleEvents(1,events,0,WSA_INFINITE,0);
	      if(selectnum==WSA_WAIT_FAILED)
		selectnum=-1;
	      else
		selectnum-=(WSA_WAIT_EVENT_0-1);

#else
	      selectnum=select(FD_SETSIZE,0,&writer,0,NULL);
#endif

	      if (selectnum<0)
		{
		  //There was an error on the select, this means the connection
		  //has definitely died.
		  socket_destroy(returnval);
		  return 0;
		}
	      if (selectnum>0)
		{
		  if (
#if defined WIN32 && defined HAVE_WINSOCK2_H
                      enumEvent(returnval->fd,returnval->event)==FD_WRITE
#else
		      FD_ISSET(returnval->fd,&writer)
#endif
		      )
		    {
		      //We have a writer, but is it ok or has it failed
		      //to connect, check with getpeername()

		      peersize=sizeof(struct sockaddr_in);

		      if (!getpeername(returnval->fd,
				       (struct sockaddr *)&peername,
				       &peersize))
			{
			  //Connected ok!
			  returnval->flags &=~ SOCKET_CONNECTING;
			  returnval->flags |= SOCKET_CONNECTED;
			  returnval->connect_time=time(NULL);
			  return returnval;
			}
		      else
			{
			  //Connection failed
			  socket_destroy(returnval);
			  return 0;
			}
		    }
		}
	    }
	}
    }

  //It was an error, and a bad one, close this
  socket_destroy(returnval);

  return 0;
}

//Create a UDP socket. Actually this never connects so the
//wait parameter is ignored. It just sets up a route where data can be thrown
//to. With UDP you dont know if it has reached its target or not.
socketbuf *socket_create_inet_udp_wait(const char *host,int port,int wait)
{
  SOCKET_FD_TYPE fd;
  unsigned long int dummy;
  socketbuf *returnval;
  struct in_addr inet_address;
  struct hostent *hp;
#ifndef FIONBIO
# ifdef O_NONBLOCK
  int flags;
# endif
#endif

  //We need to know where to connect to.
  if (!host || !*host)
    return 0;

  //Create the socket
  fd=socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
  if (fd<1)
    return 0;

  //Now create the data structure around the socket
  returnval=socket_create(fd);

  memset(&returnval->udp_sa,0,sizeof(struct sockaddr_in));

  //Lookup the hostname we are sending to
  hp=gethostbyname(host);
  if (!hp)
    inet_address.s_addr=-1;
  else
    memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));

  if (inet_address.s_addr==-1)
    {
      //We couldnt resolve the address, destroy the socket
      socket_destroy(returnval);
      close(fd);
      return 0;
    }

  //Save the data for later use in the datastruct
  returnval->udp_sa.sin_family=AF_INET;
  returnval->udp_sa.sin_port=htons(port);
  returnval->udp_sa.sin_addr.s_addr=inet_address.s_addr;

  //Note the protocol
  returnval->protocol=SOCKET_UDP;

  //Save the text representation of the address
  returnval->host=(char *)malloc(strlen(host)+1);
  strcpy(returnval->host,host);
  returnval->port=port;


  //Set non-blocking, so we can check for a data without freezing

#ifdef FIONBIO
  dummy=1;

  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      close(fd);
      return 0;
    }
#else
#  ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);

  if (flags<0)
    {
      close(fd);
      return 0;
    }

  if (fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)
    {
      close(fd);
      return 0;
    }

# else
#  error No valid non-blocking method - cannot build;
  // next is end of O_NONBLOCK
# endif
  // next is end of FIONBIO
#endif

  //While we technically havent connected, we are ready to send data, and thats
  //what is important
  returnval->flags |= SOCKET_CONNECTED;
  returnval->connect_time=time(NULL);

  return returnval;
}

//Test to see of a socket is connected
int socket_connected(socketbuf *sock)
{
  if (sock->flags & SOCKET_DEAD)
    //A dead socket is never connected
    return 0;

  if (sock->flags & SOCKET_CONNECTED)
    { 
#ifdef SOCK_SSL
      if (sock->encrypted && sock->encrypted > 1)
        return 0;
#endif

      //It has connected
      return 1;
    }
  
  return 0;
}

//Test to see if a socket is dead
int socket_dead(socketbuf *sock)
{
  if (!sock || sock->flags & SOCKET_DEAD)
    //It is {:-(
    return 1;

  //Its alive! yay!
  return 0;
}

//This function drops a set length of data from the socket This is handy
//For it we have already peeked it, so we HAVE the data, we dont want to
//reallocate. Or if we have a set of data we KNOW is useless
void socket_indata_drop(socketbuf *sock,size_t len)
{
  //memmove freaks out at a zero length memory move
  if (len==0)
    return;
  
  //Decrease the recorded amount of data stored
  sock->indata->len-=len;

  if (sock->indata->len<1)
    {
      sock->indata->len=0;
      return;
    }

  //move the later data to the start of the buffer
  memmove(sock->indata->buf,sock->indata->buf+len,sock->indata->len);
  
  return;
}

//This function drops a set length of data from the socket OUTBUFFER
//This is dangerous and is only an internal function, dont let the end user
//do it or the whole socket could break, especially in UDP
static void socket_outdata_drop(socketbuf *sock,int len)
{
  //memmove freaks out at a zero length memory move
  if (len==0)
    return;
  
  //Decriment the recorded amount of data
  sock->outdata->len-=len;

  if (sock->outdata->len<1)
    {
      sock->outdata->len=0;
      return;
    }

  //Move the rest to the start
  memmove(sock->outdata->buf,sock->outdata->buf+len,sock->outdata->len);
  
  return;
}

//A 2 way UDP socket has received some data on its return socket
static socket_udp_data *socket_udp2way_indata_action(socketbuf *sock,int pull)
{
  socket_udp_data *returnval;
  socket_intchar len;
  size_t datalen;

  //All data must be at least 4 bytes - this is the length of the data in the
  //packet
  if (sock->indata->len<4)
    return NULL;

  //get the length of the data
  memcpy(len.c,sock->indata->buf,4);

  datalen=len.i;

  //The packet isnt big enough to hold all the data we expected - this is a
  //corrupted packet, ABORT!
  if (datalen+4 > sock->indata->len)
    return NULL;

  //Create an internal UDP packet to handle the data we have received
  returnval=(socket_udp_data *)calloc(1,sizeof(socket_udp_data));

  //Allocate enough buffer for the incoming data
  returnval->data=(char *)malloc(datalen);
  memcpy(returnval->data,sock->indata->buf+4,datalen);

  returnval->length=datalen;

  //If we are deleting the data - then do so
  if (pull)
    socket_indata_drop(sock,datalen+4);

  //return the UDP data block
  return returnval;
}

//Receive a packet on a basic UDP socket
static socket_udp_data *socket_udp_indata_action(socketbuf *sock,int pull)
{
  socket_udp_data *returnval;
  socket_intchar len;
  socklen_t sa_len;
  int datalen;

  //We need to have at least 4 bytes as the length of the data in the packet
  if (sock->indata->len<4)
    return NULL;

  //If this is a 2 way UDP socket, process it using 2 way UDP handlers
  if (sock->udp2w)
    return socket_udp2way_indata_action(sock,pull);

  //Note the length of the sa structure - this is written wholesale
  //into the buffer, this is actually OK
  memcpy(len.c,sock->indata->buf,4);
  sa_len=(socklen_t)len.i;


  //Check we have enough space
  if (sa_len+8  > (socklen_t)sock->indata->len)
    return NULL;

  //Find the length of the data now.
  memcpy(len.c,sock->indata->buf+4+sa_len,4);
  datalen=len.i;

  //Check we have the whole data packet
  if (sa_len+datalen+8 > (socklen_t)sock->indata->len)
    //We dont, its corrupt
    return NULL;

  //Allocate a data structure for the packet
  returnval=(socket_udp_data *)calloc(1,sizeof(socket_udp_data));

  //Store the sa in the data structure.
  memcpy(&returnval->sa,sock->indata->buf+4,sa_len);

  //And the data itself
  returnval->data=(char *)malloc(datalen);
  memcpy(returnval->data,sock->indata->buf+8+sa_len,datalen);
  
  returnval->length=datalen;

  //If we are pulling instead of just looking, delete the data from the buffer
  if (pull)
    socket_indata_drop(sock,8+sa_len+datalen);

  //Return the UDP data packet
  return returnval;
}


//Wrapper function for the user to pull UDP data from the buffer
socket_udp_data *socket_udp_indata_pull(socketbuf *sock)
{
  return socket_udp_indata_action(sock,1);
}

//Wrapper function for the user to look at UDP data without removing it
//from the buffer
socket_udp_data *socket_udp_indata_view(socketbuf *sock)
{
  return socket_udp_indata_action(sock,0);
}

//This is a user function to pull data from any non-UDP socket
char *socket_indata_pull(socketbuf *sock,size_t len)
{
  char *returnval;

  //Ensure we dont overrun
  if (len > sock->indata->len)
    len=sock->indata->len;

  //Allocate the return buffer
  returnval=(char *)calloc(1,len+1);

  //copy the data
  memcpy(returnval,sock->indata->buf,len);

  //Drop the data from the buffer
  socket_indata_drop(sock,len);

  return returnval;
}

//Allows the user to view the buffer
const char *socket_indata_view(socketbuf *sock)
{
  //Just return the buffer. It is returned const so the user cant mess
  //it up
  return (char *)sock->indata->buf;
}

//Find the length of the incoming data
size_t socket_indata_length(socketbuf *sock)
{
  return sock->indata->len;
}

size_t socket_outdata_length(socketbuf *sock)
{
  //find the length of data still to send
  return sock->outdata->len;
}

#ifdef HAVE_SYS_UN_H
//Read a unix listener socket. Not a user function, this is an internal
//function filtered down to when we know what kind of
//socket we have.
static int socket_read_listener_unix(socketbuf *sock)
{
  socketbuf *newsock;
  socklen_t socklen;
  struct sockaddr_un sa;
  int fd;
  unsigned long int dummy=0;
  struct linger lingerval;
#ifndef FIONBIO
  int flags;
#endif

  //The length of the data passed into accept
  socklen=(socklen_t)sizeof(sa);

  //Accept the new connection on this socket
  fd = accept(sock->fd,(struct sockaddr *) &sa, &socklen);

  if (fd<1)
    {
      //The connection was bad, forget it
      return 0;
    }

  //Set non-blocking on the new socket
#ifdef FIONBIO
  dummy=1;
  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      shutdown(fd,2);
      close(fd);
      return 0;
    }
#else
# ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);
  if (flags < 0)
    {
      shutdown(fd,2);
      close(fd);
      return 0;
    }
  else
    if (fcntl(fd,F_SETFL,flags|O_NONBLOCK) < 0)
      {
	shutdown(fd,2);
	close(fd);
	return 0;
      }
# else
#  error no valid non-blocking method
# endif
#endif /*FIONBIO*/

  //We have a new non-blocking socket
  dummy=1;
  
  //Set linger on this, to make sure all data possible is sent when the
  //socket closes
  lingerval.l_onoff=0;
  lingerval.l_linger=0;
  setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
             sizeof(struct linger));
  
  //Create the socketbuf to hold the fd
  newsock=socket_create(fd);
  newsock->protocol=SOCKET_UNIX;
  newsock->path=(char *)malloc(strlen(sock->path)+1);
  strcpy(newsock->path,sock->path);

  //This socket is automatically connected (thats what we've been doing)
  newsock->flags |= (SOCKET_CONNECTED|SOCKET_INCOMING);

  //Set the mode to be the same as the socket that accepts (mode is things like
  //sequential data and the like...
  newsock->mode=sock->mode;

  //Set the parent.
  newsock->parent=sock;

  //This is a new child, it is NOT acknowledged by the parent, so we simply
  //put it into a queue waiting for the calling process to acknowledge we 
  //exist
  if (sock->new_children)
    {
      newsock->new_child_next=sock->new_children;
      newsock->new_child_prev=newsock->new_child_next->new_child_prev;
      newsock->new_child_next->new_child_prev=newsock;
      newsock->new_child_prev->new_child_next=newsock;
    }
  else
    {
      newsock->new_child_next=newsock;
      newsock->new_child_prev=newsock;
      sock->new_children=newsock;
    }

  newsock->connect_time=time(NULL);

#ifdef SOCK_SSL
  if (sock->encrypted)
    {
      socket_set_private_key(newsock,sock->private_key,
			     sock->private_key_password);
      socket_set_public_key(newsock,sock->public_key);
      socket_set_ca(newsock,sock->ca);
      socket_set_encrypted(newsock);
    }
#endif

  return 1;
}
#endif

//Some data has been received on the UDP socket. As UDP doesnt have connections
//it just gets data thrown at it, this is unlike other listeners, as we 
//dont just create a new socket here, we have to process the data we receive

static int socket_recursive_read_listener_inet_udp(socketbuf *sock,
						   int failkill,int level)
{
#ifdef FIONREAD
#ifdef WIN32
  unsigned long int chars_left;
#else
  unsigned int chars_left;
#endif
#else
  unsigned long int chars_left;
#endif
#ifdef _MSC_VER
  int chars_read,total_read;
#else
  ssize_t chars_read,total_read;
#endif
  void *buf;
  char quickbuf[1024];
  struct sockaddr_in sa;
  socket_intchar len;
  socklen_t sa_len;

  /*
  if (level > 100)
    return 0;
  */

  //Check how much data is there to read
  if (
#ifdef FIONREAD
      ioctl(sock->fd,FIONREAD,&chars_left)== -1
#else
# ifdef I_NREAD
      ioctl(sock->fd,I_NREAD,&chars_left)== -1
# else
# error no valid read length method
# endif
#endif
      )
    {
      if (failkill)
	{
	  //The socket had no data, but it was supposed to, that means its
	  //dead
	  sock->flags|=SOCKET_DEAD;
	}
      return 0;
    }
  
  /*Linkdeath*/
  if (!chars_left)
    {
      if (failkill)
	{
	  sock->flags|=SOCKET_DEAD;
	}
      return 0;
    }

  //The buffer to store the data in. This is allocated statically as it gets
  //used and reused and there is NO point in creating it time and time
  //again **change** It wasnt threadsafe - oops
  if (chars_left < 1024)
    buf=quickbuf;
  else
    buf=malloc(chars_left);

  total_read=0;

  //Loop while there is data to read
  while (chars_left>0)
    {
      sa_len=sizeof(struct sockaddr);

      //Actually perfrorm the read from the UDP socket
      chars_read=recvfrom(sock->fd,
			  (char *)buf,
			  chars_left,
			  0,
			  (struct sockaddr *)&sa,
			  &sa_len);

      if (chars_read==-1)
	{
	  if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN) /*An EAGAIN simply means that it wasnt quite ready
					       so try again later.*/
	    {
	      //There was an error on the read, dead socket
	      sock->flags|=SOCKET_DEAD;
	    }
	  if (buf!=quickbuf)
	    free(buf);
	  return 0;
	}

      if (chars_read==0)
	{
	  //No chars were read, so nothing was ready, try again next time
	  if (buf!=quickbuf)
	    free(buf);
	  return 0;
	}

#ifdef DEBUG
      //if we are in debug mode, run that now
      if (sock->debug)
	socket_data_debug(sock,(char *)buf,chars_read,0);
#endif

      //We are a 2 way UDP socket, process the data via the UDP2W data handler
      if (sock->udp2w)
	{
	  //Note that the socket received data, this is to stop it timing out,
	  //as UDP sockets are stateless
	  sock->udp2w_lastmsg=time(NULL);

	  socket_udp2way_listener_data_process(sock,
					       &sa,sa_len,
					       (signed char *)buf,chars_read);
	}
      else
	{
	  //We are a one way UDP socket

	  //Add the sa to the datastream
	  len.i=sa_len;
	  dynstringRawappend(sock->indata,len.c,4);
	  dynstringRawappend(sock->indata,(char *)&sa,sa_len);

	  //Then the data
	  len.i=chars_read;
	  dynstringRawappend(sock->indata,len.c,4);
	  dynstringRawappend(sock->indata,(char *)buf,chars_read);
	}
      //Note how many chars have been read, and loop back to see if we have
      //another packets worth of data to read
      chars_left-=chars_read;
      sock->bytes_in+=chars_read;
      total_read+=chars_read;
    }

  if (buf!=quickbuf)
    free(buf);

  //Try again for more packets, but bear in mind it is OK if there are none, so
  //we set the failkill parameter to 0
  socket_recursive_read_listener_inet_udp(sock,0,level+1);

  return total_read;
}


//This calls a recursive function, adds a 0 onto itself as this can be used 
//as a counter to stop it getting stuck in one function forever replying to
//fast connect messages from someone
static int socket_read_listener_inet_udp(socketbuf *sock,int failkill)
{
  return socket_recursive_read_listener_inet_udp(sock,failkill,0);
}

//Read the listener of a TCPIP socket
static int socket_read_listener_inet_tcp(socketbuf *sock)
{
  socketbuf *newsock;
  socklen_t socklen;
  struct sockaddr_in sa;
  SOCKET_FD_TYPE fd;
  unsigned long int dummy=0;
  struct linger lingerval;
#ifndef FIONBIO
  int flags;
#endif

  //The length of the data passed into accept
  socklen=(socklen_t)sizeof(sa);

  //Get the incoming socket
  fd = accept(sock->fd,(struct sockaddr *) &sa, &socklen);

  if (fd<1)
    {
      //It was a bad socket, drop it
      return 0;
    }

  //Set it to be non-blocking
#ifdef FIONBIO
  dummy=1;
  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      shutdown(fd,2);
      close(fd);
      return 0;
    }
#else
# ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);
  if (flags < 0)
    {
      shutdown(fd,2);
      close(fd);
      return 0;
    }
  else
    if (fcntl(fd,F_SETFL,flags|O_NONBLOCK) < 0)
      {
	shutdown(fd,2);
	close(fd);
	return 0;
      }
# else
#  error no valid non-blocking method
# endif  
#endif /*FIONBIO*/


  //Set linger so that the socket will send all its data when it close()s
  lingerval.l_onoff=0;
  lingerval.l_linger=0;
  setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
             sizeof(struct linger));
  
  //Create the socketbuf to hold the socket
  newsock=socket_create(fd);
  newsock->protocol=SOCKET_TCP;
  newsock->port=ntohs(sa.sin_port);
  newsock->host=(char *)malloc(strlen(inet_ntoa(sa.sin_addr))+1);
  strcpy(newsock->host,inet_ntoa(sa.sin_addr));

  //This is a connected socket so note it as such
  newsock->flags |= (SOCKET_CONNECTED|SOCKET_INCOMING);
  newsock->mode=sock->mode;

  //Link this into the parent so that the calling program can
  //actually get hold of this socket
  newsock->parent=sock;

  if (sock->new_children)
    {
      newsock->new_child_next=sock->new_children;
      newsock->new_child_prev=newsock->new_child_next->new_child_prev;
      newsock->new_child_next->new_child_prev=newsock;
      newsock->new_child_prev->new_child_next=newsock;
    }
  else
    {
      newsock->new_child_next=newsock;
      newsock->new_child_prev=newsock;
      sock->new_children=newsock;
    }

  newsock->connect_time=time(NULL);

#ifdef SOCK_SSL
  if (sock->encrypted)
    {
      socket_set_encrypted(newsock);
    }
#endif

  return 1;
}


//Generic function to wrap all listener read functions. It simply
//Looks at the protocol and calls the appropriate function
static int socket_read_listener(socketbuf *sock)
{
  switch (sock->protocol)
    {
    case SOCKET_TCP:
      return socket_read_listener_inet_tcp(sock);
      break;
    case SOCKET_UDP:
      return socket_read_listener_inet_udp(sock,1);
      break;
#ifdef HAVE_SYS_UN_H
    case SOCKET_UNIX:
      return socket_read_listener_unix(sock);
      break;
#endif
    case SOCKET_INTERRUPT:
      return 0;
      break;
    }

  //Couldnt find a listener handler - erm, that cant happen!
  return -1;
}

//Read a 2 way UDP socket. This will be the return socket on the client,
//as the outbound is read on the listener. Technically this is also a
//listener but it can only belong to one socketbuf so we can skip a load
//of the ownership tests that happen lower down the line
static int socket_udp2way_read(socketbuf *sock,int failkill)
{
#ifdef FIONREAD
#ifdef WIN32
  unsigned long int chars_left;
#else
  unsigned int chars_left;
#endif
#else
  unsigned long int chars_left;
#endif
#ifdef _MSC_VER
  int chars_read,total_read;
#else
  ssize_t chars_read,total_read;
#endif
  void *buf=0;
  char quickbuf[1024];
  struct sockaddr_in sa;
  socklen_t sa_len;

  //Check how much data is there to read
  if (
#ifdef FIONREAD
      ioctl(sock->fd,FIONREAD,&chars_left)== -1
#else
# ifdef I_NREAD
      ioctl(sock->fd,I_NREAD,&chars_left)== -1
# else
# error no valid read length method
# endif
#endif
      )
    {
      if (failkill)
	{
	  //Kill the socket, there is no data when we expected there would be
	  sock->flags|=SOCKET_DEAD;
	}
      return 0;
    }
  
  /*Linkdeath*/
  if (!chars_left)
    {
      if (failkill)
	{
	  sock->flags|=SOCKET_DEAD;
	}
      return 0;
    }

  //The buffer to store the data in. This is allocated statically as it gets
  //used and reused and there is NO point in creating it time and time
  //again
  if (chars_left<1024)
    buf=quickbuf;
  else
    buf=malloc(chars_left+1);

  total_read=0;

  //Loop while there is data to read
  while (chars_left>0)
    {
      sa_len=sizeof(struct sockaddr);

      //Actually perfrorm the read from the UDP socket
      chars_read=recvfrom(sock->fd,
			  (char *)buf,
			  chars_left,
			  0,
			  (struct sockaddr *)&sa,
			  &sa_len);

      if (chars_read==-1)
	{
	  if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN) /*An EAGAIN simply means that it wasnt quite ready
					       so try again later.*/

	    {
              //There was an error on the read, dead socket
	      sock->flags|=SOCKET_DEAD;
	    }

	  if (buf!=quickbuf)
	    free(buf);

	  return 0;
	}

      if (chars_read==0)
	{
	  //No chars were read, so nothing was ready, try again next time
	  if (buf!=quickbuf)
	    free(buf);

	  return 0;
	}

      //Note that the socket received data, this is to stop it timing out,
      //as UDP sockets are stateless
      sock->udp2w_lastmsg=time(NULL);

#ifdef DEBUG
      //if we are in debug mode, run that now
      if (sock->debug)
	socket_data_debug(sock,(char *)buf,chars_read,0);
#endif

      //We ARE a 2 way UDP socket reader, pass this data off to that
      //handler
      socket_udp2way_reader_data_process(sock,&sa,sa_len,
					 (signed char *)buf,chars_read);

      //Note how many chars have been read, and loop back to see if we have
      //another packets worth of data to read
      chars_left-=chars_read;
      sock->bytes_in+=chars_read;
      total_read+=chars_read;
    }
  
  if (buf!=quickbuf)
    free(buf);

  //Try again for more packets, but bear in mind it is OK if there are none, so
  //we set the failkill parameter to 0
  socket_udp2way_read(sock,0);

  return total_read;
}

#ifdef SOCK_SSL
//This is the read function for SSL sockets
static int socket_read_ssl(socketbuf *sock)
{
#ifdef FIONREAD
  unsigned int chars_left;
#else
  unsigned long int chars_left;
#endif
#ifdef _MSC_VER
  int chars_read,total_read;
#else
  ssize_t chars_read,total_read;
#endif
  void *buf;
  int finished;
  char quickbuf[1024];
  int err;


  //Check how much data there is coming in
  if (
#ifdef FIONREAD
      ioctl(sock->fd,FIONREAD,&chars_left)== -1
#else
# ifdef I_NREAD
      ioctl(sock->fd,I_NREAD,&chars_left)== -1
# else
#  error no valid read length method
# endif
#endif
      )
    {
      //The ioctl failed, this is a dead-socket case
      sock->flags|=SOCKET_DEAD;
      return 0;
    }

  if (!chars_left)
    {
      /*Linkdeath*/
      sock->flags|=SOCKET_DEAD;
      return 0;
    }


  //The buffer to store the data in. This is allocated statically as it gets
  //used and reused and there is NO point in creating it time and time
  //again
  if (chars_left < 1024)
    buf=quickbuf;
  else
    buf=malloc(chars_left);
  
  total_read=0;
  
  finished=0;
  
  while (!finished)
    {
      //Keep on looping till all data has been read
      if (chars_left==0)
        finished=1;
      else
        {
          //actually read the data from the socket
          if (sock->encrypted!=1)
            return 0;

          chars_read=SSL_read(sock->ssl,buf,chars_left);


          if (chars_read<1)
            {
              err=ssl_process_error(sock->ssl,chars_read);
              if (err==-1)
                {
                  //Anything else is bad, the socket is dead
                  sock->flags|=SOCKET_DEAD;
                }

              if (buf!=quickbuf)
                free(buf);

	      if (err==0)
		return total_read;
              return 0;
            }

#ifdef DEBUG
          //If we are in debug mode do that now
          if (sock->debug)
            socket_data_debug(sock,(char *)buf,chars_read,0);
#endif

          //Add the read data into the indata buffer
          if (sock->protocol!=SOCKET_INTERRUPT)
            dynstringRawappend(sock->indata,(char *)buf,chars_read);
          chars_left-=chars_read;
          sock->bytes_in+=chars_read;
          total_read+=chars_read;
        }


      //Check how much data there is coming in
#ifdef FIONREAD
      ioctl(sock->fd,FIONREAD,&chars_left);
#else
# ifdef I_NREAD
      ioctl(sock->fd,I_NREAD,&chars_left);
# else
#  error no valid read length method
# endif
#endif

      if (!chars_left)
        {
          finished=1;
        }
    }

  if (buf!=quickbuf)
    free(buf);
  
  return total_read;
}
#endif

//This is the generic function called to read data from the socket into the
//socket buffer. This is not called by the user. The user just looks at the
//buffer. This is called fro any type of socket, and the ones that this is not
//appropriate for it just hands off to other functions. This is THE base read
//functionf or ANY socket
static int socket_read(socketbuf *sock)
{
#ifdef FIONREAD
#ifdef WIN32
  unsigned long int chars_left;
#else
  unsigned int chars_left;
#endif
#else
  unsigned long int chars_left;
#endif
#ifdef _MSC_VER
  int chars_read,total_read;
#else
  ssize_t chars_read,total_read;
#endif
  void *buf;
  char quickbuf[1024];

  //Its a listener, read it differently using accepts
  if (sock->flags & SOCKET_LISTENER)
    {
      return socket_read_listener(sock);
    }

  //Its a UDP socket, all readable UDP sockets are listeners, you cant read
  //an outbound UDP socket
  if (sock->protocol==SOCKET_UDP)
    return 0;

#ifdef SOCK_SSL
  if (sock->encrypted>0)
    return socket_read_ssl(sock);
#endif
  
  //Check how much data there is coming in
  if (
#ifdef FIONREAD
      ioctl(sock->fd,FIONREAD,&chars_left)== -1
#else
# ifdef I_NREAD
      ioctl(sock->fd,I_NREAD,&chars_left)== -1
# else
#  error no valid read length method
# endif
#endif
      )
    {
      //The ioctl failed, this is a dead-socket case
      sock->flags|=SOCKET_DEAD;
      return 0;
    }

  if (!chars_left)
    {
      /*Linkdeath*/
      sock->flags|=SOCKET_DEAD;
      return 0;
    }


  //The buffer to store the data in. This is allocated statically as it gets
  //used and reused and there is NO point in creating it time and time
  //again
  if (chars_left < 1024)
    buf=quickbuf;
  else
    buf=malloc(chars_left);

  total_read=0;

  //Keep on looping till all data has been read
  while (chars_left>0)
    {
      //actually read the data from the socket
      chars_read=read_fn(sock->fd,buf,chars_left);

      if (chars_read==-1)
	{
	  //there was an error
	  if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN) //EAGAIN isnt bad, it just means try later
	    {
	      //Anything else is bad, the socket is dead
	      sock->flags|=SOCKET_DEAD;
	    }

	  if (buf!=quickbuf)
	    free(buf);

	  return 0;
	}

      if (chars_read==0)
	{
	  //No data was read, it shouldnt happen, if it does, then return from
	  //here.
	  if (buf!=quickbuf)
	    free(buf);

	  return 0;
	}

#ifdef DEBUG
      //If we are in debug mode do that now
      if (sock->debug)
	socket_data_debug(sock,(char *)buf,chars_read,0);
#endif

      //Add the read data into the indata buffer
      if (sock->protocol!=SOCKET_INTERRUPT)
	dynstringRawappend(sock->indata,(char *)buf,chars_read);
      chars_left-=chars_read;
      sock->bytes_in+=chars_read;
      total_read+=chars_read;
    }

  if (buf!=quickbuf)
    free(buf);

  return total_read;
}

//This function actually writes data to the socket. This is NEVER called by
//the user, as the socket could be in any state, and calling from the user
//would just break everything. This is called for stream sockets but not
//for datagram sockets like UDP
static int socket_process_write_stream(socketbuf *sock)
{
  int written;

  //Perform the write. Try and write as much as we can, as fast as we can
  written=write_fn(sock->fd,sock->outdata->buf,sock->outdata->len);

  if (written==-1)
    {
      //The write had an error
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN) /*EAGAIN simply means that the write buffer is full,
			   try again later, no problem*/
	{
	  //Any other error is fatal
	  sock->flags |= SOCKET_DEAD;
	}
    }
  else if (written > 0)
    {
#ifdef DEBUG
      //In debug mode, run the debug function
      if (sock->debug)
	socket_data_debug(sock,(char *)sock->outdata->buf,written,1);
#endif

      //Drop the written data from the buffer
      socket_outdata_drop(sock,written);
    }

  //Return the number of bytes written, in case they are needed
  return written;
}

#ifdef SOCK_SSL
//This function actually writes data to the SSL socket. This is NEVER called by
//the user, as the socket could be in any state, and calling from the user
//would just break everything. This is called for SSL encrypted sockets only
static int socket_process_write_ssl(socketbuf *sock)
{ 
  int written,err;

  if (sock->encrypted!=1)
    return 0;

  //Perform the write. Try and write as much as we can, as fast as we can
  written=SSL_write(sock->ssl,sock->outdata->buf,sock->outdata->len);


  if (written<1)
    {
      err=ssl_process_error(sock->ssl,written);

      if (err==-1)
        {
          //The write had an error                                              
          sock->flags |= SOCKET_DEAD;
          return 0;
        }
      return 0;
    }
  else
    {
#ifdef DEBUG
      //In debug mode, run the debug function
      if (sock->debug)
        socket_data_debug(sock,(char *)sock->outdata->buf,written,1);
#endif

      //Drop the written data from the buffer
      socket_outdata_drop(sock,written);
    }

  //Return the number of bytes written, in case they are needed
  return written;
}
#endif

static 
#ifdef _MSC_VER
int
#else
ssize_t
#endif
socket_sendto(socketbuf *sock,
	      SOCKET_FD_TYPE s,const void *buf,size_t len,int flags,
	      const struct sockaddr *to, socklen_t tolen)
{
  static char quickbuf[HOST_NAME_MAX+120+1+8+1024+8];
  char *newbuf;
#ifdef _MSC_VER
  int rv;
#else
  ssize_t rv;
#endif
  int offset;
  socket_intchar val;
  union 
  {
    short s;
    char c[2];
  } shortval;


  if (sock->udp2w_relay_by_listener && sock->parent)
    {
#ifdef _MSC_VER
      return sendto(sock->parent->fd,(const char *)buf,(int)len,flags,to,tolen);      
#else
      return sendto(sock->parent->fd,buf,len,flags,to,tolen);      
#endif
    }
  if (sock->udp2w_relaying_via_connector)
    {
      //If the packet is a connection out packet, just send it, no relay
      if (len >3)
	{
	  memcpy(val.c,buf,4);
	  if (ntohl(val.i)==SOCKET_UDP2W_PROTOCOL_CONNECTION)
	    {
#ifdef _MSC_VER
	      return sendto(s,(const char *)buf,(int)len,flags,to,(int)tolen);
#else
	      return sendto(s,buf,len,flags,to,(int)tolen);
#endif
	    }
	}
         

      if (len < 1024)
	newbuf=quickbuf;
      else
	newbuf=(char *)malloc(len+8+1024+8+1+120+HOST_NAME_MAX);


      val.i=htonl(SOCKET_UDP2W_PROTOCOL_LISTENER_RELAY);
      memcpy(newbuf,val.c,4);

      val.i=htonl(sock->port);
      memcpy(newbuf+4,val.c,4);

      memcpy(newbuf+8,buf,len);

      rv=sendto(s,newbuf,
#ifdef _MSC_VER
		(int)len+8,
#else
		len+8,
#endif
		flags,
		(struct sockaddr *)&sock->connect_sa,
		sizeof(struct sockaddr_in));

      if (newbuf!=quickbuf)
	free(newbuf);

      return rv;      
    }
  else if (sock->use_turn &&
      ((struct sockaddr_in *)to)->sin_addr.s_addr==sock->udp_sa.sin_addr.s_addr &&
      ((struct sockaddr_in *)to)->sin_port==sock->udp_sa.sin_port)
    {
      if (len < 1024)
	newbuf=quickbuf;
      else
	newbuf=(char *)malloc(len+8+1024+8+1+120+HOST_NAME_MAX);

      //Protocol is:
      //4 bytes: TURN protocol
      //4 bytes: target address sin_addr.s_addr in network order
      //2 bytes: target address sin_port in network order
      //4 bytes: Length of unique identifier
      //       : Unique identifier
      //       : Original Payload

      val.i=htonl(SOCKET_UDP2W_TURN_RELAY);
      memcpy(newbuf,val.c,4);

      val.i=sock->udp_sa.sin_addr.s_addr;
      memcpy(newbuf+4,val.c,4);

      shortval.s=sock->udp_sa.sin_port;
      memcpy(newbuf+8,shortval.c,2);


      val.i=htonl(sock->udp2w_uniquelen);
      memcpy(newbuf+10,val.c,4);
      
      memcpy(newbuf+14,sock->udp2w_unique,sock->udp2w_uniquelen);
       
      offset=sock->udp2w_uniquelen+14;

      memcpy(newbuf+offset,buf,len);
      
      rv=sendto(s,newbuf,
#ifdef _MSC_VER
		(int)len+offset,
#else
		len+offset,
#endif
		flags,
		(struct sockaddr *)&sock->stun_sa,
		sizeof(struct sockaddr_in));

      if (newbuf!=quickbuf)
	free(newbuf);

      return rv;
    }
  else
    {
      return sendto(s,(const char *)buf,
#ifdef _MSC_VER
		    (int)len,
#else
		    len,
#endif
		    flags,to,tolen);
    }
}

//Here we have a packet we have tried to send again and again., and it
//keeps failing, so chances are that somewhere, between us and the
//target, there is a relay or something that cannot handle a packet of
//this size. So, we need to split the packet down. If the packet is already
//split, we incriment the send index and start sending the whole packet
//again - the index stops parts of the old unsplit packet, being slow and
//corrupting the new packet. A previously unsplit packet just needs to have
//the split placed in it
static int socket_process_reprocess_large_dgram(socketbuf *sock,
						socket_udp_rdata *packet,
						size_t length)
{
  int loopa;
  size_t *newranges;  

  if (length < sock->udp2w_maxsend)
    {
      //We're saying this is longer than we can manage, drop the max length
      sock->udp2w_maxsend=length-17;
    }

  if (packet->ranges_size)
    {
      packet->split_index++;
      
      packet->resend_count=0;
      //Split each packet in half
      
      newranges=(size_t *)malloc(packet->ranges_size*2*sizeof(size_t));

      if (packet->range_received)
	free(packet->range_received);

      packet->range_received=(char **)calloc(1,packet->ranges_size*2*sizeof(char *));

      for (loopa=0;loopa < packet->ranges_size;loopa++)
	{
	  newranges[(loopa*2)]=packet->range_starts[loopa];
	  if (loopa==(packet->ranges_size-1))
	    newranges[(loopa*2)+1]=(packet->range_starts[loopa]+packet->length)/2;
	  else
	    newranges[(loopa*2)+1]=(packet->range_starts[loopa]+packet->range_starts[loopa+1])/2;
	}
      
      free(packet->range_starts);
      packet->range_starts=newranges;
      packet->ranges_size*=2;
      packet->ranges_left=packet->ranges_size;
    }
  else
    {
      //This is a single packet, we can just split it now and send it
      
      packet->range_starts=(size_t *)malloc(2*sizeof(size_t));
      packet->range_starts[0]=0;
      packet->range_starts[1]=packet->length/2;

      packet->range_received=(char **)calloc(1,2*sizeof(char *));

      packet->ranges_size=2;
      packet->ranges_left=2;

      packet->split_index=1;
    }

  return 1;
}

//This function is called from socket_process_write_dgram ONLY, and is really
//just itsown function for neatness purposes
static int socket_process_write_large_dgram(socketbuf *sock)
{
  socket_intchar val;
  size_t length,sendlength;
  socket_udp_rdata *packet;
  int packet_number;
  int subpacket_number=0;
  char *ptr;
  char *currentbuf=NULL;
  size_t currentbuflen=0;
  size_t smallranges[100];
  size_t *largeranges=NULL;
  int maxranges=100;
  size_t *ranges;
  int success,written,written_total=0;
 
  memcpy(val.c,sock->outdata->buf,4);

  length=val.i;

  if (length < sock->udp2w_maxsend)
    sock->udp2w_maxsend=length-1;

  //Now test the protocol we are using, it will be in the next 4 bytes
  memcpy(val.c,sock->outdata->buf+4,4);
  
  if (ntohl(val.i)!=SOCKET_UDP2W_PROTOCOL_RDATA)
    {
      //This is not reliable, just drop it. The drop is handled in the caller
      return 0;
    }

  //Get the packet number
  memcpy(val.c,sock->outdata->buf+8,4);
  packet_number=ntohl(val.i);

  packet=socket_rdata_locate_packetnum(sock->udp2w_rdata_out,
				       packet_number);
  if (!packet)
     return 0;

  ranges=smallranges;
  //Now loop trying to send each chunk, finding better sizes each time
  ptr=sock->outdata->buf+12;
  length-=8;
  while (length>0)
    {
      success=0;

      sendlength=(sock->udp2w_maxsend+sock->udp2w_minsend)/2;

      if (sendlength>length)
	sendlength=length;
      
      //Allocate memory to store the data
      if (sendlength + 16 > currentbuflen)
	{
	  if (currentbuflen==0)
	    currentbuf=(char *)malloc(sendlength+16);
	  else
	    currentbuf=(char *)realloc(currentbuf,sendlength+16);
	  currentbuflen=sendlength+16;
	}
      
      if (sendlength==length)
	val.i=htonl(SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA_FINAL);
      else
	val.i=htonl(SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA);
      
      memcpy(currentbuf,val.c,4);
      
      val.i=htonl(packet_number);
      memcpy(currentbuf+4,val.c,4);
      
      val.i=htonl(subpacket_number);
      memcpy(currentbuf+8,val.c,4);

      val.i=htonl(0);
      memcpy(currentbuf+12,val.c,4);

      memcpy(currentbuf+16,ptr,sendlength);

      //Now send the data
      written=socket_sendto(sock,sock->fd,
			    ptr,sendlength+16,
			    MSG_DONTWAIT,
			    (struct sockaddr *)&sock->udp_sa,
			    sizeof(struct sockaddr_in));
      
      if (written==-1) //There was an error
	{
	  if (GRAPPLE_SOCKET_ERRNO_IS_EMSGSIZE)
	    {
	      //Data too big, record the new maximum size
	      sock->udp2w_maxsend=sendlength+16-1;
	      if (sock->udp2w_maxsend < sock->udp2w_minsend)
		{
		  sock->udp2w_minsend=sock->udp2w_maxsend;
		}
	    }
	  else if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN) //If the error was EAGAIN just try again later when it hits a resend point
	    {
	      //The error was something fatal
	      sock->flags |= SOCKET_DEAD;
	      if (currentbuf)
		free(currentbuf);
	      return 0;
	    }
	  else
	    {
	      //It was eagain, set the resend data up
	      success=1;
	    }
	}
      else if (written > 0)
	{
	  success=1;
	}

      if (success)
	{
	  //The data was sent
	  written_total+=written;
	  
	  //Note the start in the resend buffer range list
	  if (subpacket_number >= maxranges)
	    {
	      maxranges*=2;
	      if (ranges==smallranges)
		{
		  largeranges=(size_t *)malloc(maxranges*sizeof(size_t));
		  memcpy(largeranges,smallranges,100*sizeof(size_t));
		  ranges=largeranges;
		}
	      else
		{
		  largeranges=(size_t *)realloc(largeranges,maxranges*sizeof(size_t));
		}	
	    }
	  
	  //Record the start of this range
	  ranges[subpacket_number++]=(size_t)(ptr-(sock->outdata->buf+12));

	  //Move the pointers
	  ptr+=(sendlength);
	  length-=(sendlength);

	}
    }
  
  if (currentbuf)
    free(currentbuf);

  //Now we've sent all the data, save this into the rdata packet
  packet->range_starts=(size_t *)malloc(subpacket_number*sizeof(size_t *));
  memcpy(packet->range_starts,ranges,subpacket_number*sizeof(size_t *));

  packet->range_received=(char **)calloc(1,subpacket_number*sizeof(char *));
  
  packet->ranges_left=subpacket_number;
  packet->ranges_size=subpacket_number;

  if (ranges!=smallranges)
    free(ranges);
  
  //We're done, all we can do is done now its up to the resend handler to make
  //sure its all there later
  return written_total;
}

//This function actually writes data to the socket. This is NEVER called by
//the user, as the socket could be in any state, and calling from the user
//would just break everything. This is called for datagram sockets but not
//for stream sockets like TCP or UNIX
static int socket_process_write_dgram(socketbuf *sock)
{
  int written;
  socket_intchar towrite;


  //The buffer contains one int of length data and then lots of data to
  //indicate a packet that should be sent all at once
  if (sock->outdata->len<4)
    return 0;

  //This is the length
  memcpy(towrite.c,sock->outdata->buf,4);

  //check we have enough data in the buffer to send it all
  if (sock->outdata->len<4+(size_t)towrite.i)
    return 0;

  //If we know we cannot send a packet this large, split it
  if ((size_t)towrite.i > sock->udp2w_maxsend)
    {
      //Data too big, split the packet and send in parts
      written=socket_process_write_large_dgram(sock);
      
      socket_outdata_drop(sock,towrite.i+4);

      if (sock->outdata->len>0)
	{
	  //Call back into the function
	  written+=socket_process_write_dgram(sock);
	}
      return written;
    }
  

  //We have enough, send the data. DO NOT send the initial length header,
  //it will get included in the receive data anyway, so we dont have to send
  //it twice
  written=socket_sendto(sock,sock->fd,
		 sock->outdata->buf+4,towrite.i,
		 MSG_DONTWAIT,
		 (struct sockaddr *)&sock->udp_sa,
		 sizeof(struct sockaddr_in));

  if (written==-1) //There was an error
    {
      if (GRAPPLE_SOCKET_ERRNO_IS_EMSGSIZE)
	{
	  //Data too big, split the packet and send in parts
	  written=socket_process_write_large_dgram(sock);
	  
	  socket_outdata_drop(sock,towrite.i+4);

	  if (sock->outdata->len>0)
	    {
	      //Call back into the function
	      written+=socket_process_write_dgram(sock);
	    }
  
	}
      else if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN) //If the error was EAGAIN just try later
	{
	  //The error was something fatal
	  sock->flags |= SOCKET_DEAD;
	  return 0;
	}
    }
  else if (written > 0)
    {
      //There was data sent

#ifdef DEBUG
      //If we are in debug mode, handle that
      if (sock->debug)
	socket_data_debug(sock,(char *)sock->outdata->buf+4,written,1);
#endif

      //Drop the data from the buffer
      socket_outdata_drop(sock,towrite.i+4);
      
      if (sock->outdata->len>0)
	{
	  //Recurse so we send as much as we can now till its empty or we error
	  written += socket_process_write_dgram(sock);
	}
    }

  return written;
}

//This is the generic function to handle writes for ALL sockets
static int socket_process_write(socketbuf *sock)
{
  //Only if we are connected and we have something to send
  if (socket_connected(sock) && 
      (sock->outdata && sock->outdata->len>0)
      )
    {
#ifdef SOCK_SSL
      if (sock->encrypted)
        { 
          return socket_process_write_ssl(sock);
        }
      else
#endif
	{
	  if (sock->protocol==SOCKET_UDP)
	    return socket_process_write_dgram(sock);
	  else
	    return socket_process_write_stream(sock);
	}
    }

  return 0;
}

//2 way UDP sockets will ping each other to keep the socket alive. They ping 
//every 10 seconds. If the sockets go 60 seconds with no ping, then the 
//socket is considered dead.

static int process_pings(socketbuf *sock)
{
  socket_intchar val;
  int written=0;
  char buf[4];
  time_t this_second;

  //Only ping 2 way UDP sockets
  if (!sock->udp2w)
    return 0;

  //Note the time
  this_second=time(NULL);

  //Handle STUN timeouts here too. Simply because we handle connection
  //timeouts here and the protocol is similar. This is for simplicity
  //As listeners can be STUNNed, we do this before the listener check
  //STUN gets 20 seconds, more than enough on even the slowest network for 
  //4 or 5 packets max
  if (sock->stun_nat_type==SOCKET_NAT_TYPE_IN_PROCESS && 
      this_second>sock->stun_starttime+3)
    {
      //Set it to this and all STUN resends stop. A late STUN response can
      //still be parsed and will override this if the state becomes known
      //after this
      switch (sock->stun_last_msg)
	{
	case SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER:
#ifdef STUN_DEBUG
	  printf("STUN: Client type set to symmatric firewall\n");
#endif
	  sock->stun_nat_type=SOCKET_NAT_TYPE_FW_SYMMETRIC;
	  sock->stun_keepalive=time(NULL)+10;
	  break;
	case SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER:
	  sock->stun_stage=1;
	  sock->stun_starttime=time(NULL);
	  sock->stun_connectcounter=0;
	  socket_udp2way_stun_start_stage1(sock);
	  break;
	case SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_PORT:
	  //This point is a legitimate finish point
	  sock->stun_nat_type=SOCKET_NAT_TYPE_PORT_RESTRICTED_CONE;
#ifdef STUN_DEBUG
	  printf("STUN: Client type set to port restricted cone\n");
#endif
	  sock->stun_keepalive=time(NULL)+10;
	  break;
	default:
	  sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
#ifdef STUN_DEBUG
	  printf("STUN: Client type set to unknown (2)\n");
#endif
	  break;
	}
    }

  //Cant ping from a listener, a listener is inbound
  if (sock->flags & SOCKET_LISTENER)
    return 0;
 
  //Dont ping connecting sockets, they time out so quickly anyway, and
  //we dont have the right address anyway
  if (sock->flags & SOCKET_CONNECTING)
    {
      //Or a much smaller 18 seconds if we are trying to connect.
      //This has been upped from 8 to 12 to allow for extra protocol
      //transmission which is used for NAT traversal
      //This is now upped to 18 seconds to allow for an attempt to connect via
      //a reverse connect via the STUN server, which begins after 6 seconds
      if (this_second>sock->udp2w_lastmsg+6)
	{
	  if (!sock->stun_host)
	    {
	      //Over 8 seconds with no STUN system, no connection
	      if (this_second>sock->udp2w_lastmsg+8)
		sock->flags |= SOCKET_DEAD;
	    }
	  else
	    {
	      //With STUN, over 6 seconds we start requesting a connection via
	      //the stun server
              //The udp2w_directport test is a HACK. Some IP MASQ cause local
              //networks to fuck up, and while one side can send to the other,
	      //the other cannot reply due to IP MASQ breaking the stateful
	      //firewall. This detects this problem and bails out to
	      //using TURN. Its a PITA
	      if (this_second>sock->udp2w_lastmsg+12 || sock->udp2w_directport>2)
		{
		  //Over 12 seconds, we try TURN
		  if (this_second>sock->udp2w_lastmsg+18 || sock->turn_refused)
		    {
		      //Over 18 seconds, or the STUN server refused TURN, then
		      //we're out of options
		      sock->flags |= SOCKET_DEAD;
		    }
		  else
		    {
		      //Only request turn if we havent already got it. If we
		      //have its now a case of wait for the connection
		      if (!sock->use_turn)
			{
			  if (sock->turn_connectcounter<1)
			    socket_client_request_connect_via_turn(sock);
			  else
			    sock->turn_connectcounter--;
			}
		    }
		}
	      else
		{
		  if (!sock->use_turn)
		    {
		      if (sock->stun_reconnectcounter<1)
			socket_client_request_connect_via_stun(sock);
		      else
			sock->stun_reconnectcounter--;
		    }
		}
	    }
	}
    }
  else
    {
  
      //Check we need to send a ping
      if (sock->udp2w_nextping < this_second)
	{
	  sock->udp2w_nextping = this_second+10;
	  
	  //Create the ping packet
	  val.i=htonl(SOCKET_UDP2W_PROTOCOL_PING);
	  memcpy(buf,val.c,4);
	  
	  //Actually send the ping
	  written=socket_sendto(sock,sock->fd,
			 buf,4,
			 MSG_DONTWAIT,
			 (struct sockaddr *)&sock->udp_sa,
			 sizeof(struct sockaddr_in));
	  
	  if (written==-1)
	    {
	      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
		{
		  //Note the socket as dead if we cant send it
		  sock->flags |= SOCKET_DEAD;
		  return 0;
		}
	    }
	}
      
      //Now we look at if its expired, over 60 seconds since any communication
      if (this_second>sock->udp2w_lastmsg+60)
	{
	  sock->flags |= SOCKET_DEAD;
	}
    }
  
  return written;
}

//This function handles reliable UDP resending packets. UDP does not
//guarentee transmission, so when we send a reliable packet, we get a repsonse
//from the other end. When that response comes through we can assume the
//packet is ok. Until then, we keep resending it on a time that is based on
//the average round trip packet time. This allows for congested networks
static int process_resends(socketbuf *sock)
{
  struct timeval time_now,target_time;
  long long us;
  socket_udp_rdata *scan;
  size_t newlen;
  int send_this_loop;
  socket_intchar udplen,udpdata;
  int loopa;

  //Only do this for 2 way UDP sockets
  if (!sock->udp2w)
    return 0;

  //If there are no outbound packets to confirm, nothing to do
  scan=sock->udp2w_rdata_out;
  if (!scan)
    return 0;


  //Now we need to find the exact time, as well as find which ones need 
  //resending
  gettimeofday(&time_now,NULL);

  //Find how old a packet needs to be
  us=sock->udp2w_averound/5; //Twice as long as average for a resend,/10*2 = /5

  target_time.tv_sec=time_now.tv_sec-(long)(us/1000000);
  target_time.tv_usec=time_now.tv_usec-(long)(us%1000000);

  if (target_time.tv_usec<0)
    {
      target_time.tv_usec+=1000000;
      target_time.tv_sec--;
    }

  scan=sock->udp2w_rdata_out;

  while (scan)
    {
      //Loop through checking each packet

      if (target_time.tv_sec > scan->sendtime.tv_sec ||
	  (target_time.tv_sec == scan->sendtime.tv_sec &&
	   target_time.tv_usec > scan->sendtime.tv_usec))
	{
	  //incriment the number of times we have tried to send this one
	  scan->resend_count++;

	  //This packet needs resending
	  if (scan->ranges_size)
	    {
	      send_this_loop=2+scan->received_this_send;
	      scan->received_this_send=0;
	      //It is a large packet, resend the parts that need it
	      for (loopa=0;loopa < scan->ranges_size && send_this_loop>0;
		   loopa++)
		{
		  if (scan->range_received[loopa]==0)
		    {
		      //This one hasnt been received yet, resend it
		      if (loopa==scan->ranges_size-1)
			{
			  newlen=scan->length-scan->range_starts[loopa];

			  if (scan->resend_count>30 &&
			      newlen > sock->udp2w_minsend)
			    {
			      //See comment below here for details
			      socket_process_reprocess_large_dgram(sock,scan,
								   newlen);
			      
			      //restart the for loop
			      loopa=-1;
			      continue;
			    }

			  udpdata.i=(SOCKET_INT_TYPE)newlen+16;

			  dynstringRawappend(sock->outdata,udpdata.c,4);
			  
			  udpdata.i=htonl(SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA_FINAL);
			}
		      else
			{
			  newlen=scan->range_starts[loopa+1]-scan->range_starts[loopa];

			  if (scan->resend_count>30 &&
			      newlen > sock->udp2w_minsend)
			    {
			      //See comment below here for details
			      socket_process_reprocess_large_dgram(sock,scan,
								   newlen);
			      
			      //Restart the for loop
			      loopa=-1;
			      continue;
			    }

			  udpdata.i=(SOCKET_INT_TYPE)newlen+16;
			  
			  dynstringRawappend(sock->outdata,udpdata.c,4);
			  
			  udpdata.i=htonl(SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA);
			}
		      
		      dynstringRawappend(sock->outdata,udpdata.c,4);
		      
		      udpdata.i=htonl(scan->packetnum);
		      dynstringRawappend(sock->outdata,udpdata.c,4);
		      
		      udpdata.i=htonl(loopa);
		      dynstringRawappend(sock->outdata,udpdata.c,4);
		      
		      udpdata.i=htonl(scan->split_index);
		      dynstringRawappend(sock->outdata,udpdata.c,4);

		      //Now send the data
		      dynstringRawappend(sock->outdata,scan->data+scan->range_starts[loopa],newlen);

		      send_this_loop--;
		    }
		}
	    }
	  else
	    {
	      //This is a non-split packet, send the data again

	      if (scan->resend_count>30 && scan->length > sock->udp2w_minsend)
		{
		  //This packet has failed to be sent 30 times
		  //It is also longer than any packet we have definitely sent 
		  //OK before. So, we need to assume that it failed to send

		  //As it is a single packet, we just need to split it and
		  //send it. No need to go through the complex system needed
		  //for already split packets
		  socket_process_reprocess_large_dgram(sock,scan,scan->length);

		}
	      else
		{
		  //Find the length the packet needs to be
		  newlen=scan->length;
		  newlen+=8;
		  
		  //Set this length into the buffer
		  udplen.i=(SOCKET_INT_TYPE)newlen;
		  dynstringRawappend(sock->outdata,udplen.c,4);
		  
		  //Send the protocol
		  udpdata.i=htonl(SOCKET_UDP2W_PROTOCOL_RDATA);
		  
		  dynstringRawappend(sock->outdata,udpdata.c,4);
		  
		  //Send the packet number
		  udpdata.i=htonl(scan->packetnum);
		  dynstringRawappend(sock->outdata,udpdata.c,4);
		  
		  //Send the data
		  dynstringRawappend(sock->outdata,scan->data,scan->length);
		  
		}
	    }

	  //note the new send time
	  scan->sendtime.tv_sec=time_now.tv_sec;
	  scan->sendtime.tv_usec=time_now.tv_usec;

	}

      //Next packet
      scan=scan->next;
      if (scan==sock->udp2w_rdata_out)
	scan=NULL;
    }

  return 0;
}

//This is the main function called to process user sockets. It handles
//calls to both input and output as well as processing incoming sockets
//and noting dead sockets as being dead. This is a program-called
//function and should be called often.
//Actual data is NOT returned from this function, this function simply
//calls appropriate subfunctions which update the internal buffers of
//sockets. It is the calling programs job to process this data.
int socket_process_sockets(socket_processlist *list,long int timeout)
{
  socket_processlist *scan;
  socketbuf *sock;
#if defined WIN32 && defined HAVE_WINSOCK2_H
  WSAEVENT events[FD_SETSIZE];
#else
  fd_set readers,writers;
  struct timeval select_timeout;
#endif
  int count,selectnum;
  time_t this_second;

  scan=list;
  this_second=time(NULL);
  //Loop through each socket in the list we have been handed
  while (scan)
    {
      sock=scan->sock;

      if (sock->udp2w)
	{
	  //If the socket is a 2 way UDP socket, process resends and pings
	  process_resends(sock);
	  process_pings(sock);
	}

      //Now process outbound writes (that will include any resends that have
      //just been created
#ifdef SOCK_SSL
      if (sock->encrypted>1)
	socket_process_ssl(sock);
      else 
#endif
	socket_process_write(sock);

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }  

  count=0;

#if !defined WIN32 || !defined HAVE_WINSOCK2_H
  FD_ZERO(&readers);
  FD_ZERO(&writers);
#endif

  scan=list;

  //Loop through all sockets again
  while (scan)
    {
      sock=scan->sock;

      //If the socket is alive
      if (
#ifdef SOCK_SSL
	  sock->encrypted<2 && 
#endif
	  !(sock->flags & SOCKET_DEAD))
	{
	  if (sock->flags & SOCKET_CONNECTING)
	    {
	      //This is a socket in the connecting state. See if it has now
	      //connected
	      if (sock->udp2w)
		{
		  //A connecting 2 way socket is one we need to send a 
		  //connection message to again. The connectcounter is
		  //explained in the socket_udp2way_connectmessage function
		  //comments
		  if (sock->udp2w_connectcounter<1)
		    socket_udp2way_connectmessage(sock);
		  else
		    sock->udp2w_connectcounter--;

		  //Now set its reader socket to look for a response
#if defined WIN32 && defined HAVE_WINSOCK2_H
		  WSAEventSelect(sock->fd,sock->event,FD_READ);
		  events[count]=sock->event;
#else
		  FD_SET(sock->fd,&readers);
#endif
		  count++;
		}
	      else
		{
		  //This socket should be set as a writer, as this will change
		  //when a stream socket connection state changes
#if defined WIN32 && defined HAVE_WINSOCK2_H
		  WSAEventSelect(sock->fd,sock->event,FD_WRITE);
		  events[count]=sock->event;
#else
		  FD_SET(sock->fd,&writers);
#endif
		  count++;
		}
	    }
	  else if (sock->flags & SOCKET_CONNECTED)
	    {
	      //This socket is alredy connected

	      //Set the main socket as a reader
#if defined WIN32 && defined HAVE_WINSOCK2_H
	      WSAEventSelect(sock->fd,sock->event,FD_READ|FD_ACCEPT);
	      events[count]=sock->event;
#else
	      FD_SET(sock->fd,&readers);
#endif

	      //Handle STUN here - simply because we did it this way for
	      //connection and the protocol is similar, lets not make it any
	      //more complex than it needs to be
	      if (sock->stun_nat_type==SOCKET_NAT_TYPE_IN_PROCESS)
		{
		  if (sock->stun_connectcounter<1)
		    {
		      if (sock->stun_stage==0)
			socket_udp2way_stun_start(sock);
		      else
			socket_udp2way_stun_start_stage1(sock);
		    }
		  else
		    sock->stun_connectcounter--;
		}

	      if (sock->stun_keepalive>0 && sock->stun_keepalive<this_second)
		{
		  socket_udp2way_stun_ping(sock);
		}

	      count++;
	    }
 	}

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  if (!count)
    //No valid sockets were ready to read, no point in reading them
    return 0;

  //Now actually run the select
#if defined WIN32 && defined HAVE_WINSOCK2_H
  selectnum=(unsigned)WSAWaitForMultipleEvents(count,events,0,timeout/1000,0);

  if(selectnum==WSA_WAIT_FAILED)
    selectnum=-1;
  else if(selectnum==WSA_WAIT_TIMEOUT)
    selectnum=0;
  else
    selectnum-=(WSA_WAIT_EVENT_0-1);
#else
  //Set the timeout to be as requested by the caller
  select_timeout.tv_sec=timeout/1000000;
  select_timeout.tv_usec=timeout%1000000;

  selectnum=select(FD_SETSIZE,&readers,&writers,0,&select_timeout);
#endif

  if (selectnum<1)
    {
      //Select was an error, or had no returns, we have nothing new to do now
      return 0;
    }

  //We have a result

  //Loop through all sockets see what we can see
  scan=list;

  while (scan)
    {
      sock=scan->sock;
      if (
#ifdef SOCK_SSL
	  sock->encrypted<2 && 
#endif
	  !(sock->flags & SOCKET_DEAD))
	{
	  if (sock->flags & SOCKET_CONNECTING)
	    {
	      //A connecting socket
	      if (sock->protocol==SOCKET_UDP)
		{
		  if (
#if defined WIN32 && defined HAVE_WINSOCK2_H
		      enumEvent(sock->fd,sock->event)==FD_READ
#else
		      FD_ISSET(sock->fd,&readers)
#endif
		      )
		    {
		      if (sock->flags & SOCKET_LISTENER)
			{
			  socket_read_listener(sock);
			}
		      else if (sock->udp2w)
			{
			  //Its a 2 way UDP - if it had any data
			  //Then send this to be processed. This will handle
			  //the connection data if that is what is received
			  socket_udp2way_read(sock,1);
			}
		    }
		}
	      else
		{
		  //If it has a writer, we simply assume it is done and 
		  //the first write will fail. Not very efficient but
		  //it works
		  if (
#if defined WIN32 && defined HAVE_WINSOCK2_H
		      enumEvent(sock->fd,sock->event)==FD_WRITE
#else
		      FD_ISSET(sock->fd,&writers)
#endif
		      )
		    {
		      sock->flags &=~ SOCKET_CONNECTING;
		      sock->flags |= SOCKET_CONNECTED;
		      sock->flags |= SOCKET_DELAYED_NOW_CONNECTED;
		      sock->connect_time=time(NULL);
		    }
		}
	    }
	  else if (sock->flags & SOCKET_CONNECTED)
	    {
	      //This is a connected socket, handle it
	      if (sock->protocol==SOCKET_UDP)
		{
		  if (
#if defined WIN32 && defined HAVE_WINSOCK2_H
		      enumEvent(sock->fd,sock->event)==FD_READ
#else
		      FD_ISSET(sock->fd,&readers)
#endif
		      )
		    {
		      if (sock->flags & SOCKET_LISTENER)
			{
			  socket_read_listener(sock);
			}
		      else if (sock->udp2w)
			{
			  //Then send this to be processed. This will handle 
			  //the connection data if that is what is received
			  socket_udp2way_read(sock,1);
			}
		    }
		}
	      else
		{
		  if (
#if defined WIN32 && defined HAVE_WINSOCK2_H
		      enumEvent(sock->fd,sock->event)&(FD_READ|FD_ACCEPT)
#else
		      FD_ISSET(sock->fd,&readers)
#endif
		      )
		    {
		      //Any other socket, read it using the generic read function
		      socket_read(sock);
		    }
		}
	    }
	}

      scan=scan->next;
      if (scan==list)
	scan=NULL;
    }

  //We're done, return how many sockets were affected
  return count;
}


//This is a wrapper function for processing one single socket. It makes it
//into a socketlist of one entry, and sends it to the previous
//function for handling.
int socket_process(socketbuf *sock,long int timeout)
{
  socket_processlist listofone;

  listofone.next=&listofone;
  listofone.prev=&listofone;
  listofone.sock=sock;

  return socket_process_sockets(&listofone,timeout);
}

#ifdef HAVE_SYS_UN_H
//Wrapper function to create a unix socket. It is assumed that wait is the
//required functionality
socketbuf *socket_create_unix(const char *path)
{
  return socket_create_unix_wait(path,1);
}
#endif

//Wrapper function to create a TCPIP socket. It is assumed that wait is the
//required functionality
socketbuf *socket_create_inet_tcp(const char *host,int port)
{
  return socket_create_inet_tcp_wait(host,port,1);
}

//Create a tcpip socket on a specific IP address
socketbuf *socket_create_inet_tcp_listener_on_ip(const char *localip,int port)
{
  struct sockaddr_in sa;
  unsigned long int dummy=0;
  char hostname[HOST_NAME_MAX+1];
  struct hostent *hp;
  SOCKET_FD_TYPE fd;
  socketbuf *sock;
  struct in_addr inet_address;
  struct linger lingerval;
#ifndef FIONBIO
#ifdef O_NONBLOCK
  int flags;
#endif
#endif

  //set the hostname. If this is passed in, use that, otherwise use any
  memset(&sa,0,sizeof(struct sockaddr_in));
  if (localip)
  {
    strcpy(hostname,localip);

    //Simply gethostbyname which handles all kinds of addresses
    hp=gethostbyname(hostname);

    if (!hp)
      //We couldnt resolve the host fail
      return 0;

    //We specifically requested an IP address, so we use it, thus restricting
    //to just one interface. If we didnt specify the address then we skip
    //this section which in effect means that the socket will bind to all
    //IP addresses on the system
    memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));
    if (inet_address.s_addr!=-1)
      sa.sin_addr.s_addr=inet_address.s_addr;
    sa.sin_family=hp->h_addrtype;
    sa.sin_port = htons(port);
  }
  else
  {
    sa.sin_addr.s_addr=INADDR_ANY;
    sa.sin_family=AF_INET;
    sa.sin_port = htons(port);
  }


  //Create the socket
  fd = socket(AF_INET,SOCK_STREAM,0);
  
  if (fd < 0)
    {
      //We couldnt create the socket!
      return 0;
    }

  dummy=1;
  //Set REUSEADDR so that if the system goes down it can go right 
  //back up again. Otherwise it will block until all data is processed
  setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&dummy,sizeof(dummy));

  //Linger so that data is sent when the socket closes
  lingerval.l_onoff=0;
  lingerval.l_linger=0;
  setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
	     sizeof(struct linger));

  //set non-blocking
#ifdef FIONBIO
  dummy=1;
  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      close(fd);
      return 0;
    }
#else
# ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);
  if (flags < 0)
    {
      close(fd);
      return 0;
    }
  else
    if (fcntl(fd,F_SETFL,flags|O_NONBLOCK) < 0)
      {
	close(fd);
	return 0;
      }
# else
#  error no valid non-blocking method
# endif
#endif /*FIONBIO*/

  //Now bind the socket to the port
  if (bind(fd,(struct sockaddr *)&sa,sizeof(sa))<0)
    {
      //We failed, maybe something else is already bound, maybe something
      //else, regardless, we're stuffed
      shutdown(fd,2);
      close(fd);
      return 0;
    }

  //Listen with the maximum number - this means we can have as many incoming
  //connections as the kernel is configured to handle (on the machine that
  //builds of course, it wont magically change itself from machine to machine)
  if (listen(fd,SOMAXCONN)<0)
    {
      shutdown(fd,2);
      close(fd);
      return 0;
    }
  
  //Finally create the socket datastruct to hold the socket
  sock=socket_create(fd);
  sock->protocol=SOCKET_TCP;
  sock->port=port;
  sock->host=(char *)malloc(strlen(hostname)+1);
  strcpy(sock->host,hostname);

  sock->flags |= (SOCKET_CONNECTED|SOCKET_LISTENER);
  sock->connect_time=time(NULL);

  return sock;
}

//Create a listener on ALL sockets
socketbuf *socket_create_inet_tcp_listener(int port)
{
  return socket_create_inet_tcp_listener_on_ip(NULL,port);
}

//Create a UDP listener
socketbuf *socket_create_inet_udp_listener_on_ip(const char *localip,int port)
{
  struct sockaddr_in sa;
  unsigned long int dummy=0;
  char hostname[HOST_NAME_MAX+1];
  struct hostent *hp;
  SOCKET_FD_TYPE fd;
  socketbuf *sock;
  struct in_addr inet_address;
  struct linger lingerval;
#ifndef FIONBIO
#ifdef O_NONBLOCK
  int flags;
#endif
#endif

  //set the hostname. If this is passed in, use that, otherwise use any
  memset(&sa,0,sizeof(struct sockaddr_in));
  if (localip)
  {
    strcpy(hostname,localip);

    //Simply gethostbyname which handles all kinds of addresses
    hp=gethostbyname(hostname);

    if (!hp)
      //We couldnt resolve the host fail
      return 0;

    //We specifically requested an IP address, so we use it, thus restricting
    //to just one interface. If we didnt specify the address then we skip
    //this section which in effect means that the socket will bind to all
    //IP addresses on the system
    memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));
    if (inet_address.s_addr!=-1)
      sa.sin_addr.s_addr=inet_address.s_addr;
    sa.sin_family=hp->h_addrtype;
    sa.sin_port = htons(port);
  }
  else
  {
    sa.sin_addr.s_addr=INADDR_ANY;
    sa.sin_family=AF_INET;
    sa.sin_port = htons(port);
  }

  //Create the socket
  fd = socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
  
  if (fd < 0)
    {
      //We couldnt create the socket!
      return 0;
    }

  lingerval.l_onoff=0;
  lingerval.l_linger=0;
  setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
	     sizeof(struct linger));


  //Set non-blocking
#ifdef FIONBIO
  dummy=1;
  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      close(fd);
      return 0;
    }
#else
# ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);
  if (flags < 0)
    {
      close(fd);
      return 0;
    }
  else
    if (fcntl(fd,F_SETFL,flags|O_NONBLOCK) < 0)
      {
	close(fd);
	return 0;
      }
# else
#  error no valid non-blocking method
# endif
#endif /*FIONBIO*/

  //Bind to the port
  if (bind(fd,(struct sockaddr *)&sa,sizeof(sa))<0)
    {
      //We failed, maybe something else is already bound, maybe something
      //else, regardless, we're stuffed
      shutdown(fd,2);
      close(fd);
      return 0;
    }

  //Finally create the socket datastruct to hold the socket
  sock=socket_create(fd);
  sock->protocol=SOCKET_UDP;
  sock->port=port;
  sock->host=(char *)malloc(strlen(hostname)+1);
  strcpy(sock->host,hostname);

  sock->flags |= (SOCKET_CONNECTED|SOCKET_LISTENER);
  sock->connect_time=time(NULL);

  return sock;
}

//A wrapper function to bind a UDP listener on all interfaces
socketbuf *socket_create_inet_udp_listener(int port)
{
  return socket_create_inet_udp_listener_on_ip(NULL,port);
}

#ifdef HAVE_SYS_UN_H
//Create a unix socket listener.
socketbuf *socket_create_unix_listener(const char *path)
{
  int fd;
  long int dummy;
  socketbuf *sock;
  struct sockaddr_un sa;
  struct linger lingerval;
#ifdef O_NONBLOCK
  int flags;
#endif

  //Create the socket
  fd = socket(PF_UNIX,SOCK_STREAM,0);

  if (fd < 1)
    //Socket creation failed
    return 0;

  //Set the socket types
  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path,path);

  //Set this to linger so any data being processed will be finished
  lingerval.l_onoff=0;
  lingerval.l_linger=0;
  setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
	     sizeof(struct linger));


  //Set nonblocking
#ifdef FIONBIO
  dummy=1;
  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      close(fd);
      return 0;
    }
#else
# ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);
  if (flags < 0)
    {
      close(fd);
      return 0;
    }
  else
    if (fcntl(fd,F_SETFL,flags|O_NONBLOCK) < 0)
      {
	close(fd);
	return 0;
      }
# else
#  error no valid non-blocking method
# endif
#endif /*FIONBIO*/


  //Now bind to the location
  if (bind(fd,(struct sockaddr *)&sa,sizeof(sa)) < 0)
    {
      //We failed. Maybe the file is already there...
      close(fd);
      return 0;
    }

  //Listen with the maximum number - this means we can have as many incoming
  //connections as the kernel is configured to handle (on the machine that
  //builds of course, it wont magically change itself from machine to machine)
  if (listen(fd,SOMAXCONN) < 0)
    {
      shutdown(fd,2);
      close(fd);
      unlink(path);
      return 0;
    }

  //Finally create the socket datastruct to hold the socket
  sock=socket_create(fd);
  sock->protocol=SOCKET_UNIX;
  sock->path=(char *)malloc(strlen(path)+1);
  strcpy(sock->path,path);

  sock->flags |= (SOCKET_CONNECTED|SOCKET_LISTENER);
  sock->connect_time=time(NULL);

  return sock;
}
#endif

//This is the function used by the calling program to see if any new 
//connections have come in on a listener socket
socketbuf *socket_new(socketbuf *parent)
{
  socketbuf *returnval;

  //Destroy any sockets that have died in the connection process. This doesnt
  //get them all, just the first ones, until the one at the front is a live.
  //This assumes that this function is called often, and so dead connections
  //are cleaned up regularly.
  while (parent->new_children && socket_dead(parent->new_children))
    {
      returnval=parent->new_children;

      //Unlink the dead socket
      parent->new_children=parent->new_children->new_child_next;

      if (parent->new_children==returnval)
	{
	  parent->new_children=NULL;
	  returnval->new_child_next=NULL;
	  returnval->new_child_prev=NULL;
	}
      else
	{
	  returnval->new_child_next->new_child_prev=returnval->new_child_prev;
	  returnval->new_child_prev->new_child_next=returnval->new_child_next;
	}
      //destroy it
      socket_destroy(returnval);
    }

  //Now look for new sockets
  if (parent->new_children)
    {
      returnval=parent->new_children;

      //Unlink the first socket from the list of new connections
      parent->new_children=parent->new_children->new_child_next;
      
      if (parent->new_children==returnval)
	{
	  parent->new_children=NULL;
	  returnval->new_child_next=NULL;
	  returnval->new_child_prev=NULL;
	}
      else
	{
	  returnval->new_child_next->new_child_prev=returnval->new_child_prev;
	  returnval->new_child_prev->new_child_next=returnval->new_child_next;
	}

      //Now link it in to the list of connected children
      if (parent->connected_children)
	{
	  returnval->connected_child_next=parent->connected_children;
	  returnval->connected_child_prev=
	    parent->connected_children->connected_child_prev;
	  returnval->connected_child_prev->connected_child_next=returnval;
	  returnval->connected_child_next->connected_child_prev=returnval;
	}
      else
	{
	  parent->connected_children=returnval;
	  returnval->connected_child_next=returnval;
	  returnval->connected_child_prev=returnval;
	}

      //Return the new socket
      return returnval;
    }

  //No new connection
  return NULL;
}

//If the socket has just connected (fairly useless, legacy now)
int socket_just_connected(socketbuf *sock)
{
  if (sock->flags & SOCKET_DELAYED_NOW_CONNECTED)
    {
      sock->flags &=~ SOCKET_DELAYED_NOW_CONNECTED;
      return 1;
    }

  return 0;
}

//Return the portnumber
int socket_get_port(socketbuf *sock)
{
  if (sock->published_port)
    return sock->published_port;
  return sock->port;
}

int socket_get_sending_port(socketbuf *sock)
{
  return sock->sendingport;
}

#ifdef DEBUG
//Set debug mode on or off
void socket_debug_off(socketbuf *sock)
{
  sock->debug=0;
}
void socket_debug_on(socketbuf *sock)
{
  sock->debug=1;
}
#endif

//Return the time the socket connected
time_t socket_connecttime(socketbuf *sock)
{
  return sock->connect_time;
}

//Set a flag into the sockets mode. The only flag right now is sequential
//and only applies to 2 way UDP sockets
int socket_mode_set(socketbuf *sock,unsigned int mode)
{
  sock->mode|=mode;
  return 1;
}

//Remove a flag from a socket
int socket_mode_unset(socketbuf *sock,unsigned int mode)
{
  sock->mode&=~mode;
  return 1;
}

//Get the sockets mode
unsigned int socket_mode_get(socketbuf *sock)
{
  return sock->mode;
}

const char *socket_host_get(socketbuf *sock)
{
  if (sock->published_port)
    return sock->published_address;
  return sock->host;
}

#ifdef SOCK_SSL

void socket_set_encrypted(socketbuf *sock)
{
  static int ssl_initialised=0;

  if (!ssl_initialised)
    {
      ssl_initialised=1;
      SSL_library_init();
      SSL_load_error_strings();
    }

  sock->encrypted=2;
  if (sock->flags & SOCKET_LISTENER)
    {
      if (socket_set_encrypted_keys(sock))
	sock->encrypted=1;
    }
  else if (sock->flags & SOCKET_INCOMING)
    socket_set_server_encrypted(sock);
  else
    socket_set_client_encrypted(sock);
}


void socket_set_private_key(socketbuf *sock,const char *key,
			    const char *password)
{
  sock->private_key=(char *)malloc(strlen(key)+1);
  strcpy(sock->private_key,key);
  if(password)
    {
      sock->private_key_password=(char *)malloc(strlen(password)+1);
      strcpy(sock->private_key_password,password);
    }
}

void socket_set_public_key(socketbuf *sock,const char *cert)
{
  sock->public_key=(char *)malloc(strlen(cert)+1);
  strcpy(sock->public_key,cert);
}

void socket_set_ca(socketbuf *sock,const char *ca)
{
  sock->ca=(char *)malloc(strlen(ca)+1);
  strcpy(sock->ca,ca);
}

#endif //SOCK_SSL

//This moves the buffers from one socket to another, MOVING it, not
//copying it. This is not a simple task as it needs to take into
//account all buffers in the UDP resend queue to!
void socket_relocate_data(socketbuf *from,socketbuf *to)
{
  socket_udp_rdata *scan,*target;

  //Transfer data in the resend queue to the new out queue. Do this first so it
  //goes back out in order
  while (from->udp2w_rdata_out)
    {
      scan=from->udp2w_rdata_out;
      target=scan;
      while (scan)
	{
	  if (scan->packetnum < target->packetnum)
	    target=scan;
	  scan=scan->next;
	  if (scan==from->udp2w_rdata_out)
	    scan=NULL;
	}

      //Add this data to the out queue
      socket_write_reliable(to,
			    target->data,target->length);

      //Now unlink that target
      from->udp2w_rdata_out=socket_rdata_delete(from->udp2w_rdata_out,target);
    }


  //Transfer the old outqueue to the new outqueue
  dynstringRawappend(to->outdata,(char *)(from->outdata->buf),from->outdata->len);
  from->outdata->len=0;

  //Transfer any unread inqueue to the new inqueue
  dynstringRawappend(to->indata,(char *)(from->indata->buf),from->indata->len);
  from->indata->len=0;

  //We're done
  return;
}


/****************************************************************************
 **                Extention for 2-way and reliable UDP                    **
 ** This is NOT generally compatable, you need to run this socket code     **
 ** at both ends                                                           **
 ****************************************************************************/


//Send the connection message to a remote listener. This initialises the
//session
int socket_udp2way_connectmessage(socketbuf *sock)
{
  int written;
  int datalen;
  socket_intchar intval;
  char buf[HOST_NAME_MAX+120+1+8];
  //short tmpport;

  //Now we construct new data to send
  //Data is as follows:

  //4 bytes: Protocol
  //4 bytes: The length of the unique identifier string
  //       : The unique identifier string
  //

#ifdef UDP_PROTOCOL_DEBUG
  printf("Sending SOCKET_UDP2W_PROTOCOL_CONNECTION\n");
#endif
  intval.i=htonl(SOCKET_UDP2W_PROTOCOL_CONNECTION);
  memcpy(buf,intval.c,4);

  datalen=sock->udp2w_uniquelen;
  intval.i=htonl(datalen);
  memcpy(buf+4,intval.c,4);

  memcpy(buf+8,sock->udp2w_unique,datalen);

  //Now we have to make sure we are sending to the correct port. The port can
  //be changed in handshake stage 2, and so we must be sure to only send to
  //the original port. If not, the UDP packet may be lost in stage 2 and stage
  //1 (this one) may just keep sending connect packets to the wrong place,
  //causing connection to hang and fail.

  //Send the data to the socket
  written=socket_sendto(sock,sock->fd,
		 buf,8+datalen,
		 MSG_DONTWAIT,
		 (struct sockaddr *)&sock->connect_sa,
		 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //If the error is not EAGAIN, its dead
	  sock->flags |= SOCKET_DEAD;
          return 0;
        }
    }

  //Incriment the connection counter. This is not a 'counter', this just
  //incriments each time a message about connection is received, and then
  //decriments each time we think about re-trying the connect. This way,
  //we reduce the number of resends, as we dont need to resend if we have
  //just received a packet further down the chain
  sock->udp2w_connectcounter+=2;

  //Return the number of bytes sent
  return written;
}


//This is sent as a reply, the connectmessage has been received, now we need to
//acknowledge it
static int socket_udp2way_connectmessage_reply(socketbuf *sock)
{
  int written;
  socket_intchar val;
  char buf[4];

  //Now we construct new data to send
  //4 bytes : protocol

#ifdef UDP_PROTOCOL_DEBUG
  printf("Sending SOCKET_UDP2W_PROTOCOL_CONNECTION_REPLY\n");
#endif
  val.i=htonl(SOCKET_UDP2W_PROTOCOL_CONNECTION_REPLY);
  memcpy(buf,val.c,4);

  //Send the data
  written=socket_sendto(sock,sock->fd,
                 buf,4,
                 MSG_DONTWAIT,
                 (struct sockaddr *)&sock->udp_sa,
                 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //This is a fatal error, kill the socket
	  sock->flags |= SOCKET_DEAD;
          return 0;
        }
    }

  return written;
}

//This is sent as a reply, the connectmessage has been received, now we need to
//acknowledge it
static int socket_udp2way_connectmessage_listener_reply(socketbuf *sock,
							socketbuf *clientsock)
{
  int written;
  socket_intchar val;
  char buf[8];

  //Now we construct new data to send
  //4 bytes : protocol

#ifdef UDP_PROTOCOL_DEBUG
  printf("Sending SOCKET_UDP2W_PROTOCOL_CONNECTION_FROMLISTENER_REPLY\n");
#endif
  val.i=htonl(SOCKET_UDP2W_PROTOCOL_CONNECTION_FROMLISTENER_REPLY);
  memcpy(buf,val.c,4);

  val.i=htonl(clientsock->sendingport);
  memcpy(buf+4,val.c,4);

  //Send the data
  written=socket_sendto(sock,sock->fd,
                 buf,8,
                 MSG_DONTWAIT,
                 (struct sockaddr *)&clientsock->udp_sa,
                 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //This is a fatal error, kill the socket
	  sock->flags |= SOCKET_DEAD;
          return 0;
        }
    }

  return written;
}


//This function creates a 2 way UDP socket connection to a remote host,
//and binds it to a known port
socketbuf *socket_create_inet_udp2way_wait_onport_stun(const char *host,
						       int port,int wait,
						       int localport,
						       const char *stunaddress,
						       int stunport)
{
  socketbuf *sock;
  int inport;
  struct timeval time_now;
  char hostname[HOST_NAME_MAX+1];
  struct sockaddr_in sa;
  struct linger lingerval;
  SOCKET_FD_TYPE fd;
  unsigned long int dummy=0;
  struct in_addr inet_address;
  struct hostent *hp;
#ifndef FIONBIO
# ifdef O_NONBLOCK
  int flags;
# endif
#endif


  //We need to know where to connect to.
  if (!host || !*host)
    return 0;

  //Create the socket
  fd=socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
  if (fd<1)
    return 0;

  //Now create the data structure around the socket
  sock=socket_create(fd);

  memset(&sock->udp_sa,0,sizeof(struct sockaddr_in));

  //Lookup the hostname we are sending to
  hp=gethostbyname(host);
  if (!hp)
    inet_address.s_addr=-1;
  else
    memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));

  if (inet_address.s_addr==-1)
    {
      //We couldnt resolve the address, destroy the socket
      socket_destroy(sock);
      close(fd);
      return 0;
    }

  //Save the data for later use in the datastruct
  sock->udp_sa.sin_family=AF_INET;
  sock->udp_sa.sin_port=htons(port);
  sock->udp_sa.sin_addr.s_addr=inet_address.s_addr;

  sock->connect_sa.sin_family=AF_INET;
  sock->connect_sa.sin_port=htons(port);
  sock->connect_sa.sin_addr.s_addr=inet_address.s_addr;


  //Note the protocol
  sock->protocol=SOCKET_UDP;

  //Save the text representation of the address
  sock->host=(char *)malloc(strlen(host)+1);
  strcpy(sock->host,host);
  sock->port=port;

  //Set non-blocking, so we can check for a data without freezing

#ifdef FIONBIO
  dummy=1;

  if (ioctl(fd,FIONBIO,&dummy)<0)
    {
      close(fd);
      socket_destroy(sock);
      return 0;
    }
#else
#  ifdef O_NONBLOCK
  flags=fcntl(fd,F_GETFL,0);

  if (flags<0)
    {
      close(fd);
      socket_destroy(sock);
      return 0;
    }

  if (fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)
    {
      close(fd);
      socket_destroy(sock);
      return 0;
    }

# else
#  error No valid non-blocking method - cannot build;
  // next is end of O_NONBLOCK
# endif
  // next is end of FIONBIO
#endif

  //While we technically havent connected, we are ready to send data, and thats
  //what is important
  sock->connect_time=time(NULL);

  //Here we now need to bind the socket to a port so that
  // a) it has a source address
  // b) the socket can be used to send AND receive
  memset(&sa,0,sizeof(struct sockaddr_in));

  gethostname(hostname,HOST_NAME_MAX);

  //Simply gethostbyname which handles all kinds of addresses
  hp=gethostbyname(hostname);

  if (!hp)
    {
      socket_destroy(sock);
      close(fd);
      //We couldnt resolve the host fail
      return 0;
    }

  lingerval.l_onoff=0;
  lingerval.l_linger=0;
  setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
	     sizeof(struct linger));

  sa.sin_family=hp->h_addrtype;
  
  //Loop through the sockets, starting one higher than the sender, and find an
  //open socket to bind to.
  if (localport)
    inport=localport-1;
  else
    inport=port;
  while (!sock->sendingport)
    {
      inport++;
      sa.sin_port = htons(inport);

      //Bind to the port
      if (bind(fd,(struct sockaddr *)&sa,sizeof(sa))==0)
	{
	  sock->sendingport=inport;
	}
      if (localport && !sock->sendingport)
	{
	  //We requested to be bound onto one specific port, we failed, so bail
	  socket_destroy(sock);
	  close(fd);
	  return 0;
	}
    }


  sock->udp2w=1;
  sock->udp2w_averound=2500000; /*Set it for a sloooooow network, it will 
				  modify itself if the network shows it is
				  faster*/
  sock->udp2w_lastmsg=time(NULL);

  sock->flags|=SOCKET_CONNECTING;

  //Send the init data

  //We CANNOT wait for the response, or it will never get there if the
  //client and server run on the same thread

  //Now we set a unique value, as we use UDP, so the other side knows WHO
  //is connecting
  gethostname(hostname,HOST_NAME_MAX);

  gettimeofday(&time_now,NULL);

  //Create a unique name for this client. This will be unique anywhere unless
  //you have 2 connections on the same machine in the same microsecond from
  //the same port. Pretty fullproof I reckon
  sprintf(sock->udp2w_unique,"%s-%d-%ld.%ld",hostname,inport,
	  time_now.tv_sec,time_now.tv_usec);
  sock->udp2w_uniquelen=(int)strlen(sock->udp2w_unique);

  //Send the connect protocol message to the remote server
  socket_udp2way_connectmessage(sock);

  if (stunaddress)
    {
      //Generate a sockaddr from this data
      //Lookup the hostname we are sending to
      hp=gethostbyname(stunaddress);
      if (!hp)
	inet_address.s_addr=-1;
      else
	memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));
      
      if (inet_address.s_addr==-1)
	{
	  //We couldnt resolve the address, no STUN for us
	  return sock;
	}
      
      //Save the data for later use in the datastruct
      sock->stun_sa.sin_family=AF_INET;
      sock->stun_sa.sin_port=htons(stunport);
      sock->stun_sa.sin_addr.s_addr=inet_address.s_addr;
      
      //Register the stun server address
      if (stunaddress!=sock->stun_host)
	{
	  if (sock->stun_host)
	    free(sock->stun_host);
	  sock->stun_host=(char *)malloc(strlen(stunaddress)+1);
	  strcpy(sock->stun_host,stunaddress);
	}
      sock->stun_port=stunport;
    }
  
  return sock;
}

socketbuf *socket_create_inet_udp2way_wait_onport(const char *host,
						  int port,int wait,
						  int localport)
{
  return socket_create_inet_udp2way_wait_onport_stun(host,port,wait,localport,
						     NULL,0);
}

//This function creates a 2 way UDP socket connection to a remote host,
socketbuf *socket_create_inet_udp2way_wait(const char *host,int port,int wait)
{
  //Call the subfunction that allows setting of outgoing ports,
  //but set the outgoing to 0 to allow any port
  return socket_create_inet_udp2way_wait_onport(host,port,wait,0);
}

//Create the 2 way listener on a specific IP address
socketbuf *socket_create_inet_udp2way_listener_on_ip(const char *localip,
						     int port)
{
  socketbuf *sock;

  //Create the basic UDP listener
  sock=socket_create_inet_udp_listener_on_ip(localip,port);

  //All we do extra is the 2 way UDP specific values
  if (sock)
    {
      sock->udp2w=1;
      sock->udp2w_averound=2500000;
      sock->udp2w_lastmsg=time(NULL);
    }

  return sock;
}

//Wrapper function, to set a 2 way UDP listener bound to all interfaces
socketbuf *socket_create_inet_udp2way_listener(int port)
{
  return socket_create_inet_udp2way_listener_on_ip(NULL,port);
}


static socketbuf *socket_get_child_socketbuf_by_sendport(socketbuf *sock,
							 int sendingport)
{
  socketbuf *scan;

  scan=sock->new_children;
  while (scan)
    {
      if (scan->sendingport == sendingport)
	return scan;
      scan=scan->new_child_next;
      if (scan==sock->new_children)
	scan=NULL;
    }

  scan=sock->connected_children;
  while (scan)
    {
      if (scan->sendingport == sendingport)
	return scan;
      scan=scan->connected_child_next;
      if (scan==sock->connected_children)
	scan=NULL;
    }

  return NULL;
}


//This function takes a bit of explaining.
//UDP always sends data to the 'listener' socket, not to a socket specific to
//the user. This means that all data comes in to the one socket and then needs
//to be associated with a socket for THAT user
//So, each packet contains the IP address and the portnumber of the sender
//which allows unique identification. This function looks at all sockets
//that are children of the listener, and finds the one that matches the host
//and the portnumber of the sender.
static socketbuf *socket_get_child_socketbuf(socketbuf *sock,
					     char *host,int port)
{
  socketbuf *scan;

  scan=sock->new_children;
  while (scan)
    {
      if (!strcmp(scan->host,host) && scan->port==port && !socket_dead(scan))
	return scan;
      scan=scan->new_child_next;
      if (scan==sock->new_children)
	scan=NULL;
    }

  scan=sock->connected_children;
  while (scan)
    {
      if (!strcmp(scan->host,host) && scan->port==port && !socket_dead(scan))
	return scan;
      scan=scan->connected_child_next;
      if (scan==sock->connected_children)
	scan=NULL;
    }

  return NULL;
}

//This function is called when a 2 way UDP connection is received. This
//means that we need to find out if we are already connected, and then
//connect back to them if we arent. We must also allow for the fact that
//someone may reconnect when we THINK they are already connected
static socketbuf *socket_udp2way_listener_create_connection(socketbuf *sock,
							    struct sockaddr_in *sa,
							    socklen_t sa_len,
							    int port,
							    char *unique,
							    int using_turn)
{
  SOCKET_FD_TYPE fd;
  unsigned long int dummy;
  socketbuf *returnval,*oldreturnval;
  char host[20];
  struct sockaddr_in bindsa;
  char hostname[HOST_NAME_MAX+1];
  struct hostent *hp;
  struct linger lingerval;
  int inport;
#ifndef FIONBIO
# ifdef O_NONBLOCK
  int flags;
# endif
#endif

  //Create an outgoing socket back to the originator

  //Find their IP address
  inet_ntop(AF_INET,(void *)(&sa->sin_addr),host,19);

  //Find if anyone else is connected to this listener from that port
  returnval=socket_get_child_socketbuf(sock,host,port);


  //Note if we have no match already connected, this whole loop will not
  //start
  oldreturnval=0;
  while (returnval && returnval!=oldreturnval)
    {
      //We loop here onthe highly unlikely chance we already have 2
      //connections from the same port. This is impossible but just in case,
      //its a negligable overhead to be sure

      oldreturnval=returnval;
      /*First, check if we are already connected to THIS one*/

      if (returnval->udp2w_unique && strcmp(returnval->udp2w_unique,unique))
	{
	  //This is a different one, mark THAT one as dead, cos we cant 
	  //have 2 sockets coming from the same place, its impossible. The old
	  //one must be dead
	  returnval->flags |= SOCKET_DEAD;
	}
      returnval->udp2w_lastmsg=time(NULL);
      returnval=socket_get_child_socketbuf(sock,host,port);
    }

  //We have no match, so we create a new outbound. NOTE: this means if the same
  //connection was made more than once, the socket is not duplicated
  if (!returnval)
    {
      //Create the socket
      fd=socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
      if (fd<1)
	//No socket, no way to procede
	return 0;

      //Create the socketbuf around the fd
      returnval=socket_create(fd);
      
      //Set the udp_sa so we have an identifier for the other end
      memset(&returnval->udp_sa,0,sizeof(struct sockaddr_in));
      
      //Set the destination
      returnval->udp_sa.sin_family=AF_INET;
      returnval->udp_sa.sin_port=htons(port);
      returnval->udp_sa.sin_addr.s_addr=sa->sin_addr.s_addr;

      //Set the 2 way UDP stuff
      returnval->protocol=SOCKET_UDP;
      returnval->udp2w=1;
      returnval->udp2w_averound=2500000;
      returnval->udp2w_lastmsg=time(NULL);
      strcpy(returnval->udp2w_unique,unique);
      returnval->udp2w_uniquelen=(int)strlen(returnval->udp2w_unique);

      returnval->mode=sock->mode;

      //Record the hostname too
      returnval->host=(char *)malloc(strlen(host)+1);
      strcpy(returnval->host,host);
      
      returnval->port=port;
      
      //Set non-blocking, so we can check for a data without freezing
      
#ifdef FIONBIO
      dummy=1;
      
      if (ioctl(fd,FIONBIO,&dummy)<0)
	{
	  close(fd);
	  return 0;
	}
#else
#  ifdef O_NONBLOCK
      flags=fcntl(fd,F_GETFL,0);
      
      if (flags<0)
	{
	  close(fd);
	  return 0;
	}
      
      if (fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)
	{
	  close(fd);
	  return 0;
	}
      
# else
#  error No valid non-blocking method - cannot build;
  // next is end of O_NONBLOCK
# endif
  // next is end of FIONBIO
#endif
      

      //Set the flags to connected
      returnval->flags |= (SOCKET_CONNECTED|SOCKET_INCOMING);

      //Here we now need to bind the socket to a port so that
      // a) it has a source address
      // b) the socket can be used to send AND receive
      memset(&bindsa,0,sizeof(struct sockaddr_in));

      gethostname(hostname,HOST_NAME_MAX);

      //Simply gethostbyname which handles all kinds of addresses
      hp=gethostbyname(hostname);

      if (!hp)
	//We couldnt resolve the host fail
	return 0;
      
      lingerval.l_onoff=0;
      lingerval.l_linger=0;
      setsockopt(fd,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
		 sizeof(struct linger));

      bindsa.sin_family=hp->h_addrtype;

      //Loop through the sockets, using the global socket reply port, so
      //that we dont end up looping through hundreds of binds if we are
      //working a busy server

      while (!returnval->sendingport)
	{
	  inport=udp_replyport++;
	  if (udp_replyport>65500)
	    udp_replyport=20000;

	  bindsa.sin_port = htons(inport);
	  
	  //Bind to the port
	  if (bind(fd,(struct sockaddr *)&bindsa,sizeof(bindsa))==0)
	    {
	      returnval->sendingport=inport;
	    }
	}
      
      returnval->parent=sock;

      //Link this in to the new children list as it needs to be acknowledged
      //by the calling program
      if (sock->new_children)
	{
	  returnval->new_child_next=sock->new_children;
	  returnval->new_child_prev=returnval->new_child_next->new_child_prev;
	  returnval->new_child_next->new_child_prev=returnval;
	  returnval->new_child_prev->new_child_next=returnval;
	}
      else
	{
	  returnval->new_child_next=returnval;
	  returnval->new_child_prev=returnval;
	  sock->new_children=returnval;
	}

      returnval->connect_time=time(NULL);
    }


  //HERE if we are working on a TURN connection, we simply note this, the
  //socket_sendto will handle sending to the right location
  if (using_turn)
    returnval->use_turn=1;

  //What we do here depends entirely on whether the server is NATTED or not.
  //If it is, and we can use STUN, we STUN ourselves a new socket

  if (sock->stun_nat_type > SOCKET_NAT_TYPE_NEEDS_CLIENT_STUN &&
      returnval->stun_nat_type==SOCKET_NAT_TYPE_UNKNOWN)
    {
      socket_inet_udp2way_listener_stun(returnval,sock->stun_host,
					sock->stun_port);
    }
  else
    {
      //Send the reply to acknowledge the connection
      socket_udp2way_connectmessage_reply(returnval);
      
      //Now we ALSO send a reply via the outgoing connection socket, as that 
      //one has been connected to by the other end. This will mean that 
      //clients behind NAT or firewall that is not full cone have a chance of 
      //connecting 
      socket_udp2way_connectmessage_listener_reply(sock,returnval);
    }
  
  return returnval;
}

//This function handles all incoming data sent to a listener socket
//from a client.
int socket_udp2way_listener_data_process(socketbuf *sock,
					 struct sockaddr_in *sa,
					 socklen_t sa_len,
					 signed char *buf,int datalen)
{
  socket_intchar len,val;
  int type,uniquelen;
  socketbuf *target;
  char unique[HOST_NAME_MAX+60+1];
  
  //There must always be at least 4 bytes, that is a protocol header
  if (datalen<4)
    return 0;

  memcpy(val.c,buf,4);
  type=ntohl(val.i);

  //We have the protocol

  if (type==SOCKET_UDP2W_PROTOCOL_CONNECTION)
    {
#ifdef UDP_PROTOCOL_DEBUG
      printf("Listener received SOCKET_UDP2W_PROTOCOL_CONNECTION\n");
#endif
      //New connection messages need 8 bytes minimum
      //4 Bytes : Protocol
      //4 Bytes : Length of the unique identifier
      //        : Unique identifier

      if (datalen<8)
	return 0;

      //Now get the unique connection ID that we have
      memcpy(len.c,buf+4,4);
      uniquelen=ntohl(len.i);
      memcpy(unique,buf+8,uniquelen);
      unique[uniquelen]=0;

      //Now call the create connection function to handle this message
      socket_udp2way_listener_create_connection(sock,sa,sa_len,
						ntohs(sa->sin_port),
						unique,0);
      
      return 1;
    }

  if (type==SOCKET_UDP2W_PROTOCOL_LISTENER_RELAY)
    {
      if (datalen<9)
	return 0;
      
      memcpy(len.c,buf+4,4);
      target=socket_get_child_socketbuf_by_sendport(sock,ntohl(len.i));
      
      if (target)
	{
	  target->udp2w_relay_by_listener=1;

          target->udp2w_lastmsg=time(NULL);

	  return socket_udp2way_reader_data_process(target,
						    sa,sa_len,
						    buf+8,datalen-8);
	}
      
      return 0;
    }

  if (type > SOCKET_UDP2W_STUN_PROTOCOL_MIN && 
      type < SOCKET_UDP2W_STUN_PROTOCOL_MAX)
    {
      socket_udp2way_reader_stun_process(sock,sa,sa_len,buf,datalen,type);
      
      return 1;
    }

  if (type > SOCKET_UDP2W_TURN_PROTOCOL_MIN && 
      type < SOCKET_UDP2W_TURN_PROTOCOL_MAX)
    {
      socket_udp2way_reader_turn_process(sock,sa,sa_len,buf,datalen,type);
      
      return 1;
    }

  return 1;
}

//This function acknowledges the sending of a reliable data packet. This will
//tell the sender that the packet has been accepted and can now be dropped.
//If the sender does not receive this by the time the packet resend comes
//around, the packet will be resent.
static int socket_acknowledge_reader_udp_rpacket(socketbuf *sock,int packetnumber,int subpacketnumber,int split_index)
{
  int written;
  socket_intchar intval;
  char buf[16];

  //Now we construct new data to send

  //4 bytes: Protocol
  //4 bytes: Packet number
  //4 bytes: Packet subnumber (optional)
  //4 bytes: Packet split index (optional)

  intval.i=htonl(SOCKET_UDP2W_PROTOCOL_RCONFIRM);
  memcpy(buf,intval.c,4);

  intval.i=htonl(packetnumber);
  memcpy(buf+4,intval.c,4);

  if (subpacketnumber>-1)
    {
      intval.i=htonl(subpacketnumber);
      memcpy(buf+8,intval.c,4);
      intval.i=htonl(split_index);
      memcpy(buf+12,intval.c,4);
    }

  //Send to the socket
  written=socket_sendto(sock,sock->fd,
			buf,subpacketnumber==-1?8:16,
			MSG_DONTWAIT,
			(struct sockaddr *)&sock->udp_sa,
			sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
          //If the send fails, the socket dies
	  sock->flags |= SOCKET_DEAD;
          return 0;
        }
    }

  return written;
}

static void process_rpacket_backlog(socketbuf *sock)
{
  socket_udp_rdata *oldpacket;
  socket_intchar len;

  //Check the next accepted packet is not on the received list
  oldpacket=socket_rdata_locate_packetnum(sock->udp2w_rdata_in,
					  sock->udp2w_rinpacket);
  while (oldpacket && !oldpacket->ranges_size)
    {
      if (!oldpacket->sent)
	{
#ifdef PACKET_DEBUG
	  printf("Processing backlogged packet %d\n",sock->udp2w_rinpacket);
#endif

	  //We are sequential, so this hasnt been sent yet
	  len.i=(SOCKET_INT_TYPE)oldpacket->length;
	  dynstringRawappend(sock->indata,len.c,4);
	  dynstringRawappend(sock->indata,oldpacket->data,
			     oldpacket->length);
	}
	    
      //Now its 'in the past' delete it
      sock->udp2w_rdata_in=socket_rdata_delete(sock->udp2w_rdata_in,
					       oldpacket);
	    
      //Incriment the packet number
      sock->udp2w_rinpacket++;
      
      //try the next!
      oldpacket=socket_rdata_locate_packetnum(sock->udp2w_rdata_in,
					      sock->udp2w_rinpacket);
    }

  return;
}

//This is VERY similar to the listener reading, except as the data can ONLY
//come from the other end of THIS socket (we are the client) then we dont
//need the portnumber. We can be at either end of the socket for this
//to be the execution path
int socket_udp2way_reader_data_process(socketbuf *sock,
				       struct sockaddr_in *sa,
				       socklen_t sa_len,
				       signed char *buf,int datalen)
{
  socket_intchar len,val;
  int type,loopa;
  socket_udp_rdata *packet;
  int packetnumber,subpacketnumber,split_index=0;
  struct timeval time_now;
  char uniquebuf[HOST_NAME_MAX+120+1+8];
  char outbuf[HOST_NAME_MAX+120+1+8];
  int uniquelen,written;

  //There must always be at least 4 bytes, that is a protocol header
  if (datalen<4)
    return 0;

  memcpy(val.c,buf,4);
  type=ntohl(val.i);

  //We have the protocol
  
  switch (type)
    {
    case SOCKET_UDP2W_PROTOCOL_CONNECTION_REPLY:
      {
#ifdef UDP_PROTOCOL_DEBUG
	printf("Socket received SOCKET_UDP2W_PROTOCOL_CONNECTION_REPLY\n");
#endif
      
	//The server has acknowledged our connection, we now need to connect back
	//to the server. If we can, and if we get a response, THEN we are
	//connected
	
	//The server is responding from a new port, this is also the port we
	//should send the response messages to. As we have received directly
	//from the child port on the other side, we should always send from
	//this one. A response from the server MAY be on the wrong port,
	//as it doesnt know about NAT. Full cone NAT will mean that this is
	//correct and the server is wrong
	sock->udp_sa.sin_port=sa->sin_port;
	sock->udp_sa.sin_addr.s_addr=sa->sin_addr.s_addr;
	sock->udp2w_directport++;
	sock->udp2w_connectcounter+=2;
	
	//Directly write to the socket, a response including out unique ID
	
	//Now we construct new data to send
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
#ifdef UDP_PROTOCOL_DEBUG
	printf("Sending SOCKET_UDP2W_PROTOCOL_CONNECTION_ACKNOWLEDGE\n");
#endif
	val.i=htonl(SOCKET_UDP2W_PROTOCOL_CONNECTION_ACKNOWLEDGE);
	memcpy(outbuf,val.c,4);
	
	uniquelen=sock->udp2w_uniquelen;
	len.i=htonl(uniquelen);
	memcpy(outbuf+4,len.c,4);
	
	memcpy(outbuf+8,sock->udp2w_unique,uniquelen);
	
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      outbuf,8+uniquelen,
			      MSG_DONTWAIT,
			      (struct sockaddr *)&sock->udp_sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the connection over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_CONNECTION_FROMLISTENER_REPLY:
      {
#ifdef UDP_PROTOCOL_DEBUG
	printf("Socket received SOCKET_UDP2W_PROTOCOL_CONNECTION_FROMLISTENER_REPLY\n");
#endif
	//The server has acknowledged our connection, we now need to connect back
	//to the server. If we can, and if we get a response, THEN we are
	//connected

	sock->udp2w_connectcounter+=2;

	//This connection is direct from the listener at the other end. It
	//contains the portnumber to connect to. Decode this.
	if (sock->udp2w_directport>0)
	  {
	    //We have already had a connection directly from the socket itself,
	    //so we can ignore this.
	    return 1;
	  }

	//If we have tried to connect for a long enough time, we just start
	//relaying to the main socket which we CAN reach
	sock->udp2w_fromserver_counter++;
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	if (sock->udp2w_fromserver_counter>20 && 
	    !sock->udp2w_relaying_via_connector)
	  {
	    sock->udp2w_relaying_via_connector=1;
	  }
	
	memcpy(val.c,buf+4,4);	
	sock->port=ntohl(val.i);

	sock->udp_sa.sin_port=htons(sock->port);
	
	//Directly write to the socket, a response including out unique ID
	
	//Now we construct new data to send
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
#ifdef UDP_PROTOCOL_DEBUG
	printf("Sending SOCKET_UDP2W_PROTOCOL_CONNECTION_ACKNOWLEDGE\n");
#endif
	val.i=htonl(SOCKET_UDP2W_PROTOCOL_CONNECTION_ACKNOWLEDGE);
	memcpy(outbuf,val.c,4);
	
	uniquelen=sock->udp2w_uniquelen;
	len.i=htonl(uniquelen);
	memcpy(outbuf+4,len.c,4);
	
	memcpy(outbuf+8,sock->udp2w_unique,uniquelen);
	
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      outbuf,8+uniquelen,
			      MSG_DONTWAIT,
			      (struct sockaddr *)&sock->udp_sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the connection over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_CONNECTION_ACKNOWLEDGE:
      {
#ifdef UDP_PROTOCOL_DEBUG
	printf("Socket received SOCKET_UDP2W_PROTOCOL_CONNECTION_ACKNOWLEDGE\n");
#endif
	//This is only ever received by the server end. It is part of the
	//connection negotiation. When the server received this, it knows it
	//can communicate with the client. This may also change the port as
	//the client may be behind a half-cone NAT and have changed its
	//portnumber to connect to a different port HERE.
	
	//We need to check we are receiving from the correct port first before
	//we change port
	
	sock->udp2w_connectcounter+=2;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	if (strcmp(uniquebuf,sock->udp2w_unique))
	  {
	    //The unique value is different, abort
	    return 0;
	  }
	
	//It is correct, now set the port
	sock->udp_sa.sin_port=sa->sin_port;
	
	
	//Now send the last response back and the handshake is complete
#ifdef UDP_PROTOCOL_DEBUG
	printf("Sending SOCKET_UDP2W_PROTOCOL_OK_CONNECTION_ACKNOWLEDGE\n");
#endif
	val.i=htonl(SOCKET_UDP2W_PROTOCOL_OK_CONNECTION_ACKNOWLEDGE);
	memcpy(outbuf,val.c,4);
	
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      outbuf,4,
			      MSG_DONTWAIT,
			      (struct sockaddr *)&sock->udp_sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the connection over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_OK_CONNECTION_ACKNOWLEDGE:
      {
#ifdef UDP_PROTOCOL_DEBUG
	printf("Socket received SOCKET_UDP2W_PROTOCOL_OK_CONNECTION_ACKNOWLEDGE\n");
	printf("CONNECTED\n");
#endif
	//The server and client can talk directly, we are connected
	sock->flags&=~SOCKET_CONNECTING;
	sock->flags|=SOCKET_CONNECTED;
	sock->udp2w_connectcounter=0;
	
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_DATA:
      {
	//This is user data, it is NOT reliable so we just take it and use
	//it
	
	//Add it to the users data buffer
	len.i=datalen-4;
	dynstringRawappend(sock->indata,len.c,4);
	dynstringRawappend(sock->indata,(char *)buf+4,datalen-4);
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_RDATA:
      {

	//This is a RELIABLE data packet and requires handling specially
	
	// 4 bytes : protocol
	// 4 bytes : packet number
	//         : data
	
	//Comes with a packet number
	memcpy(val.c,buf+4,4);
	packetnumber=ntohl(val.i);
	
	//The packet number is important. The packets may need to be
	//stored in sequence. It may also be a packet we have had before,
	//as the acknowledgement does not always make it back.
	
	//We have in the socketbuf the next packet number we are expecting,
	//all packets earlier than this have been processed and forgotten
	
#ifdef PACKET_DEBUG
	printf("Received packet %d\n",packetnumber);
#endif
	
	if (packetnumber==sock->udp2w_rinpacket)
	  {
	    //Its the correct next packet - we can just send it to the buffer
	    
#ifdef PACKET_DEBUG
	    printf("Received packet %d as expected\n",packetnumber);
#endif
	    
	    sock->udp2w_rinpacket++;
	    
	    len.i=datalen-8;
	    dynstringRawappend(sock->indata,len.c,4);
	    dynstringRawappend(sock->indata,(char *)buf+8,datalen-8);
	  }
	else if (packetnumber<sock->udp2w_rinpacket)
	  {
#ifdef PACKET_DEBUG
	    printf("Old packet %d, discarding\n",packetnumber);
#endif
	    //We've already got this one, do nothing
	  }
	else if (socket_rdata_locate_packetnum(sock->udp2w_rdata_in,
					       packetnumber))
	  {
	    //This is one we already have in the queue - do nothing
	  }
	else
	  {
	    //This is one we dont have yet, and we also dont have its
	    //predecessor,
	    //There are 2 ways to handle this:
	    // 1) Sequential mode:
	    //      We add it onto a queue and wait for the previous ones
	    // 2) Non-sequential mode:
	    //      We deal with it now, but add it to the list anyway, so
	    //      we know its been dealt with.
	    
#ifdef PACKET_DEBUG
	    printf("Received an OOS packet %d - ",packetnumber);
#endif

	    if (!(sock->mode & SOCKET_MODE_UDP2W_SEQUENTIAL))
	      {
		//We store the packet, we note that it HAS been sent, so we
		//can switch between sequential and non-sequential modes
		//without losing track of the packets we've already processed
		sock->udp2w_rdata_in=rdata_allocate(sock->udp2w_rdata_in,
						    packetnumber,
						    (char *)(buf+8),
						    datalen-8,1);
		

		//We arent sequential, so we just send it to the out buffer
		len.i=datalen-8;
		dynstringRawappend(sock->indata,len.c,4);
		dynstringRawappend(sock->indata,(char *)buf+8,datalen-8);
#ifdef PACKET_DEBUG
		printf("Processing anyway\n");
#endif
	      }
	    else
	      {
		//We are sequential, so all we do is add it to the list for
		//later handling
		sock->udp2w_rdata_in=rdata_allocate(sock->udp2w_rdata_in,
						    packetnumber,
						    (char *)(buf+8),
						    datalen-8,0);
#ifdef PACKET_DEBUG
		printf("Holding for later\n");
#endif
	      }
	  }
	
	//we may have now got a series of packets we can send, or at least
	//get rid of. So, we test this.
	process_rpacket_backlog(sock);

	//acknowledge the packet we have just received
	socket_acknowledge_reader_udp_rpacket(sock,packetnumber,-1,0);
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_RCONFIRM:
      {
	//This is the confirmation of a packet we sent in reliable mode
	
	// 4 bytes : protocol
	// 4 bytes : packet number
	// 4 bytes : Optional subpacketnumber
	// 4 bytes : Optional split index

	//Comes with a packet number
	memcpy(val.c,buf+4,4);
	packetnumber=ntohl(val.i);

	if (datalen==16)
	  {
	    memcpy(val.c,buf+8,4);
	    subpacketnumber=ntohl(val.i);

	    memcpy(val.c,buf+12,4);
	    split_index=ntohl(val.i);
	  }
	else
	  {
	    subpacketnumber=-1;
	    split_index=0;
	  }

	//Locate this packet in the list of packets we are remembering to
	//resend
	packet=socket_rdata_locate_packetnum(sock->udp2w_rdata_out,
					     packetnumber);
	if (packet)
	  {
	    if (packet->ranges_size==0)
	      {
		//Record the receipt of this packet, we KNOW we can send this
		//sized packet now
		if (packet->length-8 >0 && 
		    packet->length-8 > sock->udp2w_minsend)
		  {
		    sock->udp2w_minsend=packet->length-8;
		  }

		//rebalance the timings, so we know better when to resend,
		//but not on partial packets where its going to be pointless
		sock->udp2w_averound=(long long)(sock->udp2w_averound*0.9);
		
		gettimeofday(&time_now,NULL);
		
		sock->udp2w_averound+=
		  ((time_now.tv_sec-packet->sendtime.tv_sec)*1000000);
		sock->udp2w_averound+=(time_now.tv_usec-packet->sendtime.tv_usec);
		//We've not already been told of the receipt, so delete it
		sock->udp2w_rdata_out=socket_rdata_delete(sock->udp2w_rdata_out,
							  packet);
	      }
	    else
	      {
		//This is a partial packet, we delete the partial part, and
		//then if it is all received, we delete the whole thing
		if (packet->split_index==split_index && 
		    packet->range_received[subpacketnumber]==0)
		  {
		    packet->range_received[subpacketnumber]=(char *)1;
		    packet->ranges_left--;

		    //Reset the resend count as we have received something new
		    packet->resend_count=0;
		    packet->received_this_send++;
		    
		    //see if this is the longest we have ever received
		    if (subpacketnumber==packet->ranges_size-1)
		      {
			if (packet->length-packet->range_starts[subpacketnumber]-16 > sock->udp2w_minsend)
			  {
			    sock->udp2w_minsend=(packet->length-packet->range_starts[subpacketnumber])-16;
			  }
		      }
		    else
		      {
			if (packet->range_starts[subpacketnumber+1]-packet->range_starts[subpacketnumber]-16 > sock->udp2w_minsend)
			  {
			    sock->udp2w_minsend=packet->range_starts[subpacketnumber+1]-packet->range_starts[subpacketnumber]-16;
			  }
		      }
		    
		    if (packet->ranges_left==0)
		      {
			//Thats it, all done
			sock->udp2w_rdata_out=socket_rdata_delete(sock->udp2w_rdata_out,
								  packet);
		      }
		  }
	      }
	    

	  }
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA:
    case SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA_FINAL:
      {
	//We have a partial packet, find the packet to add it to, or make a
	//new one if we need to
	//This is a RELIABLE data packet and requires handling specially
	
	// 4 bytes : protocol
	// 4 bytes : packet number
	// 4 bytes : subpacket number
	// 4 bytes : Split Index
	//         : data
	
	//Comes with a packet number
	memcpy(val.c,buf+4,4);
	packetnumber=ntohl(val.i);

	memcpy(val.c,buf+8,4);
	subpacketnumber=ntohl(val.i);
	
	memcpy(val.c,buf+12,4);
	split_index=ntohl(val.i);

#ifdef PACKET_DEBUG
	printf("Receiving split packet %d.%d.%d\n",packetnumber,
	       subpacketnumber,split_index);
#endif

	//The packet number is important. The packets may need to be
	//stored in sequence. It may also be a packet we have had before,
	//as the acknowledgement does not always make it back.
	
	//We have in the socketbuf the next packet number we are expecting,
	//all packets earlier than this have been processed and forgotten
	
	
	if (packetnumber<sock->udp2w_rinpacket)
	  {
#ifdef PACKET_DEBUG
	    printf("Old packet %d.%d.%d\n",packetnumber,
		   subpacketnumber,split_index);
#endif
	    //We've already got this one and finished with it, do nothing
	  }
	else
	  {
	    //Find the packet we are working on if there is one
	    packet=socket_rdata_locate_packetnum(sock->udp2w_rdata_in,
						 packetnumber);
	    if (!packet)
	      {
#ifdef PACKET_DEBUG
		printf("New packet %d.%d.%d\n",packetnumber,
		       subpacketnumber,split_index);
#endif
		
		sock->udp2w_rdata_in=rdata_allocate(sock->udp2w_rdata_in,
						    packetnumber,
						    (char *)(buf+16),
						    datalen-16,0);
		packet=socket_rdata_locate_packetnum(sock->udp2w_rdata_in,
						     packetnumber);
		//We need to cheat a little here and blank the buffer we just
		//got so it can be used properly
		free(packet->data);
		packet->data=NULL;
		packet->length=0;
	      }

	    if (packet->length)
	      {
#ifdef PACKET_DEBUG
		printf("Packet %d.%d.%d is already complete\n",packetnumber,
		       subpacketnumber,split_index);
#endif
		//This is a finished packet, send ack and finish
		socket_acknowledge_reader_udp_rpacket(sock,packetnumber,
						      subpacketnumber,
						      split_index);
		
		return 1;
	      }
	    
	    //Check if this is a reset packet, if it is, drop this
	    //particular split
	    if (packet->split_index > split_index)
	      {
#ifdef PACKET_DEBUG
		printf("Packet %d.%d.%d is an old split index, dropping\n",
		       packetnumber,subpacketnumber,split_index);
#endif

		//We dont even acknowledge this one, just dump it
		return 1;
	      }

	    //If this is a NEW packet, we reset it all
	    if (packet->split_index < split_index)
	      {
#ifdef PACKET_DEBUG
		printf("Packet %d.%d.%d is a new split index, resetting\n",
		       packetnumber,
		       subpacketnumber,split_index);
#endif

		if (packet->range_received)
		  {
		    for (loopa=0;loopa < packet->ranges_size;loopa++)
		      {
			if (packet->range_received[loopa])
			  free(packet->range_received[loopa]);
		      }
		    free(packet->range_received);
		    packet->range_received=0;
		  }

		free(packet->data);
		packet->data=NULL;
		packet->length=0;
		packet->ranges_left=0;
		packet->ranges_size=0;
		packet->found_last_range=0;
		packet->split_index = split_index;
	      }

	    //Now we have a packet, add data into the buffer
	    if ((subpacketnumber+1) > packet->ranges_size)
	      {
		char **new_ranges;

#ifdef PACKET_DEBUG
		printf("Packet %d.%d.%d expands size\n",packetnumber,
		       subpacketnumber,split_index);
#endif

		packet->ranges_left+=(subpacketnumber+1)-packet->ranges_size;
		
		if (type==SOCKET_UDP2W_PROTOCOL_PARTIAL_DATA_FINAL)
		  {
		    packet->found_last_range=1;
		  }

		new_ranges=(char **)calloc(1,(subpacketnumber+1)*sizeof(char *));
		
		if (packet->range_received)
		  {
		    memcpy(new_ranges,packet->range_received,packet->ranges_size*sizeof(char *));
		    free(packet->range_received);
		  }
		packet->range_received=new_ranges;
		
		packet->ranges_size=subpacketnumber+1;
	      }

	    if (!packet->range_received[subpacketnumber])
	      {
#ifdef PACKET_DEBUG
		printf("Packet %d.%d.%d is new\n",packetnumber,
		       subpacketnumber,split_index);
#endif

		packet->ranges_left--;

		packet->range_received[subpacketnumber]=(char *)malloc(datalen-12);
		val.i=datalen-16;
		memcpy(packet->range_received[subpacketnumber],val.c,4);
		memcpy(packet->range_received[subpacketnumber]+4,buf+16,datalen-16);

		//Now test if we have the whole packet
		if (packet->ranges_left>0 || packet->found_last_range==0)
		  {
		    //We dont have the whole packet, we're done
		  }
		else
		  {
		    //We have the whole packet, process the buffer
		    int totallen;
		    totallen=0;
		    
#ifdef PACKET_DEBUG
		    printf("Split packet %d.%d.%d finishes the packet\n",packetnumber,
			   subpacketnumber,split_index);
#endif

		    for (loopa=0;loopa < packet->ranges_size;loopa++)
		      {
			memcpy(val.c,packet->range_received[loopa],4);
			totallen+=val.i;
		      }
		    
		    packet->length=0;
		    packet->data=(char *)malloc(totallen);

		    //Compress all the small buffers into one big one
		    for (loopa=0;loopa < packet->ranges_size;loopa++)
		      {
			memcpy(val.c,packet->range_received[loopa],4);
			
			memcpy(packet->data+packet->length,
			       packet->range_received[loopa]+4,val.i);
			
			packet->length+=val.i;
			
			free(packet->range_received[loopa]);
		      }
		    free(packet->range_received);
		    packet->range_received=NULL;
		    packet->ranges_left=0;
		    packet->ranges_size=0;
		    
		    //Now we have the packet looking normal, if we process the
		    //packet backlog, this will sort itself out
		    process_rpacket_backlog(sock);
		  }
	      }
	  }

	//acknowledge the packet we have just received
	socket_acknowledge_reader_udp_rpacket(sock,packetnumber,
					      subpacketnumber,
					      split_index);
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_PROTOCOL_PING:
      {
	//This has already done its job by making something happen on the link
	
	return 1;
      }
    }

  //Only process STUN if we are enabled as a STUN server, otherwise people
  //could just use other peoples random game servers as STUN servers.
  if (type > SOCKET_UDP2W_STUN_PROTOCOL_MIN && 
      type < SOCKET_UDP2W_STUN_PROTOCOL_MAX)
    {
      socket_udp2way_reader_stun_process(sock,sa,sa_len,buf,datalen,type);
      
      return 1;
    }

  if (type > SOCKET_UDP2W_TURN_PROTOCOL_MIN && 
      type < SOCKET_UDP2W_TURN_PROTOCOL_MAX)
    {
      socket_udp2way_reader_turn_process(sock,sa,sa_len,buf,datalen,type);
      
      return 1;
    }

  return 1;
}

/****************************************************************************
 **                Extention for STUN                                      **
 ** This is NOT accurate to the RFC, you need to run this codes            **
 ** STUN server for this to work                                           **
 ****************************************************************************/

int socket_udp2way_stun_start(socketbuf *sock)
{
  int written;
  size_t datalen;
  socket_intchar intval;
  char buf[HOST_NAME_MAX+5+120+1+8];

  //Now we construct new data to send
  //Data is as follows:

  //4 bytes: Protocol
  //4 bytes: The length of the unique identifier string
  //       : The unique identifier string
  //

  intval.i=htonl(SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC);
  memcpy(buf,intval.c,4);

  datalen=strlen(sock->stun_unique);
  intval.i=htonl((long)datalen);
  memcpy(buf+4,intval.c,4);

  memcpy(buf+8,sock->stun_unique,datalen);

  //Now we send this to the STUN server

  //Send the data to the socket
  written=socket_sendto(sock,sock->fd,
		 buf,8+datalen,
		 MSG_DONTWAIT,
		 (struct sockaddr *)&sock->stun_sa,
		 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //If the error is not EAGAIN, no STUN for us
#ifdef STUN_DEBUG
	  printf("STUN: Client type set to unknown (1) on error %d\n",grapple_errno());
#endif
	  sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
          return -1;
        }
    }

  if (sock->stun_last_msg < SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC)
    {
      sock->stun_last_msg=SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC;
      sock->stun_starttime=time(NULL);
    }

  //Incriment the connection counter. This is not a 'counter', this just
  //incriments each time a message about STUN is received, and then
  //decriments each time we think about re-trying the STUN. This way,
  //we reduce the number of resends, as we dont need to resend if we have
  //just received a packet further down the chain
  sock->stun_connectcounter+=2;

  //Return the number of bytes sent
  return written;
}

int socket_udp2way_stun_start_stage1(socketbuf *sock)
{
  int written;
  size_t datalen;
  socket_intchar intval;
  char buf[HOST_NAME_MAX+5+120+1+8];

  //Now we construct new data to send
  //Data is as follows:

  //4 bytes: Protocol
  //4 bytes: The length of the unique identifier string
  //       : The unique identifier string
  //

  if (sock->stun2_host==NULL)
    {
      intval.i=htonl(SOCKET_UDP2W_STUN_REQUEST_ALT_SERVER_ADDRESS);
      memcpy(buf,intval.c,4);

      if (sock->stun_last_msg < SOCKET_UDP2W_STUN_REQUEST_ALT_SERVER_ADDRESS)
	{
	  sock->stun_last_msg=SOCKET_UDP2W_STUN_REQUEST_ALT_SERVER_ADDRESS;
          sock->stun_starttime=time(NULL);
	}

      datalen=strlen(sock->stun_unique);
      intval.i=htonl((long)datalen);
      memcpy(buf+4,intval.c,4);

      memcpy(buf+8,sock->stun_unique,datalen);

      datalen+=8;


      //Now we send this to the STUN server

      //Send the data to the socket
      written=socket_sendto(sock,sock->fd,
		     buf,datalen,
		     MSG_DONTWAIT,
		     (struct sockaddr *)&sock->stun_sa,
		     sizeof(struct sockaddr_in));

    }
  else
    {
      intval.i=htonl(SOCKET_UDP2W_STUN_REQUEST_ADDRESS_SECOND_BASIC);
      memcpy(buf,intval.c,4);

      if (sock->stun_last_msg < SOCKET_UDP2W_STUN_REQUEST_ADDRESS_SECOND_BASIC)
	{
	  sock->stun_last_msg=SOCKET_UDP2W_STUN_REQUEST_ADDRESS_SECOND_BASIC;
          sock->stun_starttime=time(NULL);
	}

      datalen=strlen(sock->stun_unique);
      intval.i=htonl((long)datalen);
      memcpy(buf+4,intval.c,4);

      memcpy(buf+8,sock->stun_unique,datalen);

      datalen+=8;

      //Now we send this to the STUN server

      //Send the data to the socket
      written=socket_sendto(sock,sock->fd,
		     buf,datalen,
		     MSG_DONTWAIT,
		     (struct sockaddr *)&sock->stun2_sa,
		     sizeof(struct sockaddr_in));
    }

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //If the error is not EAGAIN, no STUN for us
#ifdef STUN_DEBUG
	  printf("STUN: Client type set to unknown (3)\n");
#endif
	  sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
          return -1;
        }
    }

  //Incriment the connection counter. This is not a 'counter', this just
  //incriments each time a message about STUN is received, and then
  //decriments each time we think about re-trying the STUN. This way,
  //we reduce the number of resends, as we dont need to resend if we have
  //just received a packet further down the chain
  sock->stun_connectcounter+=2;

  //Return the number of bytes sent
  return written;
}

static int socket_udp2way_stun_secondserver_test(socketbuf *sock)
{
  int written;
  size_t datalen;
  socket_intchar intval;
  char buf[HOST_NAME_MAX+5+120+1+8];

  //Now we construct new data to send
  //Data is as follows:

  //4 bytes: Protocol
  //4 bytes: The length of the unique identifier string
  //       : The unique identifier string
  //

  intval.i=htonl(SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER);
  memcpy(buf,intval.c,4);

  datalen=strlen(sock->stun_unique);
  intval.i=htonl((long)datalen);
  memcpy(buf+4,intval.c,4);

  memcpy(buf+8,sock->stun_unique,datalen);

  //Now we send this to the STUN server
#ifdef STUN_DEBUG
  printf("STUN: Sending SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER\n");
#endif
  //Send the data to the socket
  written=socket_sendto(sock,sock->fd,
		 buf,8+datalen,
		 MSG_DONTWAIT,
		 (struct sockaddr *)&sock->stun_sa,
		 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //If the error is not EAGAIN, no STUN for us
#ifdef STUN_DEBUG
	  printf("STUN: Client type set to unknown (4)\n");
#endif
	  sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
          return -1;
        }
    }

  if (sock->stun_last_msg < SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER)
    {
      sock->stun_last_msg=SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER;
      sock->stun_starttime=time(NULL);
    }

  //Incriment the connection counter. This is not a 'counter', this just
  //incriments each time a message about STUN is received, and then
  //decriments each time we think about re-trying the STUN. This way,
  //we reduce the number of resends, as we dont need to resend if we have
  //just received a packet further down the chain
  sock->stun_connectcounter+=2;

  //Return the number of bytes sent
  return written;
}

static int socket_udp2way_stun_firewall_test(socketbuf *sock)
{
  int written;
  size_t datalen;
  socket_intchar intval;
  char buf[HOST_NAME_MAX+5+120+1+8];

  //Now we construct new data to send
  //Data is as follows:

  //4 bytes: Protocol
  //4 bytes: The length of the unique identifier string
  //       : The unique identifier string
  //

  intval.i=htonl(SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER);
  memcpy(buf,intval.c,4);

  datalen=strlen(sock->stun_unique);
  intval.i=htonl((long)datalen);
  memcpy(buf+4,intval.c,4);

  memcpy(buf+8,sock->stun_unique,datalen);

  //Now we send this to the STUN server

  //Send the data to the socket
  written=socket_sendto(sock,sock->fd,
		 buf,8+datalen,
		 MSG_DONTWAIT,
		 (struct sockaddr *)&sock->stun_sa,
		 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //If the error is not EAGAIN, no STUN for us
#ifdef STUN_DEBUG
	  printf("STUN: Client type set to unknown (5)\n");
#endif
	  sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
          return -1;
        }
    }

  if (sock->stun_last_msg < SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER)
    {
      sock->stun_last_msg=SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER;
      sock->stun_starttime=time(NULL);
    }

  //Incriment the connection counter. This is not a 'counter', this just
  //incriments each time a message about STUN is received, and then
  //decriments each time we think about re-trying the STUN. This way,
  //we reduce the number of resends, as we dont need to resend if we have
  //just received a packet further down the chain
  sock->stun_connectcounter+=2;

  //Return the number of bytes sent
  return written;
}

int socket_inet_udp2way_listener_stun_complete(socketbuf *sock)
{
  if (sock->stun_nat_type==SOCKET_NAT_TYPE_IN_PROCESS)
    return 0;
  else
    return 1;
}

int socket_inet_udp2way_listener_stun_type_get(socketbuf *sock)
{
  return sock->stun_nat_type;
}

int socket_inet_udp2way_listener_stun(socketbuf *sock,
				      const char *host,int port)
{
  struct in_addr inet_address;
  struct hostent *hp;
  struct timeval time_now;

#ifdef STUN_DEBUG
  printf("Stun startup\n");
#endif
  //Generate a sockaddr from this data
  //Lookup the hostname we are sending to
  hp=gethostbyname(host);
  if (!hp)
    inet_address.s_addr=-1;
  else
    memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));

  if (inet_address.s_addr==-1)
    {
#ifdef STUN_DEBUG
      printf("Stun server address resolution failed\n");
#endif

      //We couldnt resolve the address, no STUN for us
      return -1;
    }

  //Save the data for later use in the datastruct
  sock->stun_sa.sin_family=AF_INET;
  sock->stun_sa.sin_port=htons(port);
  sock->stun_sa.sin_addr.s_addr=inet_address.s_addr;

  //Register the stun server address
  if (host!=sock->stun_host)
    {
      if (sock->stun_host)
	free(sock->stun_host);
      sock->stun_host=(char *)malloc(strlen(host)+1);
      strcpy(sock->stun_host,host);
    }
  sock->stun_port=port;

  //We now know where the STUN server is and our next step is to send to it

  gettimeofday(&time_now,NULL);

  //Generate a unique identifier for this STUN request
  sprintf(sock->stun_unique,"STUN-%s-%d-%ld.%ld",sock->host,sock->port,
	  time_now.tv_sec,time_now.tv_usec);

  sock->stun_starttime=time_now.tv_sec;
  
  sock->stun_nat_type=SOCKET_NAT_TYPE_IN_PROCESS;

  //Now we send the STUN request
  return socket_udp2way_stun_start(sock);

  //We are done, STUN will progress in each call to the socket processing
  //routine now, until it is done or it times out
}

//This function is purely for the use of a STUN server. It identifies where
//the second server and port is. If this has not been run, then the
//server will not act as a STUN server in regards to protocol received
int socket_inet_udp2way_listener_stun_enable(socketbuf *sock,
					     const char *host,int port,
					     int secondport)
{
  unsigned long int dummy;
  struct sockaddr_in bindsa;
  struct hostent *hp;
  struct in_addr inet_address;
  struct linger lingerval;
#ifndef FIONBIO
# ifdef O_NONBLOCK
  int flags;
# endif
#endif


  //Generate a sockaddr from this data
  //Lookup the second stun server hostname
  hp=gethostbyname(host);
  if (!hp)
    inet_address.s_addr=-1;
  else
    memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));

  if (inet_address.s_addr==-1)
    {
      //We couldnt resolve the address, no STUN for us
      return -1;
    }

  //Save the data for later use in the datastruct
  sock->stun2_sa.sin_family=AF_INET;
  sock->stun2_sa.sin_port=htons(port);
  sock->stun2_sa.sin_addr.s_addr=inet_address.s_addr;


  //Create an outgoing socket ready to send second port STUN requests

  //Create the socket
  sock->stun_fd2=socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
  if (sock->stun_fd2<1)
    {
      sock->stun_fd2=0;
      //No socket, no way to procede
      return 0;
    }

  //Set non-blocking, so we can check for a data without freezing
      
#ifdef FIONBIO
  dummy=1;
      
  if (ioctl(sock->stun_fd2,FIONBIO,&dummy)<0)
    {
      close(sock->stun_fd2);
      sock->stun_fd2=0;
      return 0;
    }
#else
#  ifdef O_NONBLOCK
  flags=fcntl(sock->stun_fd2,F_GETFL,0);
  
  if (flags<0)
    {
      close(sock->stun_fd2);
      sock->stun_fd2=0;
      return 0;
    }
  
  if (fcntl(sock->stun_fd2,F_SETFL,flags|O_NONBLOCK)<0)
    {
      close(sock->stun_fd2);
      sock->stun_fd2=0;
      return 0;
    }
  
# else
#  error No valid non-blocking method - cannot build;
  // next is end of O_NONBLOCK
# endif
  // next is end of FIONBIO
#endif
  
  //Here we now need to bind the socket to a port
  memset(&bindsa,0,sizeof(struct sockaddr_in));

  lingerval.l_onoff=0;
  lingerval.l_linger=0;
  setsockopt(sock->stun_fd2,SOL_SOCKET,SO_LINGER,(char *)&lingerval,
	     sizeof(struct linger));

  bindsa.sin_family=hp->h_addrtype;

  //Loop through the sockets, using the global socket reply port, so
  //that we dont end up looping through hundreds of binds if we are
  //working a busy server

  bindsa.sin_port = htons(secondport);
	  
  //Bind to the port
  if (bind(sock->stun_fd2,(struct sockaddr *)&bindsa,sizeof(bindsa))!=0)
    {
      close(sock->stun_fd2);
      sock->stun_fd2=0;
      return 0;
    }
      
  //Register the stun server address
  if (sock->stun2_host)
    free(sock->stun2_host);

  sock->stun2_host=(char *)malloc(HOST_NAME_MAX+1);

  inet_ntop(AF_INET,(void *)(&sock->stun2_sa.sin_addr),
	    sock->stun2_host,HOST_NAME_MAX);
  sock->stun2_port=port;
  sock->stun_port2=secondport;

  //Set us a value identifying us as a server
  sock->stun_keepalive=-1;
  sock->stunserver=1;

  return 1;
  //We are done, STUN will progress in each call to the socket processing
  //routine now, until it is done or it times out
}

//This function will enable TURN on a STUN server. This is a separate
//initialisation as TURN relays all data via itself and is an expensive
//system
int socket_inet_udp2way_listener_turn_enable(socketbuf *sock)
{
  //Can only enable TURN if we are a STUN server
  if (sock->stunserver)
    sock->turn_enabled=1;

  return 1;
}

int socket_udp2way_reader_stun_process(socketbuf *sock,
				       struct sockaddr_in *sa,
				       socklen_t sa_len,
				       signed char *buf,int datalen,
				       int protocol)
{
  socket_intchar len,val;
  char uniquebuf[HOST_NAME_MAX+120+1+8];
  char outbuf[HOST_NAME_MAX+HOST_NAME_MAX+4+120+1+8+HOST_NAME_MAX+8];
  int uniquelen,written;
  char hostname[HOST_NAME_MAX+1];
  int hostnamelen;
  int offset,port;
  struct in_addr inet_address;
  struct hostent *hp;


  //We have a STUN message to handle on this socket. This socket could be
  //anything, a listener, a reader, anything that can have STUN

  switch (protocol)
    {
    case SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC:
    case SOCKET_UDP2W_STUN_REQUEST_ADDRESS_SECOND_BASIC:
      {
	//This is a message that should only be received by the STUN server.
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
#ifdef STUN_DEBUG
	if (protocol==SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC)
	  printf("STUN: Received SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC\n");
	else
	  printf("STUN: Received SOCKET_UDP2W_STUN_REQUEST_ADDRESS_SECOND_BASIC\n");
#endif
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Send the last response back with the address we connected from
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	
	if (protocol==SOCKET_UDP2W_STUN_REQUEST_ADDRESS_BASIC)
	  {
	    val.i=htonl(SOCKET_UDP2W_STUN_REPLY_ADDRESS_BASIC);
	  }
	else if (protocol==SOCKET_UDP2W_STUN_REQUEST_ADDRESS_SECOND_BASIC)
	  {
	    val.i=htonl(SOCKET_UDP2W_STUN_REPLY_ADDRESS_SECOND_BASIC);
	  }
	memcpy(outbuf,val.c,4);
	
	len.i=htonl(uniquelen);
	memcpy(outbuf+4,len.c,4);
	
	memcpy(outbuf+8,uniquebuf,uniquelen);
	offset=uniquelen+8;
	
	//Find their IP address
	inet_ntop(AF_INET,(void *)(&sa->sin_addr),hostname,HOST_NAME_MAX);
	hostname[HOST_NAME_MAX]=0;
	hostnamelen=(int)strlen(hostname);
	
	len.i=htonl(hostnamelen);
	memcpy(outbuf+offset,len.c,4);
	offset+=4;
	
	memcpy(outbuf+offset,hostname,hostnamelen);
	offset+=hostnamelen;
	
	port=(int)ntohs(sa->sin_port);
	val.i=htonl(port);
	memcpy(outbuf+offset,val.c,4);
	offset+=4;
	
#ifdef STUN_DEBUG
	printf("STUN: Server replied address request at %s %d\n",hostname,port);
#endif
	
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      outbuf,offset,
			      MSG_DONTWAIT,
			      (struct sockaddr *)sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the STUN over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_STUN_REPLY_ADDRESS_BASIC:
      {
	//We have been sent an address from the STUN server. See if it
	//matches our current address
	const char **interfaces;
	int ifcount;
	struct sockaddr_in resolve_sa;
	
#ifdef STUN_DEBUG
	  printf("STUN: Received SOCKET_UDP2W_STUN_REPLY_ADDRESS_BASIC\n");
#endif
	//Only accept this on stage 0
	if (sock->stun_stage>0)
	  return 1;
	
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;

	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Now check that this data is meant for us
	if (strcmp(uniquebuf,sock->stun_unique))
	  {
	    //It isnt ours, finish here
	    return 0;
	  }
	
	offset=uniquelen+8;
	
	//How get the hostname
	if (datalen<offset+4)
	  return 0;
	
	memcpy(len.c,buf+offset,4);
	
	hostnamelen=ntohl(len.i);
	offset+=4;
	
	if (datalen < offset+hostnamelen)
	  return 0;
	
	if (hostnamelen > HOST_NAME_MAX)
	  return 0;
	
	memcpy(hostname,buf+offset,hostnamelen);
	hostname[hostnamelen]=0;
	
	offset+=hostnamelen;
	
	if (datalen < offset+4)
	  return 0;
	
	memcpy(val.c,buf+offset,4);
	
	port=ntohl(val.i);
	offset+=4;
	
#ifdef STUN_DEBUG
	printf("STUN: Client received address response %s %d\n",hostname,port);
#endif
	
	//That is all the incoming data
	
	//If we ARENT a listener, finish here, as all we need to do for a
	//client socket is find our outfacing socket
	if (!(sock->flags & SOCKET_LISTENER))
	  {
#ifdef STUN_DEBUG
	    printf("STUN: Client type outward socket address discovered. Done.\n");
#endif
	    sock->stun_nat_type=SOCKET_NAT_TYPE_NONE;
	    
	    //Now start the connection sequence
	    
	    //Send the reply to acknowledge the connection
	    socket_udp2way_connectmessage_reply(sock);
	    
	    //Now we ALSO send a reply via the outgoing connection socket, as that 
	    //one has been connected to by the other end. This will mean that 
	    //clients behind NAT or firewall that is not full cone have a chance of 
	    //connecting 
	    if (sock->parent)
	      socket_udp2way_connectmessage_listener_reply(sock->parent,sock);
	    
	    return 1;
	  }
	
	sock->stun_connectcounter+=2;
	
	//How we see if the address is the same as we thought it was 
	sock->published_address=(char *)malloc(hostnamelen+1);
	strcpy(sock->published_address,hostname);
	
	sock->published_port=port;
	
	if (port==sock->port)
	  {
	    //Port is OK, now check the hostname (which is passed in as an IP)
	    
	    if (sock->host && *sock->host && !strcmp(sock->host,
						     sock->published_address))
	      {
		//Hostname is OK too. We are behind no NAT.
		
		//Now check if we are behind a firewall
#ifdef STUN_DEBUG
		printf("STUN: Client requesting firewall test\n");
#endif
		
		return socket_udp2way_stun_firewall_test(sock);
	      }
	    
	    //Check if we need to resolve the hostname to an IP
	    hp=gethostbyname(sock->host);
	    if (!hp)
	      inet_address.s_addr=-1;
	    else
	      memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));
	    
	    if (inet_address.s_addr!=-1)
	      {
		//Resolved. Now check if its a match
		resolve_sa.sin_addr.s_addr=inet_address.s_addr;
		
		inet_ntop(AF_INET,(void *)(&resolve_sa.sin_addr),
			  hostname,HOST_NAME_MAX);
		
		if (*hostname && !strcmp(hostname,sock->published_address))
		  {
		    //Hostname is OK too. We are behind no NAT.
		    
		    //Now check if we are behind a firewall
#ifdef STUN_DEBUG
		    printf("STUN: Client requesting firewall test (2)\n");
#endif
		    return socket_udp2way_stun_firewall_test(sock);
		  }
	      }
	    
	    
	    //The host isnt a match, but we may have just bound to all
	    //ports, so now test to see if we have a match on an IP
	    //bound to this machine
	    interfaces=socket_get_interface_list();
	    
	    if (interfaces)
	      {
		ifcount=0;
		while (interfaces[ifcount])
		  {
#ifdef STUN_DEBUG
		    printf("Testing locally discovered address %s\n",interfaces[ifcount]);
#endif
		    if (!strcmp(interfaces[ifcount],sock->published_address))
		      {
			//Its a local interface
			
			//Now check if we are behind a firewall
#ifdef STUN_DEBUG
			printf("STUN: Client requesting firewall test (3)\n");
#endif
			return socket_udp2way_stun_firewall_test(sock);
		      }
		    
		    ifcount++;
		  }
	      }
	  }
	
#ifdef STUN_DEBUG
	printf("STUN: Client requesting second server validation\n");
#endif
	return socket_udp2way_stun_secondserver_test(sock);
      }
      break;
      
    case SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER:
    case SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER:
      {

#ifdef STUN_DEBUG
	if (protocol==SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER)
	  printf("STUN: Received SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER\n");
	else
	  printf("STUN: Received SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER\n");	  
#endif

	//This is a message that should only be received by the STUN server.
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Send the data back via server 2. 
	
	//Data is as follows:              
	//4 bytes: Relay protocol
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	// ** Relayed data below here **
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	val.i=htonl(SOCKET_UDP2W_STUN_INT_SEND_ADDRESS_REPLY);
	memcpy(outbuf,val.c,4);
	
	//Find their IP address
	inet_ntop(AF_INET,(void *)(&sa->sin_addr),hostname,HOST_NAME_MAX);
	hostname[HOST_NAME_MAX]=0;
	hostnamelen=(int)strlen(hostname);
	
	len.i=htonl(hostnamelen);
	memcpy(outbuf+4,len.c,4);
	
	memcpy(outbuf+8,hostname,hostnamelen);
	offset=8+hostnamelen;
	
	//no need to hton it, its already in network order in this section
	port=(int)(ntohs(sa->sin_port));
	val.i=htonl(port);
	memcpy(outbuf+offset,val.c,4);
	offset+=4;
	
#ifdef STUN_DEBUG
	printf("STUN: Server requesting Alt Address\n");
#endif
	
	//Now for the protocol to send back
	if (protocol==SOCKET_UDP2W_STUN_REQUEST_FW_ADDRESS_FROM_ALT_SERVER)
	  {
	    val.i=htonl(SOCKET_UDP2W_STUN_REPLY_FW_ADDRESS_FROM_ALT_SERVER);
	  }
	else if (protocol==SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_SERVER)
	  {
	    val.i=htonl(SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_SERVER);
	  }
	else
	  val.i=htonl(0);
	
	memcpy(outbuf+offset,val.c,4);
	offset+=4;
	
	len.i=htonl(uniquelen);
	memcpy(outbuf+offset,len.c,4);
	offset+=4;
	
	memcpy(outbuf+offset,uniquebuf,uniquelen);
	offset+=uniquelen;
	
	//Find their IP address
	len.i=htonl(hostnamelen);
	memcpy(outbuf+offset,len.c,4);
	offset+=4;
	
	memcpy(outbuf+offset,hostname,hostnamelen);
	offset+=hostnamelen;
	
	//no need to hton it, its already in network order in this section
	port=(int)(ntohs(sa->sin_port));
	val.i=htonl(port);
	memcpy(outbuf+offset,val.c,4);
	offset+=4;
	
#ifdef STUN_DEBUG
	printf("STUN: Server replies alt server address is %s %d\n",hostname,port);
#endif
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      outbuf,offset,
			      MSG_DONTWAIT,
			      (struct sockaddr *)&sock->stun2_sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the STUN over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;
    case SOCKET_UDP2W_STUN_INT_SEND_ADDRESS_REPLY:
      {
	struct sockaddr_in send_sa;
	char sourcehostname[HOST_NAME_MAX+1];
	//This is a relay request from a different STUN server
	
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_INT_SEND_ADDRESS_REPLY\n");
#endif

	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	//       : Remainder is the relayable data
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	hostnamelen=(int)ntohl(len.i);
	
	if (datalen < hostnamelen+8)
	  return 0;
	
	if (hostnamelen > HOST_NAME_MAX)
	  return 0;
	
	memcpy(hostname,buf+8,hostnamelen);
	hostname[hostnamelen]=0;
	
	offset=hostnamelen+8;
	
	if (datalen<offset+4)
	  return 0;
	
	memcpy(val.c,buf+offset,4);
	port=htonl(val.i);
	offset+=4;
	
#ifdef STUN_DEBUG
	printf("STUN: Second Server Address Relay Reply %s %d\n",hostname,port);
#endif
	//Check that the data comes from the other server, otherwise it is just
	//an open relay
	inet_ntop(AF_INET,(void *)(&sa->sin_addr),sourcehostname,HOST_NAME_MAX);
	if (strcmp(sourcehostname,sock->stun2_host))
	  {
	    //It didnt come from the other server, don't relay
	    return 0;
	  }
	
	//Now make an sa to send to
	memset(&send_sa,0,sizeof(struct sockaddr_in));
	send_sa.sin_family=AF_INET;
	send_sa.sin_port=htons(port);
	//We know that the address is in dots, now make it an inet addr
	inet_pton(AF_INET,hostname,(void *)(&send_sa.sin_addr));
	
	//We can now send the remaining data
	written=socket_sendto(sock,sock->fd,
			      (const void *)(buf+offset),datalen-offset,
			      MSG_DONTWAIT,
			      (struct sockaddr *)&send_sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the STUN over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_STUN_REPLY_FW_ADDRESS_FROM_ALT_SERVER:
      {
	//We have been sent a firewall reply from the STUN server.

#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_REPLY_FW_ADDRESS_FROM_ALT_SERVER\n");
#endif
	
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//Only accept this on stage 0
	if (sock->stun_stage>0)
	  return 1;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	//Get the data now
	if (datalen<8)
	  return 0;
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Now check that this data is meant for us
	if (strcmp(uniquebuf,sock->stun_unique))
	  {
	    //It isnt ours, finish here
	    return 0;
	  }
	
	//It is ours, we dont need to parse any more, we know we now have open
	//internet
	sock->stun_nat_type=SOCKET_NAT_TYPE_NONE;
#ifdef STUN_DEBUG
	printf("STUN: Client type set to direct internet\n");
#endif
	return 1;
      }
      break;
      
    case SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_SERVER:
      {
	//We have been sent an address reply from the second STUN server.
	
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_SERVER\n");
#endif
	
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//Only accept this on stage 0
	if (sock->stun_stage>0)
	  return 1;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	//Get the data now
	if (datalen<8)
	  return 0;
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Now check that this data is meant for us
	if (strcmp(uniquebuf,sock->stun_unique))
	  {
	    //It isnt ours, finish here
	    return 0;
	  }
	
	//It is ours, we dont need to parse any more, we know the address already
	
	//As we have a reply, this means that the NAT is full cone
#ifdef STUN_DEBUG
	printf("STUN: Client type set to full cone\n");
#endif
	sock->stun_nat_type=SOCKET_NAT_TYPE_FULL_CONE;
	sock->stun_keepalive=time(NULL)+10;
	
	//End of STUN here
	return 1;
      }
      break;

    case SOCKET_UDP2W_STUN_REQUEST_ALT_SERVER_ADDRESS:
      {
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_REQUEST_ALT_SERVER_ADDRESS\n");
#endif
	
	//This is a message that should only be received by the STUN server.
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	//If we dont have host2 we cant broadcast it
	if (!sock->stun2_host)
	  return 1;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Send the last response back with the address for the other server
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	
	val.i=htonl(SOCKET_UDP2W_STUN_REPLY_ALT_SERVER_ADDRESS);
	memcpy(outbuf,val.c,4);
	
	len.i=htonl(uniquelen);
	memcpy(outbuf+4,len.c,4);
	
	memcpy(outbuf+8,uniquebuf,uniquelen);
	offset=uniquelen+8;
	
	//Find their IP address
	hostnamelen=(int)strlen(sock->stun2_host);
	
	len.i=htonl(hostnamelen);
	memcpy(outbuf+offset,len.c,4);
	offset+=4;
	
	memcpy(outbuf+offset,sock->stun2_host,hostnamelen);
	offset+=hostnamelen;
	
	val.i=htonl(sock->stun2_port);
	memcpy(outbuf+offset,val.c,4);
	offset+=4;
	
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      outbuf,offset,
			      MSG_DONTWAIT,
			      (struct sockaddr *)sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the STUN over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_STUN_REPLY_ALT_SERVER_ADDRESS:
      {
	//We have been sent an address from the STUN server. Set it
	//as our second server address
	
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_REPLY_ALT_SERVER_ADDRESS\n");
#endif
	
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Now check that this data is meant for us
	if (strcmp(uniquebuf,sock->stun_unique))
	  {
	    //It isnt ours, finish here
	    return 0;
	  }
	
	if (!sock->stun2_host)
	  {
	    offset=uniquelen+8;
	    
	    //How get the hostname
	    if (datalen<offset+4)
	      return 0;
	    
	    memcpy(len.c,buf+offset,4);
	    
	    hostnamelen=ntohl(len.i);
	    offset+=4;
	    
	    if (datalen < offset+hostnamelen)
	      return 0;
	    
	    if (hostnamelen > HOST_NAME_MAX)
	      return 0;
	    
	    memcpy(hostname,buf+offset,hostnamelen);
	    hostname[hostnamelen]=0;
	    
	    offset+=hostnamelen;
	    
	    if (datalen < offset+4)
	      return 0;
	    
	    memcpy(val.c,buf+offset,4);
	    
	    port=ntohl(val.i);
	    offset+=4;
	    
	    //That is all the incoming data
	    
	    //Set the values into the data struct
	    
	    sock->stun2_port=port;
	    sock->stun2_host=(char *)malloc(hostnamelen+1);
	    strcpy(sock->stun2_host,hostname);
	    
	    //Generate the sa for the second host
	    
	    //Lookup the hostname we are sending to
	    hp=gethostbyname(hostname);
	    if (!hp)
	      inet_address.s_addr=-1;
	    else
	      memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));
	    
	    if (inet_address.s_addr==-1)
	      {
		//We couldnt resolve the address, no STUN for us
#ifdef STUN_DEBUG
		printf("STUN: Client type set to unknown (6)\n");
#endif
		sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
		return -1;
	      }
	    
	    //Save the data for later use in the datastruct 
	    sock->stun2_sa.sin_family=AF_INET;
	    sock->stun2_sa.sin_port=htons(port);
	    sock->stun2_sa.sin_addr.s_addr=inet_address.s_addr;
	  }
	
	//At this stage, send the next step which is contained in
	return socket_udp2way_stun_start_stage1(sock);
      }
      break;

    case SOCKET_UDP2W_STUN_REPLY_ADDRESS_SECOND_BASIC:
      {
	//We have been sent an address from the STUN server. See if it
	//matches our current address
	
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_REPLY_ADDRESS_SECOND_BASIC\n");
#endif
	
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	//4 bytes: The length of the hostname
	//       : The hostname
	//4 bytes: The port number
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Now check that this data is meant for us
	if (strcmp(uniquebuf,sock->stun_unique))
	  {
	    //It isnt ours, finish here
	    return 0;
	  }
	
	offset=uniquelen+8;
	
	//How get the hostname
	if (datalen<offset+4)
	  return 0;
	
	memcpy(len.c,buf+offset,4);
	
	hostnamelen=ntohl(len.i);
	offset+=4;
	
	if (datalen < offset+hostnamelen)
	  return 0;
	
	if (hostnamelen > HOST_NAME_MAX)
	  return 0;

	memcpy(hostname,buf+offset,hostnamelen);
	hostname[hostnamelen]=0;
	
	offset+=hostnamelen;
	
	if (datalen < offset+4)
	  return 0;
	
	memcpy(val.c,buf+offset,4);
	
	port=ntohl(val.i);
	offset+=4;
	
	//That is all the incoming data
	
	sock->stun_connectcounter+=2;
	
	//How we see if the address is the same as we had before
	if (!sock->published_address)
	  {
	    //We didnt have a previous published address. This should be
	    //impossible. If we are here, bail out of STUN
#ifdef STUN_DEBUG
	    printf("STUN: Client type set to unknown - impossible point\n");
#endif
	    sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
	    return 1;
	  }
	
	if (port!=sock->published_port ||
	    strcmp(hostname,sock->published_address))
	  {
	    //We have a different address. This indicates that we have a
	    //symmatric NAT
	    
#ifdef STUN_DEBUG
	    printf("STUN: Client type set to symmatric\n");
#endif
	    sock->stun_nat_type=SOCKET_NAT_TYPE_SYMMETRIC;
	    sock->stun_keepalive=time(NULL)+10;
	    return 1;
	  }
	
	//We got a reply of the same address, which means we have half-cone NAT.
	
	//We need to know whether it is port restricted or host restricted,
	//either is fine but we find out for completeness.
	
	//We find out by requesting an address from the same host but from a
	//different portnumber.
	
	//Now we construct new data to send
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	val.i=htonl(SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_PORT);
	memcpy(outbuf,val.c,4);
	
	uniquelen=(int)strlen(sock->stun_unique);
	len.i=htonl(uniquelen);
	memcpy(outbuf+4,len.c,4);
	
	memcpy(outbuf+8,sock->stun_unique,uniquelen);
	
	//Now we send this to the *second* STUN server
	
	//Send the data to the socket
	written=socket_sendto(sock,sock->fd,
			      outbuf,8+uniquelen,
			      MSG_DONTWAIT,
			      (struct sockaddr *)&sock->stun2_sa,
			      sizeof(struct sockaddr_in));
	
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, no STUN for us
#ifdef STUN_DEBUG
		printf("STUN: Client type set to unknown (7), send error\n");
#endif
		sock->stun_nat_type=SOCKET_NAT_TYPE_UNKNOWN;
		return -1;
	      }
	  }
	
	if (sock->stun_last_msg < SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_PORT)
	  {
	    sock->stun_last_msg=SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_PORT;
	    sock->stun_starttime=time(NULL);
	  }
	
	//Incriment the connection counter. This is not a 'counter', this just
	//incriments each time a message about STUN is received, and then
	//decriments each time we think about re-trying the STUN. This way,
	//we reduce the number of resends, as we dont need to resend if we have
	//just received a packet further down the chain
	sock->stun_connectcounter+=2;
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_PORT:
      {
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_REQUEST_ADDRESS_FROM_ALT_PORT\n");
#endif
	
	//This is a message that should only be received by the STUN server.
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	//If we dont have port2 we cant broadcast it
	if (!sock->stun_port2)
	  return 1;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	//Get the data now
	if (datalen<8)
	  return 0;
	
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Send the last response back with the ack, do not need more info than
	//just the ack
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	
	val.i=htonl(SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_PORT);
	memcpy(outbuf,val.c,4);
	
	len.i=htonl(uniquelen);
	memcpy(outbuf+4,len.c,4);
	
	memcpy(outbuf+8,uniquebuf,uniquelen);
	
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      outbuf,uniquelen+8,
			      MSG_DONTWAIT,
			      (struct sockaddr *)sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the STUN over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }
	
	return 1;
      }
      break;

      //Finally, the last STUN stage
    case SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_PORT:
      {
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_REPLY_ADDRESS_FROM_ALT_PORT\n");
#endif
	
	//We have been sent an ack from the server
	
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: The length of the unique identifier string  
	//       : The unique identifier string                
	
	//Get the data now
	if (datalen<8)
	  return 0;
	memcpy(len.c,buf+4,4);
	
	uniquelen=ntohl(len.i);
	
	if (datalen < uniquelen+8)
	  return 0;
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	//Now check that this data is meant for us
	if (strcmp(uniquebuf,sock->stun_unique))
	  {
	    //It isnt ours, finish here
	    return 0;
	  }
	
	//Set the type of NAT to be half cone host restricted
#ifdef STUN_DEBUG
	printf("STUN: Client type set to restricted cone\n");
#endif
	sock->stun_nat_type=SOCKET_NAT_TYPE_RESTRICTED_CONE;
	sock->stun_keepalive=time(NULL)+10;
	
	return 1;
      }
      
    case SOCKET_UDP2W_STUN_KEEPALIVE:
      {
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_KEEPALIVE\n");
#endif
	
	//Keepalives are only responded to by the server, the client
	//sends them.
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	if (sock->stun_keepalive!=-1)
	  //This is a client, STUN servers always have keepalive of -1
	  return 1;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	
	val.i=htonl(SOCKET_UDP2W_STUN_KEEPALIVE);
	
	//Send the data to the socket                                    
	socket_sendto(sock,sock->fd,
		      val.c,4,
		      MSG_DONTWAIT,
		      (struct sockaddr *)sa,
		      sizeof(struct sockaddr_in));
	
	//Dont check the result, we dont care if it worked, we just try
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_STUN_CONNECTBACK:
      {
	struct sockaddr_in send_sa;
	char sourcehostname[HOST_NAME_MAX+1];
	//This is a request from a client to tell the server to connect to them
	
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_CONNECTBACK\n");
#endif
	
	//This is only received by a stun server
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	//4 bytes: Unique identifier length
	//       : Unique identifier
	//4 bytes: Hostname length
	//       : Hostname
	//4 bytes: Port Number
	
	memcpy(val.c,buf+4,4);
	uniquelen=ntohl(val.i);
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	offset=uniquelen+8;
	
	memcpy(val.c,buf+offset,4);
	hostnamelen=ntohl(val.i);
	offset+=4;
	
	if (hostnamelen > HOST_NAME_MAX)
	  return 0;
	
	
	memcpy(hostname,buf+offset,hostnamelen);
	hostname[hostnamelen]=0;
	
	offset+=hostnamelen;
	
	memcpy(val.c,buf+offset,4);
	port=ntohl(val.i);
	offset+=4;
	
	
	//Make an sa out of the address we have been asked to get a relay from
	hp=gethostbyname(hostname);
	if (!hp)
	  inet_address.s_addr=-1;
	else
	  memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));
	
	
	if (inet_address.s_addr==-1)
	  {
	    //We couldnt resolve the address, so ignore
	    return 0;
	  }
	
	
	memset(&send_sa,0,sizeof(struct sockaddr_in));
	send_sa.sin_family=AF_INET;
	send_sa.sin_port=htons(port);
	send_sa.sin_addr.s_addr=inet_address.s_addr;
	
	//Compile the outdata
	val.i=htonl(SOCKET_UDP2W_STUN_CONNECT_REQUEST);
	memcpy(buf,val.c,4);
	
	val.i=htonl(uniquelen);
	memcpy(buf+4,val.c,4);
	
	memcpy(buf+8,uniquebuf,uniquelen);
	
	offset=uniquelen+8;
	
	//Now get the hostname we sent from, send this as the target for 
	//the relay connect
	inet_ntop(AF_INET,(void *)(&sa->sin_addr),sourcehostname,HOST_NAME_MAX);
	sourcehostname[HOST_NAME_MAX]=0;
	
	hostnamelen=(int)strlen(sourcehostname);
	
	val.i=htonl(hostnamelen);
	memcpy(buf+offset,val.c,4);
	
	offset+=4;
	memcpy(buf+offset,sourcehostname,hostnamelen);
	
	offset+=hostnamelen;
	
	port=ntohs(sa->sin_port);
	val.i=htonl(port);
	memcpy(buf+offset,val.c,4);
	offset+=4;
	
	//Send the data to the socket                                    
	socket_sendto(sock,sock->fd,
		      buf,offset,
		      MSG_DONTWAIT,
		      (struct sockaddr *)&send_sa,
		      sizeof(struct sockaddr_in));
	
	//Dont check the result, we dont care if it worked, we just try
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_STUN_CONNECT_REQUEST:
      {
	struct sockaddr_in send_sa;
	
#ifdef STUN_DEBUG
	printf("STUN: Received SOCKET_UDP2W_STUN_CONNECT_REQUEST\n");
#endif
	
	//Request from the stun server to connect to a remote host
	
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//treat this exactly like an initial connect request directly
	memcpy(val.c,buf+4,4);
	uniquelen=ntohl(val.i);
	
	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;
	
	memcpy(uniquebuf,buf+8,uniquelen);
	uniquebuf[uniquelen]=0;
	
	offset=uniquelen+8;
	
	memcpy(val.c,buf+offset,4);
	hostnamelen=ntohl(val.i);
	offset+=4;
	
	if (hostnamelen > HOST_NAME_MAX)
	  return 0;
	
	
	memcpy(hostname,buf+offset,hostnamelen);
	hostname[hostnamelen]=0;
	
	offset+=hostnamelen;
	
	memcpy(val.c,buf+offset,4);
	port=ntohl(val.i);
	offset+=4;
	
	//Now we know where, try and connect there
	
	//Make an sa out of the host details we have
	hp=gethostbyname(hostname);
	if (!hp)
	  inet_address.s_addr=-1;
	else
	  memcpy((char *)&inet_address,hp->h_addr_list[0],sizeof(struct in_addr));
	
	
	if (inet_address.s_addr==-1)
	  {
	    //We couldnt resolve the address, so ignore
	    return 0;
	  }
	
	
	memset(&send_sa,0,sizeof(struct sockaddr_in));
	send_sa.sin_family=AF_INET;
	send_sa.sin_port=htons(port);
	send_sa.sin_addr.s_addr=inet_address.s_addr;
	
	socket_udp2way_listener_create_connection(sock,&send_sa,sizeof(send_sa),
						  ntohs(send_sa.sin_port),
						  uniquebuf,0);     
      }
      break;
    }

  return 1;
}

int socket_udp2way_stun_ping(socketbuf *sock)
{
  socket_intchar val;
  val.i=htonl(SOCKET_UDP2W_STUN_KEEPALIVE);

  //Send the data to the socket                                    
  socket_sendto(sock,sock->fd,
	 val.c,4,
	 MSG_DONTWAIT,
	 (struct sockaddr *)&sock->stun_sa,
	 sizeof(struct sockaddr_in));
  
  //Dont check the result, we dont care if it worked, we just try
  sock->stun_keepalive+=10;

  return 1;
}

int socket_client_request_connect_via_stun(socketbuf *sock)
{
  int written;
  int datalen;
  socket_intchar intval;
  char buf[HOST_NAME_MAX+HOST_NAME_MAX+2+120+1+8];
  int offset;

  //short tmpport;

  //Now we construct new data to send
  //Data is as follows:

  //4 bytes: Protocol
  //4 bytes: The length of the unique identifier string
  //       : The unique identifier string
  //4 bytes: The length of the servers hostname
  //       : The servers hostname
  //4 bytes: The servers portnumber


#ifdef UDP_PROTOCOL_DEBUG
  printf("Sending SOCKET_UDP2W_STUN_CONNECTBACK\n");
#endif
  intval.i=htonl(SOCKET_UDP2W_STUN_CONNECTBACK);
  memcpy(buf,intval.c,4);

  datalen=sock->udp2w_uniquelen;
  intval.i=htonl(datalen);
  memcpy(buf+4,intval.c,4);

  memcpy(buf+8,sock->udp2w_unique,datalen);

  offset=8+datalen;

  datalen=(int)strlen(sock->host);
  intval.i=htonl(datalen);
  memcpy(buf+offset,intval.c,4);
  offset+=4;

  memcpy(buf+offset,sock->host,datalen);
  offset+=datalen;

  intval.i=htonl(sock->port);
  memcpy(buf+offset,intval.c,4);
  offset+=4;


  //Now we have to make sure we are sending to the correct port. The port can
  //be changed in handshake stage 2, and so we must be sure to only send to
  //the original port. If not, the UDP packet may be lost in stage 2 and stage
  //1 (this one) may just keep sending connect packets to the wrong place,
  //causing connection to hang and fail.

  //Send the data to the socket
  written=socket_sendto(sock,sock->fd,
		 buf,offset,
		 MSG_DONTWAIT,
		 (struct sockaddr *)&sock->stun_sa,
		 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //If the error is not EAGAIN, its dead
	  sock->flags |= SOCKET_DEAD;
          return 0;
        }
    }


  //Incriment the stun counter. This is not a 'counter', this just
  //incriments each time a message about connection is received, and then
  //decriments each time we think about re-trying the connect. This way,
  //we reduce the number of resends, as we dont need to resend if we have
  //just received a packet further down the chain
  sock->stun_reconnectcounter=2;

  //Return the number of bytes sent
  return written;
}

int socket_client_request_connect_via_turn(socketbuf *sock)
{
  int written;
  int datalen;
  socket_intchar intval;
  char buf[HOST_NAME_MAX+HOST_NAME_MAX+2+120+1+8];
  int offset;

  //short tmpport;

  //Now we construct new data to send
  //Data is as follows:

  //4 bytes: Protocol
  //4 bytes: The length of the unique identifier string
  //       : The unique identifier string
  //4 bytes: The length of the servers hostname
  //       : The servers hostname
  //4 bytes: The servers portnumber


#ifdef UDP_PROTOCOL_DEBUG
  printf("Sending SOCKET_UDP2W_TURN_DO\n");
#endif
  intval.i=htonl(SOCKET_UDP2W_TURN_DO);
  memcpy(buf,intval.c,4);

  datalen=sock->udp2w_uniquelen;
  intval.i=htonl(datalen);
  memcpy(buf+4,intval.c,4);

  memcpy(buf+8,sock->udp2w_unique,datalen);

  offset=8+datalen;

  datalen=(int)strlen(sock->host);
  intval.i=htonl(datalen);
  memcpy(buf+offset,intval.c,4);
  offset+=4;

  memcpy(buf+offset,sock->host,datalen);
  offset+=datalen;

  intval.i=htonl(sock->port);
  memcpy(buf+offset,intval.c,4);
  offset+=4;


  //Now we have to make sure we are sending to the correct port. The port can
  //be changed in handshake stage 2, and so we must be sure to only send to
  //the original port. If not, the UDP packet may be lost in stage 2 and stage
  //1 (this one) may just keep sending connect packets to the wrong place,
  //causing connection to hang and fail.

  //Send the data to the socket
  written=socket_sendto(sock,sock->fd,
		 buf,offset,
		 MSG_DONTWAIT,
		 (struct sockaddr *)&sock->stun_sa,
		 sizeof(struct sockaddr_in));

  if (written==-1)
    {
      if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
        {
	  //If the error is not EAGAIN, its dead
	  sock->flags |= SOCKET_DEAD;
          return 0;
        }
    }


  //Incriment the stun counter. This is not a 'counter', this just
  //incriments each time a message about connection is received, and then
  //decriments each time we think about re-trying the connect. This way,
  //we reduce the number of resends, as we dont need to resend if we have
  //just received a packet further down the chain
  sock->turn_connectcounter=2;

  //Return the number of bytes sent
  return written;
}

int socket_udp2way_reader_turn_process(socketbuf *sock,
				       struct sockaddr_in *sa,
				       socklen_t sa_len,
				       signed char *buf,int datalen,
				       int protocol)
{
  socket_intchar val;
  int written,uniquelen;
  char uniquebuf[HOST_NAME_MAX+120+1+8];

  /*
  socket_intchar len;
  char outbuf[HOST_NAME_MAX+HOST_NAME_MAX+4+120+1+8+HOST_NAME_MAX+8];
  char hostname[HOST_NAME_MAX+1];
  int hostnamelen;
  int offset,port;
  struct in_addr inet_address;
  struct hostent *hp;
  */

  //We have a STUN message to handle on this socket. This socket could be
  //anything, a listener, a reader, anything that can have STUN

  switch (protocol)
    {
    case SOCKET_UDP2W_TURN_DO:
      {
#ifdef TURN_DEBUG
	printf("TURN: Server received TURN_DO\n");
#endif
	
	//This is a message that should only be received by the STUN server.
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	
	//Send the last response back with the address we connected from
	
	//Data is as follows:              
	//4 bytes: Protocol                
	
	if (sock->turn_enabled)
	  val.i=htonl(SOCKET_UDP2W_TURN_WILL);
	else
	  val.i=htonl(SOCKET_UDP2W_TURN_WONT);
	
	//Send the data to the socket                                    
	written=socket_sendto(sock,sock->fd,
			      val.c,4,
			      MSG_DONTWAIT,
			      (struct sockaddr *)sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable. The client keeps on starting
	//the TURN over and over again until it gets its response
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }

	return 1;
      }
      break;

    case SOCKET_UDP2W_TURN_WONT:
      {
#ifdef TURN_DEBUG
	printf("TURN: Server received TURN_WONT\n");
#endif

	//This is a message that should only be received by the STUN server.
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	
	//Data is as follows:              
	//4 bytes: Protocol                
	
	//Here we have been told that the server is not TURN enabled
	sock->turn_refused=1;
	
	return 1;
      }
      break;

    case SOCKET_UDP2W_TURN_WILL:
      {
#ifdef TURN_DEBUG
	printf("TURN: Server received TURN_WILL\n");
#endif
	
	//This is a message that should only be received by the STUN server.
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//Data is as follows:              
	//4 bytes: Protocol                
	
	//Here we have been told that the server is not TURN enabled
	sock->use_turn=1;
	
        //Reset the socket to use the same address it started with, as this
        //is needed for the TURN client
        sock->udp_sa.sin_port=sock->connect_sa.sin_port;
        sock->udp_sa.sin_addr.s_addr=sock->connect_sa.sin_addr.s_addr;

	return 1;
      }
      break;

    case SOCKET_UDP2W_TURN_RELAY:
      {
	struct sockaddr_in send_sa;
	union 
	{
	  short s;
	  char c[2];
	} shortval;

#ifdef TURN_DEBUG
	printf("TURN: Server received TURN_RELAY\n");
#endif
	
	//This is a message that should only be received by the STUN server.
	if (!sock->stunserver)
	  //We arent a stun enabled server, ignore the message
	  return 0;
	
	//Protocol is:
	//4 bytes: TURN protocol
	//4 bytes: target address sin_addr.s_addr in network order
	//2 bytes: target address sin_port in network order
	//4 bytes: Length of unique identifier
	//       : Unique identifier
	//       : Original Payload
	
	//Dont do it if we arent a turn enabled server
	if (!sock->turn_enabled)
	  return 0;
	
	//We should relay it. So, we create a new sa to send to, using the
	//data in the packet, then we send the packet modified to include the
	//sa data from the sending socket. This way the other end knows where
	//it came from.
	memset(&send_sa,0,sizeof(struct sockaddr_in));
        send_sa.sin_family=AF_INET;
	memcpy(val.c,buf+4,4);
	send_sa.sin_addr.s_addr=val.i;
	memcpy(shortval.c,buf+8,2);
	send_sa.sin_port=shortval.s;

	//Now overwrite old data
	val.i=htonl(SOCKET_UDP2W_TURN_RELAY_DATA);
	memcpy(buf,val.c,4);

	val.i=sa->sin_addr.s_addr;
	memcpy(buf+4,val.c,4);

	shortval.s=sa->sin_port;
	memcpy(buf+8,shortval.c,2);

	//varify that the data is in an appropriate format, stop just anyone
	//relaying anything they feel like
	memcpy(val.c,buf+10,4);
	uniquelen=ntohl(val.i);

	if (uniquelen < 10)
	  return 0;

	if (uniquelen > HOST_NAME_MAX+120+8)
	  return 0;

	//Also dont send empty packets
	if (datalen <= uniquelen+10)
	  return 0;

	//we're done with tests and we're done with rewriting, send the data
	written=socket_sendto(sock,sock->fd,
			      buf,datalen,
			      MSG_DONTWAIT,
			      (struct sockaddr *)&send_sa,
			      sizeof(struct sockaddr_in));
	
	//This does not need to be reliable, the underlying protocols make it
	//reliable or not as the need arises
	if (written==-1)
	  {
	    if (!GRAPPLE_SOCKET_ERRNO_IS_EAGAIN)
	      {
		//If the error is not EAGAIN, its dead       
		sock->flags |= SOCKET_DEAD;
		return 0;
	      }
	  }

	return 1;
      }
      break;
    case SOCKET_UDP2W_TURN_RELAY_DATA:
      {
	union 
	{
	  short s;
	  char c[2];
	} shortval;
	struct sockaddr_in send_sa;
	int offset,type;

#ifdef TURN_DEBUG
	printf("TURN: Server received TURN_RELAY_DATA\n");
#endif
	
	//This is a message that should only be received by applications
	if (sock->stunserver)
	  //We are a stun enabled server, ignore the message
	  return 0;
	
	//Protocol is:
	//4 bytes: TURN protocol
	//4 bytes: target address sin_addr.s_addr in network order
	//2 bytes: target address sin_port in network order
	//4 bytes: Length of unique identifier
	//       : Unique identifier
	//       : Original Payload
	
	if (sock->flags & SOCKET_LISTENER)
	  {
	    //We are a listener, the ONLY thing valid from a TURN server is a
	    //connection request

	    //Get the socket target from the data
	    memset(&send_sa,0,sizeof(struct sockaddr_in));
	    send_sa.sin_family=AF_INET;
	    memcpy(val.c,buf+4,4);
	    send_sa.sin_addr.s_addr=val.i;
	    memcpy(shortval.c,buf+8,2);
	    send_sa.sin_port=shortval.s;
	    
	    memcpy(val.c,buf+10,4);
	    uniquelen=ntohl(val.i);

	    offset=uniquelen+14;
	    
	    //Get the start of the payload
	    
	    //There must always be at least 4 bytes in the payload,
	    //that is a protocol header

	    if (datalen-offset<4)
	      return 0;

	    memcpy(val.c,buf+offset,4);
	    type=ntohl(val.i);

	    //We have the protocol

	    if (type==SOCKET_UDP2W_PROTOCOL_CONNECTION)
	      {
		//New connection messages need 8 bytes minimum
		//4 Bytes : Protocol
		//4 Bytes : Length of the unique identifier
		//        : Unique identifier

		if (datalen-offset<8)
		  return 0;

		//Now get the unique connection ID that we have
		memcpy(val.c,buf+4+offset,4);
		uniquelen=ntohl(val.i);
		memcpy(uniquebuf,buf+8+offset,uniquelen);
		uniquebuf[uniquelen]=0;
		
		//Now call the create connection function to handle this 
		//message
		socket_udp2way_listener_create_connection(sock,&send_sa,sa_len,
							  ntohs(send_sa.sin_port),
							  uniquebuf,1);
      
	      }

	    //Anything that isnt this part of the protocol just gets dumped,
	    //its not valid
	    return 1;
	  }
	else
	  {
	    //Here, we are a socket talking to something else, so we
	    //process the data header and pass the payload off to the
	    //appropriate handler

	    //If we arent supposed to be using TURN, dont.
	    if (!sock->use_turn)
	      {
		//Ignore this invalid request
		return 1;
	      }

	    //Get the socket target from the data
	    memset(&send_sa,0,sizeof(struct sockaddr_in));
	    send_sa.sin_family=AF_INET;
	    memcpy(val.c,buf+4,4);
	    send_sa.sin_addr.s_addr=val.i;
	    memcpy(shortval.c,buf+8,2);
	    send_sa.sin_port=shortval.s;
	    
	    memcpy(val.c,buf+10,4);
	    uniquelen=ntohl(val.i);

	    offset=uniquelen+14;
	    
	    memcpy(uniquebuf,buf+14,uniquelen);
	    uniquebuf[uniquelen]=0;

	    //Check the unique code is correct, if it isnt, drop the
	    //packet, as this is probably a forgery
	    if (strcmp(sock->udp2w_unique,uniquebuf))
	      return 1;

	    //Get the start of the payload
	    
	    //There must always be at least 4 bytes in the payload,
	    //that is a protocol header
	    if (datalen-offset<4)
	      return 0;

	    return socket_udp2way_reader_data_process(sock,
						      &send_sa,
						      sa_len,
						      (signed char *)(buf+offset),
						      datalen-offset);

	  }

	return 1;
      }
      break;
    }
      
 return 0;
}
