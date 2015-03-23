dnl Setup for autoconf
AC_INIT([libgrapple], [0.9.8])
AC_CONFIG_SRCDIR([src/grapple.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

dnl Set various version strings - taken gratefully from the GTk sources
# Making releases:
#   MICRO_VERSION += 1;
#   INTERFACE_AGE += 1;
#   BINARY_AGE += 1;
# if any functions have been added, set INTERFACE_AGE to 0.
# if backwards compatibility has been broken,
# set BINARY_AGE and INTERFACE_AGE to 0.
MAJOR_VERSION=0
MINOR_VERSION=9
MICRO_VERSION=8
INTERFACE_AGE=1
BINARY_AGE=6

dnl libtool versioning
LT_RELEASE=$MAJOR_VERSION.$MINOR_VERSION
LT_CURRENT=`expr $MICRO_VERSION - $INTERFACE_AGE`
LT_REVISION=$INTERFACE_AGE
LT_AGE=`expr $BINARY_AGE - $INTERFACE_AGE`
AC_SUBST([LT_RELEASE])
AC_SUBST([LT_CURRENT])
AC_SUBST([LT_REVISION])
AC_SUBST([LT_AGE])

dnl Setup for automake
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

dnl Check for compiler
AC_PROG_CC_C99
CFLAGS="$CFLAGS -fvisibility=hidden -Wall"

dnl Check for tools
LT_INIT
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

dnl Dependency list for grapple.pc
GRAPPLE_PC_REQUIRES=""
AC_SUBST([GRAPPLE_PC_REQUIRES])

dnl Check for pthreads
AX_PTHREAD([have_pthreads=yes], [have_pthreads=no])
if test "$have_pthreads" = "yes"; then
	LIBS="$PTHREAD_LIBS $LIBS"
	CFLAGS="$CFLAGS $PTHREAD_CFLAGS -DHAVE_PTHREAD_H"
	CC="$PTHREAD_CC"
else
	AC_MSG_ERROR([cannot find pthreads])
fi

dnl Check for SSL
AC_ARG_ENABLE([openssl], AS_HELP_STRING([--disable-openssl], [do not compile with OpenSSL support]))
if test "$enable_openssl" != "no"; then
	PKG_CHECK_MODULES([OPENSSL], [openssl])
	CFLAGS="$CFLAGS $OPENSSL_CFLAGS -DSOCK_SSL"
	LIBS="$LIBS $OPENSSL_LIBS"
	GRAPPLE_PC_REQUIRES="$GRAPPLE_PC_REQUIRES openssl"
fi

dnl Check whether an extra library is required for crypt()
CRYPT_LIBS=""
AC_SEARCH_LIBS([crypt], [crypt], [CRYPT_LIBS="-lcrypt"])
AC_SUBST([CRYPT_LIBS])

dnl Check for Windows Winsock library
AC_CHECK_LIB([ws2_32], [main])

AC_CHECK_HEADERS_ONCE([
	arpa/inet.h
	crypt.h
	errno.h
	fcntl.h
	ifaddrs.h
	limits.h
	linux/limits.h
	netdb.h
	netinet/in.h
	signal.h
	stdbool.h
	stdint.h
	strings.h
	stropts.h
	sys/file.h
	sys/ioctl.h
	sys/select.h
	sys/socket.h
	sys/time.h
	sys/types.h
	sys/un.h
	unistd.h
	windows.h
	winsock2.h
	ws2tcpip.h
])

AC_CHECK_HEADERS([net/if.h], CFLAGS="$CFLAGS -DHAVE_NET_IF_H", [], 
[[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
]])

AC_CHECK_FUNCS(inet_ntop inet_pton sigaction gettimeofday)

dnl Finally create all the generated files
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([pkgconfig/grapple.pc])
AC_CONFIG_FILES([pkgconfig/Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([test/Makefile])
AC_OUTPUT
