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

dnl Check for tools
AC_PROG_CC
LT_INIT
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

dnl Check for pthreads
AX_PTHREAD([have_pthreads=yes], [have_pthreads=no])

dnl Check for SSL
AC_ARG_ENABLE([openssl], AS_HELP_STRING([--disable-openssl], [do not compile with OpenSSL support]))
if test "$enable_openssl" != "no"; then
	PKG_CHECK_MODULES([OPENSSL], [openssl])
	CFLAGS="$CFLAGS $OPENSSL_CFLAGS -DSOCK_SSL"
	LIBS="$LIBS $OPENSSL_LIBS"
fi

if test "$have_pthreads" = "yes" ; then
	LIBS="$PTHREAD_LIBS $LIBS"
	CFLAGS="$CFLAGS $PTHREAD_CFLAGS -DHAVE_PTHREAD_H"
	CC="$PTHREAD_CC"
else
	AC_MSG_ERROR([cannot find pthreads])
fi

AC_CHECK_HEADER([errno.h], CFLAGS="$CFLAGS -DHAVE_ERRNO_H",)

AC_CHECK_HEADER([netinet/in.h], CFLAGS="$CFLAGS -DHAVE_NETINET_IN_H",)

AC_CHECK_HEADER([sys/types.h], CFLAGS="$CFLAGS -DHAVE_SYS_TYPES_H",)

AC_CHECK_HEADER([sys/socket.h], CFLAGS="$CFLAGS -DHAVE_SYS_SOCKET_H",)

AC_CHECK_HEADER([sys/select.h], CFLAGS="$CFLAGS -DHAVE_SYS_SELECT_H",)

AC_CHECK_HEADER([sys/un.h], CFLAGS="$CFLAGS -DHAVE_SYS_UN_H",)

AC_CHECK_HEADER([arpa/inet.h], CFLAGS="$CFLAGS -DHAVE_ARPA_INET_H",)

AC_CHECK_HEADER([netdb.h], CFLAGS="$CFLAGS -DHAVE_NETDB_H",)

AC_CHECK_HEADER([sys/ioctl.h], CFLAGS="$CFLAGS -DHAVE_SYS_IOCTL_H",)

AC_CHECK_HEADER([winsock2.h], CFLAGS="$CFLAGS -DHAVE_WINSOCK2_H" LIBS="$LIBS -lws2_32",)

AC_CHECK_HEADER([ws2tcpip.h], CFLAGS="$CFLAGS -DHAVE_WS2TCPIP_H",)

AC_CHECK_HEADER([windows.h], CFLAGS="$CFLAGS -DHAVE_WINDOWS_H",)

AC_CHECK_HEADER([unistd.h], CFLAGS="$CFLAGS -DHAVE_UNISTD_H",)

AC_CHECK_HEADER([ifaddrs.h], CFLAGS="$CFLAGS -DHAVE_IFADDRS_H",)

AC_CHECK_HEADERS([net/if.h], CFLAGS="$CFLAGS -DHAVE_NET_IF_H", [], 
[[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
]])

AC_CHECK_HEADER([signal.h], CFLAGS="$CFLAGS -DHAVE_SIGNAL_H",)

AC_CHECK_HEADER([sys/time.h], CFLAGS="$CFLAGS -DHAVE_SYS_TIME_H",)

AC_CHECK_HEADER([sys/file.h], CFLAGS="$CFLAGS -DHAVE_SYS_FILE_H",)

AC_CHECK_HEADER([stdint.h], CFLAGS="$CFLAGS -DHAVE_STDINT_H",)

AC_CHECK_HEADER([stdbool.h], CFLAGS="$CFLAGS -DHAVE_STDBOOL_H",)

AC_CHECK_HEADER([linux/limits.h], CFLAGS="$CFLAGS -DHAVE_LINUX_LIMITS_H",)
AC_CHECK_HEADER([limits.h], CFLAGS="$CFLAGS -DHAVE_LIMITS_H",)

AC_CHECK_HEADER([fcntl.h], CFLAGS="$CFLAGS -DHAVE_FCNTL_H",)

AC_CHECK_HEADER([strings.h], CFLAGS="$CFLAGS -DHAVE_STRINGS_H",)

AC_CHECK_HEADER([stropts.h], CFLAGS="$CFLAGS -DHAVE_STROPTS_H",)

AC_CHECK_FUNCS(inet_ntop inet_pton sigaction gettimeofday)

dnl Finally create all the generated files
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([test/Makefile])
AC_OUTPUT
