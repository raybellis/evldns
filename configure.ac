# $Id$

# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([evldns],[0.1],[ray@nominet.org.uk])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

CHECK_COMPILER_FLAG([Wall], [CFLAGS="-Wall $CFLAGS"])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for libraries.
AC_ARG_WITH(ldns,
	    [ --with-ldns=DIR          LDNS install directory], [
	     	AM_CPPFLAGS="$AM_CPPFLAGS -I$withval/include"
	     	AM_LDFLAGS="$AM_LDFLAGS -L$withval/lib"
	    ])

AC_ARG_WITH(libevent,
	    [ --with-libevent=DIR      libevent install directory], [
	     	AM_CPPFLAGS="$AM_CPPFLAGS -I$withval/include"
	     	AM_LDFLAGS="$AM_LDFLAGS -L$withval/lib"
	    ])

# save user flags
OLDCFLAGS="$CFLAGS"
OLDCPPFLAGS="$CPPFLAGS"
OLDLDFLAGS="$LDFLAGS"
tmp_LIBS="$LIBS"

# check for libraries using supplied flags
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"
LDFLAGS="$AM_LDFLAGS $LDFLAGS"

AC_CHECK_LIB([ldns], [ldns_dname_match_wildcard], [],
	     AC_MSG_ERROR([libdns unuseable])
)
AC_CHECK_LIB([event], [event_init])

# restore user flags
CPPFLAGS="$OLDCPPFLAGS"
CFLAGS="$OLDCFLAGS"
LDFLAGS="$OLDLDFLAGS"
LIBS="$tmp_LIBS"

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([sys/socket.h netdb.h])
AC_CHECK_HEADERS([ldns/ldns.h event.h])
AC_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_SEARCH_LIBS([dlopen], [dl])
AC_CHECK_FUNCS([socket memset strdup])
AC_CHECK_FUNCS([getaddrinfo getnameinfo])
AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)
AC_OUTPUT
