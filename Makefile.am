# $Id$

ACLOCAL_AMFLAGS	= -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

bin_PROGRAMS	= chaos as112d
chaos_SOURCES	= chaos.c
chaos_LDFLAGS	= -rdynamic -levldns -levent -lldns

as112d_SOURCES	= as112d.c
as112d_LDFLAGS	= -rdynamic -levldns -levent -lldns

lib_LTLIBRARIES	= libevldns.la mod_mangler.la mod_txtrec.la mod_myip.la

libevldns_la_SOURCES	= evldns.c plugin.c function.c network.c

mod_mangler_la_LDFLAGS = -module
mod_txtrec_la_LDFLAGS = -module
mod_myip_la_LDFLAGS = -module
