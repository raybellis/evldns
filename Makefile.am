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

include_HEADERS = evldns.h

bin_PROGRAMS	= chaos as112d oas112d fixed

chaos_SOURCES	= chaos.c
chaos_LDFLAGS	= -rdynamic -levldns -levent -lldns

as112d_SOURCES	= as112d.c
as112d_LDFLAGS	= -rdynamic -levldns -levent -lldns

oas112d_SOURCES	= oas112d.c
oas112d_LDFLAGS	= -rdynamic -levldns -levent -lldns

fixed_SOURCES	= fixed.c
fixed_LDFLAGS	= -rdynamic -levldns -levent -lldns

lib_LTLIBRARIES	= libevldns.la mod_mangler.la mod_txtrec.la mod_arec.la mod_myip.la

libevldns_la_SOURCES	= evldns.c plugin.c function.c network.c

mod_mangler_la_LDFLAGS = -module
mod_txtrec_la_LDFLAGS = -module
mod_arec_la_LDFLAGS = -module
mod_myip_la_LDFLAGS = -module
