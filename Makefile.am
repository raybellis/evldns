ACLOCAL_AMFLAGS	= -I m4

bin_PROGRAMS	= chaos as112d
chaos_SOURCES	= chaos.c
chaos_LDFLAGS	= -rdynamic -levldns -levent -lldns

as112d_SOURCES	= as112d.c
as112d_LDFLAGS	= -rdynamic -levldns -levent -lldns

lib_LTLIBRARIES	= libevldns.la mod_mangler.la mod_version.la

libevldns_la_SOURCES	= evldns.c plugin.c function.c network.c

mod_mangler_la_LDFLAGS = -module
mod_version_la_LDFLAGS = -module
