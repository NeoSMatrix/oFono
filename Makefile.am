
AM_MAKEFLAGS = --no-print-directory

builtin_modules =
builtin_sources =
builtin_cflags =
builtin_libadd =

libexec_PROGRAMS = src/mmsd

src_mmsd_SOURCES = $(builtin_sources) \
			src/main.c src/mms.h \
			src/log.h src/log.c src/plugin.h src/plugin.c

src_mmsd_LDADD = $(builtin_libadd) @GLIB_LIBS@ -ldl

src_mmsd_LDFLAGS = -Wl,--export-dynamic

nodist_src_mmsd_SOURCES = src/builtin.h

plugindir = $(libdir)/mms/plugins

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

AM_CFLAGS = @GLIB_CFLAGS@ $(builtin_cflags) \
					-DMMS_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(builddir)/src -I$(srcdir)/src

CLEANFILES = src/builtin.h

EXTRA_DIST = src/genbuiltin

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
