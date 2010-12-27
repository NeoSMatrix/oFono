
AM_MAKEFLAGS = --no-print-directory

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

builtin_modules =
builtin_sources =
builtin_cflags =
builtin_libadd =

builtin_modules += ofono
builtin_sources += plugins/ofono.c

libexec_PROGRAMS = src/mmsd

src_mmsd_SOURCES = $(gdbus_sources) $(builtin_sources) \
			src/main.c src/mms.h \
			src/log.h src/log.c src/plugin.h src/plugin.c \
			src/dbus.h src/dbus.c src/service.h src/service.c \
			src/push.h src/push.c

src_mmsd_LDADD = $(builtin_libadd) @GLIB_LIBS@ @DBUS_LIBS@ -ldl

src_mmsd_LDFLAGS = -Wl,--export-dynamic

nodist_src_mmsd_SOURCES = src/builtin.h

plugindir = $(libdir)/mms/plugins

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

AM_CFLAGS = @GLIB_CFLAGS@ @DBUS_CFLAGS@ $(builtin_cflags) \
					-DMMS_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(builddir)/src -I$(srcdir)/src -I$(srcdir)/gdbus

CLEANFILES = src/builtin.h

test_scripts = test/monitor-mms test/get-services

doc_files = doc/manager-api.txt

EXTRA_DIST = src/genbuiltin $(test_scripts) $(doc_files)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
