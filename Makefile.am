
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
			src/main.c src/mms.h src/types.h \
			src/log.h src/log.c src/plugin.h src/plugin.c \
			src/dbus.h src/dbus.c src/service.h src/service.c \
			src/push.h src/push.c src/wsputil.h src/wsputil.c \
			src/mmsutil.h src/mmsutil.c

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

doc_files = doc/architecture.txt doc/manager-api.txt

EXTRA_DIST = src/genbuiltin $(test_scripts) $(doc_files)

noinst_PROGRAMS = unit/test-wsputil unit/test-mmsutil \
			tools/decode-mms tools/create-hex-array

unit_test_wsputil_SOURCES = unit/test-wsputil.c src/wsputil.c src/wsputil.h
unit_test_wsputil_LDADD = @GLIB_LIBS@

unit_test_mmsutil_SOURCES = unit/test-mmsutil.c src/mmsutil.c src/mmsutil.h \
						src/wsputil.c src/wsputil.h
unit_test_mmsutil_LDADD = @GLIB_LIBS@

tools_decode_mms_SOURCES = src/wsputil.h src/wsputil.c tools/decode-mms.c
tools_decode_mms_LDADD = @GLIB_LIBS@

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
