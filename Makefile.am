
AM_MAKEFLAGS = --no-print-directory

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

gweb_sources = gweb/gweb.h gweb/gweb.c gweb/gresolv.h gweb/gresolv.c \
					gweb/giognutls.h gweb/gionotls.c

builtin_modules =
builtin_sources =
builtin_cflags =
builtin_libadd =

builtin_modules += ofono
builtin_sources += plugins/ofono.c

libexec_PROGRAMS = src/mmsd

src_mmsd_SOURCES = $(gdbus_sources) $(gweb_sources) $(builtin_sources) \
			src/main.c src/mms.h src/types.h \
			src/log.h src/log.c src/plugin.h src/plugin.c \
			src/dbus.h src/dbus.c src/service.h src/service.c \
			src/push.h src/push.c src/store.h src/store.c \
			src/wsputil.h src/wsputil.c src/mmsutil.h src/mmsutil.c

src_mmsd_LDADD = $(builtin_libadd) @GLIB_LIBS@ @DBUS_LIBS@ -lresolv -ldl

src_mmsd_LDFLAGS = -Wl,--export-dynamic

nodist_src_mmsd_SOURCES = src/builtin.h

plugindir = $(libdir)/mms/plugins

pushconfdir = $(libdir)/mms/push.d

pushconf_DATA =

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

AM_CFLAGS = @GLIB_CFLAGS@ @DBUS_CFLAGS@ $(builtin_cflags) \
					-DMMS_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(plugindir)"\" \
					-DPUSHCONFDIR=\""$(pushconfdir)"\"

INCLUDES = -I$(builddir)/src -I$(srcdir)/src -I$(srcdir)/gdbus

CLEANFILES = src/builtin.h

test_scripts = test/monitor-mms test/get-services test/send-message \
		test/delete-message test/mark-message-read test/get-messages \
		test/get-conversation test/set-use-delivery-reports

doc_files = doc/architecture.txt doc/consumer.txt doc/manager-api.txt \
				doc/service-api.txt doc/message-api.txt \
				doc/storage.txt

unit_test_data_files = unit/ni-mms-1-3-con-271.mms \
				unit/ni-mms-1-3-con-272.mms \
				unit/rc-mms-1-3-con-210.mms \
				unit/rc-mms-1-3-con-271.mms \
				unit/rc-mms-1-3-con-212.mms \
				unit/rc-mms-1-3-con-213.mms \
				unit/rc-mms-1-3-con-214.mms \
				unit/rc-mms-1-3-con-216.mms \
				unit/rc-mms-1-3-con-220.mms \
				unit/rc-mms-1-3-con-224.mms \
				unit/rc-mms-1-3-con-228.mms \
				unit/rc-mms-1-3-con-211.mms \
				unit/rc-mms-1-3-con-282.mms \
				unit/rc-mms-1-3-con-281.mms \
				unit/sr-mms-mixed.mms \
				unit/sr-mms-related-multi-to.mms

EXTRA_DIST = src/genbuiltin $(test_scripts) $(doc_files) \
					$(unit_test_data_files)

noinst_PROGRAMS = tools/decode-mms tools/create-hex-array \
			unit/test-wsputil unit/test-mmsutil

tools_decode_mms_SOURCES = src/wsputil.h src/wsputil.c tools/decode-mms.c
tools_decode_mms_LDADD = @GLIB_LIBS@

unit_test_wsputil_SOURCES = unit/test-wsputil.c src/wsputil.c src/wsputil.h
unit_test_wsputil_LDADD = @GLIB_LIBS@

unit_test_mmsutil_SOURCES = unit/test-mmsutil.c src/mmsutil.c src/mmsutil.h \
						src/wsputil.c src/wsputil.h
unit_test_mmsutil_LDADD = @GLIB_LIBS@

TESTS = unit/test-wsputil unit/test-mmsutil

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
