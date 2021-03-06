AC_PREREQ(2.60)
AC_INIT(mmsd, 0.0)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests])
AM_CONFIG_HEADER(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

if (test "${libdir}" = '${exec_prefix}/lib'); then
	libdir="${prefix}/lib"
fi

plugindir="${libdir}/mms/plugins"

pushconfdir="${libdir}/mms/push.d"

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi
])

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

AC_CHECK_HEADERS(resolv.h, dummy=yes,
			AC_MSG_ERROR(resolver header files are required))
AC_CHECK_LIB(resolv, ns_initparse, dummy=yes, [
	AC_CHECK_LIB(resolv, __ns_initparse, dummy=yes,
			AC_MSG_ERROR(resolver library support is required))
])

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16, dummy=yes,
				AC_MSG_ERROR(GLib >= 2.16 is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.2, dummy=yes,
				AC_MSG_ERROR(D-Bus >= 1.2 is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_OUTPUT(Makefile)
