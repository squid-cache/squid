include $(top_srcdir)/src/Common.am

MSNTAUTH_CONF = $(sysconfdir)/msntauth.conf

libexec_PROGRAMS = basic_msnt_auth

basic_msnt_auth_SOURCES = \
	allowusers.cc \
	confload.cc \
	denyusers.cc \
	msntauth.cc \
	msntauth.h \
	usersfile.cc \
	usersfile.h \
	valid.cc \
	valid.h

EXTRA_DIST = \
	msntauth.conf.default \
	msntauth-v2.0.lsm \
	README.html \
	config.test

sysconf_DATA = \
	msntauth.conf.default

CFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\"
CXXFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\"
LDADD = \
	$(top_builddir)/lib/smblib/libsmblib.la \
	$(top_builddir)/lib/rfcnb/librfcnb.la \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir) -I$(top_srcdir)/lib


install-data-local: msntauth.conf.default
	@if test -f $(DESTDIR)$(MSNTAUTH_CONF) ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(MSNTAUTH_CONF)" ; \
	else \
		echo "$(INSTALL_DATA) $(srcdir)/msntauth.conf.default $(DESTDIR)$(MSNTAUTH_CONF)" ; \
		$(INSTALL_DATA) $(srcdir)/msntauth.conf.default $(DESTDIR)$(MSNTAUTH_CONF) ; \
	fi

uninstall-local:
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(MSNTAUTH_CONF)
	$(RM) -f $(DESTDIR)$(MSNTAUTH_CONF).default

