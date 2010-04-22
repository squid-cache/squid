include $(top_srcdir)/src/Common.am

MSNTAUTH_CONF = $(sysconfdir)/msntauth.conf

libexec_PROGRAMS = msnt_auth

msnt_auth_SOURCES = md4.c rfcnb-io.c rfcnb-util.c session.c msntauth.c \
		msntauth.h smbdes.c smbencrypt.c smblib-util.c smblib.c \
		valid.c denyusers.c allowusers.c confload.c \
		usersfile.c \
		byteorder.h rfcnb-common.h rfcnb-error.h rfcnb.h \
		rfcnb-io.h rfcnb-priv.h rfcnb-util.h smblib-common.h \
		smblib.h smblib-priv.h std-defines.h std-includes.h valid.h \
		md4.h  smbdes.h smbencrypt.h usersfile.h

EXTRA_DIST = \
	COPYING-2.0 \
	msntauth.conf.default \
	msntauth-v2.0.lsm \
	README.html \
	config.test

sysconf_DATA = \
	msntauth.conf.default

LDADD = -L$(top_builddir)/lib -lmiscutil $(XTRA_LIBS) $(top_builddir)/compat/libcompat.la

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

confload.o: confload.c
	$(COMPILE) -DSYSCONFDIR=\"$(sysconfdir)\" -c $(srcdir)/confload.c -o $@

install-data-local:
	@if test -f $(DESTDIR)$(MSNTAUTH_CONF) ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(MSNTAUTH_CONF)" ; \
	else \
		echo "$(INSTALL_DATA) $(srcdir)/msntauth.conf.default $(DESTDIR)$(MSNTAUTH_CONF)" ; \
		$(INSTALL_DATA) $(srcdir)/msntauth.conf.default $(DESTDIR)$(MSNTAUTH_CONF) ; \
	fi

uninstall-local:
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(MSNTAUTH_CONF)
	$(RM) -f $(DESTDIR)$(MSNTAUTH_CONF).default
