#
#  Makefile for the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.10 2003/01/23 00:35:26 robertc Exp $
#
#  Uncomment and customize the following to suit your needs:
#


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
	README.html

sysconf_DATA = \
	msntauth.conf.default

LDADD = -L$(top_builddir)/lib -lmiscutil $(XTRA_LIBS)

INCLUDES      = -I$(top_srcdir)/include

confload.o: confload.c
	$(COMPILE) -DSYSCONFDIR=\"$(sysconfdir)\" -c $(srcdir)/confload.c -o $@

install-data-local:
	@if test -f $(DESTDIR)$(sysconfdir)/msntauth.conf ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/msntauth.conf" ; \
	else \
		echo "$(INSTALL_DATA) $(srcdir)/msntauth.conf.default $(DESTDIR)$(sysconfdir)/msntauth.conf" ; \
		$(INSTALL_DATA) $(srcdir)/msntauth.conf.default $(DESTDIR)$(sysconfdir)/msntauth.conf ; \
	fi

	
