## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# Makefile for installing Squid startup files on systems
# using a SVR4-based startup mechanism/file system layout
#

SQUID_RC        = $(top_srcdir)/tools/sysvinit/squid.rc
SQUID_OPTIONS   = squid.options

EXTRA_DIST = \
	squid.options \
	config.site \
	rredir.c \
	rredir.pl \
	user-agents.pl \
	url-normalizer.pl \
	nextstep/Makefile \
	nextstep/Makefile.real \
	nextstep/README \
	nextstep/Squid.pkg.README \
	nextstep/info.in \
	nextstep/makepkg \
	nextstep/post_install \
	nextstep/pre_install \
	solaris/solaris-krb5-include.patch

all: 

install: install-@host_os@

install-hpux10.10 install-hpux10.20:
	$(INSTALL_BIN) $(SQUID_RC) /sbin/init.d/squid
	$(INSTALL_FILE) $(SQUID_OPTIONS) /etc/rc.config.d/squid
	-$(LN_S) ../init.d/squid /sbin/rc2.d/S900squid
	-$(LN_S) ../init.d/squid /sbin/rc1.d/K100squid
	/usr/sbin/ch_rc -ap SQUID=1
	@echo "use 'ch_rc -ap SQUID=0' to disable squid at startup"
	@echo "edit /etc/rc.config.d/squid to change options"

install-solaris2.4 install-solaris2.5:
	$(INSTALL_BIN) $(SQUID_RC) /etc/init.d/squid
	-$(LN_S) ../init.d/squid /etc/rc2.d/S90squid
	-$(LN_S) ../init.d/squid /etc/rc1.d/K10squid
	-$(LN_S) ../init.d/squid /etc/rc0.d/K10squid
	@echo "set SQUID=0 in /etc/init.d/squid to disable squid at startup"
	@echo "edit /etc/init.d/squid to change options"

install-irix6.2:
	$(INSTALL_BIN) $(SQUID_RC) /etc/init.d/squid
	$(INSTALL_FILE) $(SQUID_OPTIONS) /var/config/squid.options
	-$(LN_S) ../init.d/squid /etc/rc2.d/S99squid
	-$(LN_S) ../init.d/squid /etc/rc0.d/K01squid
	/sbin/chkconfig -f squid on
	@echo "use 'chkconfig squid off' to disable squid at startup"
	@echo "edit /var/config/squid.options to change options"

install-osf3.2:
	$(INSTALL_BIN) $(SQUID_RC) /sbin/init.d/squid
	-$(LN_S) ../init.d/squid /sbin/rc2.d/S99squid
	-$(LN_S) ../init.d/squid /sbin/rc0.d/K01squid
	/usr/sbin/rcmgr set SQUID 1
	@echo "use 'rcmgr set SQUID 0' to disable squid at startup"
	@echo "use 'rcmgr set SQUID_OPTIONS ...' to change options"
	@echo "use 'rcmgr set SQUID_RESPAWN 0' to change option"

install-linux:
	$(INSTALL_BIN) $(SQUID_RC) /sbin/init.d/squid
	-$(LN_S) ../squid /sbin/init.d/rc3.d/S90squid
	-$(LN_S) ../squid /sbin/init.d/rc3.d/K10squid
	grep '^SQUID=' /etc/rc.config || echo SQUID=1 >>/etc/rc.config
	@echo "set SQUID=0 in /etc/rc.config to disable squid at startup"
	@echo "edit /sbin/init.d/squid to change options"
