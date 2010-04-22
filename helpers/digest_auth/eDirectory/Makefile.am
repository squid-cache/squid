#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


libexec_PROGRAMS = digest_edir_auth
digest_edir_auth_SOURCES = digest_pw_auth.c \
	digest_common.h \
	ldap_backend.c \
	ldap_backend.h \
	edir_ldapext.c \
	edir_ldapext.h

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(LIB_LDAP) \
	$(LIB_LBER) \
	$(CRYPTLIB) \
	$(XTRA_LIBS) \
	$(SSLLIB)

EXTRA_DIST = config.test
