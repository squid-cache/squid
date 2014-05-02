include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

libexec_PROGRAMS = digest_ldap_auth
digest_ldap_auth_SOURCES = digest_pw_auth.cc \
	digest_common.h \
	ldap_backend.cc \
	ldap_backend.h

digest_ldap_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(NETTLELIB) \
	$(CRYPTLIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = required.m4
