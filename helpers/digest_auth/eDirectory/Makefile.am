include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


libexec_PROGRAMS = digest_edirectory_auth
digest_edirectory_auth_SOURCES = digest_pw_auth.cc \
	digest_common.h \
	ldap_backend.cc \
	ldap_backend.h \
	edir_ldapext.cc \
	edir_ldapext.h

digest_edirectory_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(LDAPLIB) \
	$(LBERLIB) \
	$(CRYPTLIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)

EXTRA_DIST = config.test
