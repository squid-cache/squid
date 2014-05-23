include $(top_srcdir)/src/Common.am

EXTRA_DIST = required.m4

libexec_PROGRAMS = negotiate_wrapper_auth

negotiate_wrapper_auth_SOURCES = negotiate_wrapper.cc
negotiate_wrapper_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(NETTLELIB) \
	$(XTRA_LIBS)
