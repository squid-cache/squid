include $(top_srcdir)/src/Common.am

EXTRA_DIST = config.test

libexec_PROGRAMS = negotiate_wrapper_auth

negotiate_wrapper_auth_SOURCES = negotiate_wrapper.cc
negotiate_wrapper_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(XTRA_LIBS)
