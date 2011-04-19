include $(top_srcdir)/src/Common.am

EXTRA_DIST = config.test

libexec_PROGRAMS = negotiate_wrapper_auth

negotiate_wrapper_auth_SOURCES = negotiate_wrapper.cc nw_base64.cc nw_base64.h
negotiate_wrapper_auth_LDADD =  $(COMPAT_LIB) $(XTRA_LIBS)
