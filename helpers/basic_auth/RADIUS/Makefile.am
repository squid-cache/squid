include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)

libexec_PROGRAMS 	= basic_radius_auth
man_MANS 		= basic_radius_auth.8
EXTRA_DIST		= basic_radius_auth.8 config.test
basic_radius_auth_SOURCES = \
			basic_radius_auth.cc \
			radius.h \
			radius-util.cc \
			radius-util.h

basic_radius_auth_LDADD = \
	$(top_builddir)/lib/libmiscencoding.la \
	$(COMPAT_LIB) \
	$(SSLLIB) \
	$(XTRA_LIBS)
