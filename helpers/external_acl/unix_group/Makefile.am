include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


libexec_PROGRAMS 		= squid_unix_group
man_MANS 			= squid_unix_group.8
EXTRA_DIST			= squid_unix_group.8 config.test
squid_unix_group_SOURCES	= check_group.c

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(XTRA_LIBS)
