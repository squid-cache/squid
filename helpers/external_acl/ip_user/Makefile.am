include $(top_srcdir)/src/Common.am

## we need our local files too (but avoid -I. at all costs)
INCLUDES += -I$(srcdir)


libexec_PROGRAMS = ip_user_check

ip_user_check_SOURCES = \
	dict.c \
	ip_user.h \
	main.c \
	match.c

EXTRA_DIST = \
	example.conf \
	example-deny_all_but.conf \
	license \
	README \
	config.test

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	$(XTRA_LIBS)
