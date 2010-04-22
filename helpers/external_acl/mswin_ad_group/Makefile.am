libexec_PROGRAMS = mswin_check_ad_group

mswin_check_ad_group_SOURCES = mswin_check_ad_group.c mswin_check_ad_group.h

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include

LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	-lnetapi32 \
	-ladvapi32 \
	-lntdll \
	$(XTRA_LIBS)

EXTRA_DIST = readme.txt config.test
