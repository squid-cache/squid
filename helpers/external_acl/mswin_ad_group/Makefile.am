libexec_PROGRAMS = mswin_check_ad_group

mswin_check_ad_group_SOURCES = mswin_check_ad_group.c mswin_check_ad_group.h

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/include

#
# Currently activeds and adsiid libraries are not available on MinGW or Cygwin,
# so the following library list is just a placeholder for future MinGW/Cygwin releases.
# This helper can be compiled only using Microsoft Visual Studio.
#
LDADD = \
	$(top_builddir)/compat/libcompat.la \
	-L$(top_builddir)/lib -lmiscutil \
	-lnetapi32 \
	-ladvapi32 \
	-lole32 \
	-loleaut32 \
	-lntdll \
	-lactiveds \
	-ladsiid \
	$(XTRA_LIBS)

EXTRA_DIST = readme.txt config.test
