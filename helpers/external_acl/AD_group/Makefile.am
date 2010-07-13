include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = ext_ad_group_acl
ext_ad_group_acl_SOURCES = ext_ad_group_acl.cc
man_MANS = ext_ad_group_acl.8

#
# Currently activeds and adsiid libraries are not available on MinGW or Cygwin,
# so the following library list is just a placeholder for future MinGW/Cygwin releases.
# This helper can be compiled only using Microsoft Visual Studio.
#
LDADD = \
	$(COMPAT_LIB) \
	-lnetapi32 \
	-ladvapi32 \
	-lole32 \
	-loleaut32 \
	-lntdll \
	-lactiveds \
	-ladsiid \
	$(XTRA_LIBS)

EXTRA_DIST = config.test ext_ad_group_acl.8
