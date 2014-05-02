include $(top_srcdir)/src/Common.am
 
libexec_PROGRAMS = url_fake_rewrite
url_fake_rewrite_SOURCES = fake.cc

url_fake_rewrite_LDADD = $(COMPAT_LIB)

libexec_SCRIPTS = url_fake_rewrite.sh

EXTRA_DIST = url_fake_rewrite.sh required.m4
