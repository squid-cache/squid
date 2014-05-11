include $(top_srcdir)/src/Common.am

libexec_SCRIPTS = delayer
CLEANFILES += delayer delayer.8
man_MANS = delayer.8
EXTRA_DIST = delayer.pl.in delayer.8 required.m4

delayer.8: delayer
	pod2man delayer delayer.8

delayer: delayer.pl.in
	$(subst_perlshell)
