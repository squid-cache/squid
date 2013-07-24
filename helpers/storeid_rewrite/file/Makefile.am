include $(top_srcdir)/src/Common.am

libexec_SCRIPTS	= storeid_file_rewrite
CLEANFILES += storeid_file_rewrite storeid_file_rewrite.8
man_MANS = storeid_file_rewrite.8
EXTRA_DIST= \
	storeid_file_rewrite.8 \
	storeid_file_rewrite.pl.in \
	required.m4

storeid_file_rewrite.8: storeid_file_rewrite
	pod2man storeid_file_rewrite storeid_file_rewrite.8

storeid_file_rewrite: storeid_file_rewrite.pl.in
	$(subst_perlshell)
