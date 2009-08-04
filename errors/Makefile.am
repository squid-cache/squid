## Process this file with automake to produce Makefile.in
#
# $Id$
#

errordir = $(datadir)/errors

##dist-hook eveything

DEFAULT_ERROR_DIR	= $(errordir)
DEFAULT_STYLESHEET	= $(sysconfdir)/errorpage.css

## List of automated translations possible:
TRANSLATIONPO=`ls -1 $(top_srcdir)/errors/*.po | grep -o -E "[a-z\-]+\.po" | sed s/.po//`
TRANSLATIONDIR=`ls -1 $(srcdir) $(builddir) | sed -e 's%$(srcdir)/%%' -e 's%$(builddir)/%%' -e 's%.po%%' `

## TODO: prevent this loop installing everything twice when srcdir == builddir
install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR) ; \
	for l in $(TRANSLATIONDIR) ; do \
	  echo "Located $$l for install..."; \
	  if test -d $(srcdir)/$$l; then \
		$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l && \
		for f in $(srcdir)/$$l/ERR_*; do \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		done; \
	  fi ; \
	  if test -d $(builddir)/$$l; then \
		$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l && \
		for f in $(builddir)/$$l/ERR_*; do \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		done; \
	  fi \
	done; \
	$(INSTALL_DATA) $(srcdir)/TRANSLATORS $(DESTDIR)$(DEFAULT_ERROR_DIR)/TRANSLATORS; \
	$(INSTALL_DATA) $(srcdir)/COPYRIGHT $(DESTDIR)$(DEFAULT_ERROR_DIR)/COPYRIGHT; \
	$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET).default; \
	if test -f $(DESTDIR)$(DEFAULT_STYLESHEET) ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_STYLESHEET)" ; \
	else \
		echo "$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET)"; \
		$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET); \
	fi ; \
	$(SHELL) $(srcdir)/alias-link.sh "$(LN)" "$(RM)" "$(DESTDIR)$(DEFAULT_ERROR_DIR)" "$(srcdir)/aliases" || exit 1 ;


uninstall-local:
	for l in $(TRANSLATIONDIR) ; do \
	  echo "Located $$l for uninstall ..."; \
	  if test -d $(srcdir)/$$l; then \
		for f in $(srcdir)/$$l/ERR_*; do \
			if test -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; then \
		        	$(RM) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; \
			fi; \
		done; \
	  fi ; \
	  if test -d $(builddir)/$$l; then \
		for f in $(builddir)/$$l/ERR_*; do \
			if test -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; then \
		        	$(RM) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; \
			fi; \
		done; \
	  fi \
	done;
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(DEFAULT_STYLESHEET)
	rm -f $(DESTDIR)$(DEFAULT_STYLESHEET).default
	rm -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/TRANSLATORS
	rm -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/COPYRIGHT

## Upgrade requires the new files to be pre-installed
upgrade: install
	$(SHELL) $(srcdir)/alias-link.sh "$(LN)" "$(RM)" "$(DESTDIR)$(DEFAULT_ERROR_DIR)" "$(srcdir)/alias-upgrade" || exit 1 ;

# undocumented hack.  You can use this target to create multi-lingual
# error pages.  For example:
#
#	make ADDLANG=English DESTLANG=French addlang
#
# by Andres Kroonmaa <andre@mail.lbi.ee>
#
# UPDATE: this hack completely breaks HTML standards and with the addition
#	  of language translations is now largely obsolete.
#	  It will be removed without notice at some future date.
#
addlang: all
	-@if test -d $(srcdir)/$(ADDLANG); then \
	if test -d $(DEFAULT_ERROR_DIR)/$(DESTLANG); then \
	cd $(srcdir)/$(ADDLANG)/ ; \
	for f in ERR_*; do \
		if test -f $(DEFAULT_ERROR_DIR)/$(DESTLANG)/$$f ; then \
			echo "appending $(ADDLANG)/$$f"; \
			echo "<HR>" >> $(DEFAULT_ERROR_DIR)/$(DESTLANG)/$$f ; \
			cat $$f >> $(DEFAULT_ERROR_DIR)/$(DESTLANG)/$$f; \
		fi; \
	done; \
	fi \
	fi

dist-hook: translate
	for lang in $(TRANSLATIONPO) templates; do \
	  if test -d $$lang ; then \
		test -d $(distdir)/$$lang \
		  || mkdir $(distdir)/$$lang \
		  || exit 1; \
		cp -p $(top_builddir)/errors/$$lang/ERR_*  $(distdir)/$$lang \
		  || exit 1; \
	  fi; \
	done; \
	for f in aliases alias-link.sh alias-upgrade errorpage.css TRANSLATORS COPYRIGHT; do \
		cp -p $(srcdir)/$$f $(distdir)/`basename $$f`; \
	done;

translate:
	@if ! test -f $(top_srcdir)/errors/en.po; then \
	  echo "Translation is not currently possible."; \
	  exit 0; \
	fi; \
	if test "$(PO2HTML)" != "" && test "$(PO2HTML)" != "no" && test "$(PO2HTML)" != "off" && test -f $(top_srcdir)/errors/en.po; then \
	  for lang in $(TRANSLATIONPO); do \
		test -d $(top_builddir)/errors/$$lang && $(RM) -r $(top_builddir)/errors/$$lang; \
		mkdir $(top_builddir)/errors/$$lang || exit 1; \
		echo -n "Translate '$$lang' ..."; \
		for f in `ls -1 $(top_srcdir)/errors/templates`; do \
			$(PO2HTML) --progress=none -i $(top_srcdir)/errors/$$lang.po -t $(top_srcdir)/errors/templates/$$f >$(top_builddir)/errors/$$lang/$$f || exit 1; \
		done; \
		echo "done."; \
	  done; \
	else \
	  if test "$(PO2HTML)" = "off" ; then \
	    echo "WARNING: Translation is disabled."; \
	  else \
	    echo "WARNING: Translation toolkit was not detected."; \
	  fi; \
	  echo "A drop-in bundle of pre-translated files is available from"; \
	  echo "http://www.squid-cache.org/Versions/langpack/"; \
	fi

all: translate
