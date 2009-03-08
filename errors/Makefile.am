## Process this file with automake to produce Makefile.in
#
# $Id$
#

errordir = $(datadir)/errors


##dist-hook eveything

DEFAULT_ERROR_DIR	= $(errordir)
DEFAULT_STYLESHEET	= $(sysconfdir)/errorpage.css


# List of automated translations possible:
TRANSLATIONS = \
	ar \
	az \
	bg \
	ca \
	cs \
	da \
	de \
	el \
	en en-au en-gb en-nz en-us \
	es \
	et \
	fi \
	fr \
	hy \
	id \
	it \
	ja \
	lv \
	nl \
	pt-br \
	ro \
	ru \
	sr \
	sv \
	tr \
	uk \
	zh-cn

# Legacy language contributions...
#
LANGUAGES	= \
		Hebrew \
		Hungarian \
		Korean \
		Lithuanian \
		Polish \
		Portuguese \
		Slovak \
		Traditional_Chinese

install-data-local: 
	@for l in $(LANGUAGES); do \
		$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l && \
		for f in $(srcdir)/$$l/ERR_*; do \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		done; \
	done; \
	for l in $(TRANSLATIONS) templates; do \
	  if test -d $(srcdir)/$$l; then \
		$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l && \
		for f in $(srcdir)/$$l/ERR_*; do \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		done; \
	  fi \
	done; \
	$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET).default; \
	if test -f $(DESTDIR)$(DEFAULT_STYLESHEET) ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_STYLESHEET)" ; \
	else \
		echo "$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET)"; \
		$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET); \
	fi


uninstall-local:
	@ for l in $(LANGUAGES); do \
		for f in $(srcdir)/$$l/ERR_*; do \
	        	rm -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; \
		done; \
	done; \
	for l in $(TRANSLATIONS) templates; do \
	  if test -d $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; then \
		for f in $(srcdir)/$$l/ERR_*; do \
	        	rm -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; \
		done; \
	  fi \
	done;
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh $(RM) $(DESTDIR)$(DEFAULT_STYLESHEET)
	rm -f $(DESTDIR)$(DEFAULT_STYLESHEET).default

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

dist-hook:
	for lang in $(LANGUAGES) templates; do \
	  if test -d $(srcdir)/$$lang ; then \
		test -d $(distdir)/$$lang \
		  || mkdir $(distdir)/$$lang \
		  || exit 1; \
		cp -p $(srcdir)/$$lang/ERR_*  $(distdir)/$$lang \
		  || exit 1; \
	  fi; \
	done; \
	$(MAKE) translate; \
	for lang in $(TRANSLATIONS); do \
	  if test -d $$lang ; then \
		test -d $(distdir)/$$lang \
		  || mkdir $(distdir)/$$lang \
		  || exit 1; \
		cp -p $$lang/ERR_*  $(distdir)/$$lang \
		  || exit 1; \
	  fi; \
	done; \
	cp -p $(srcdir)/errorpage.css  $(distdir)/errorpage.css

translate:
	@ if test "$(PO2HTML)" != "" && test "$(PO2HTML)" != "no" && test "$(PO2HTML)" != "off"; then \
	  for lang in $(TRANSLATIONS); do \
		test -d $$lang && rm -r $$lang; \
		mkdir $$lang; \
		cd $$lang; \
		echo -n "Translate '$$lang' ..."; \
		for f in `ls -1 ../$(srcdir)/templates`; do \
			$(PO2HTML) --progress=none -i ../$(srcdir)/$$lang.po -t ../$(srcdir)/templates/$$f >$$f || exit 1; \
		done; \
		echo "done."; \
		cd ..; \
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

all:
	$(MAKE) translate
