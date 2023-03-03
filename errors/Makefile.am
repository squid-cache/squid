## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

errordir = $(datadir)/errors

##dist-hook eveything

DEFAULT_ERROR_DIR	= $(errordir)
DEFAULT_STYLESHEET	= $(sysconfdir)/errorpage.css

## List of automated translations possible:
include $(srcdir)/template.am
include $(srcdir)/language.am

if ENABLE_TRANSLATION
TRANSLATE_LANGUAGES = $(LANGUAGE_FILES)
else !ENABLE_TRANSLATION
TRANSLATE_LANGUAGES =
endif

CLEANFILES = $(TRANSLATE_LANGUAGES) translate-warn
EXTRA_DIST = \
	$(ERROR_TEMPLATES) \
	templates/error-details.txt \
	language.am \
	template.am \
	aliases alias-link.sh alias-upgrade errorpage.css TRANSLATORS COPYRIGHT

if ENABLE_TRANSLATION
ALIAS_LINKER=$(SHELL) $(srcdir)/alias-link.sh "$(LN)" "$(RM)" "$(DESTDIR)$(DEFAULT_ERROR_DIR)"
else !ENABLE_TRANSLATION
ALIAS_LINKER=$(TRUE)
endif

all: all-am

translate: translate-warn $(TRANSLATE_LANGUAGES)

translate-warn:
	case "$(PO2HTML)" in \
	off) \
	    echo "WARNING: Translation is disabled."; \
	    ;; \
	""|no) \
	    echo "WARNING: Translation toolkit was not detected."; \
	    ;; \
	esac; \
	touch translate-warn

$(TRANSLATE_LANGUAGES): $(ERROR_TEMPLATES)

NOTIDY=`$(PO2HTML) --help | grep -o "[-]-notidy"`

.po.lang:
	if test "$(PO2HTML)" != "" && test "$(PO2HTML)" != "no" && test "$(PO2HTML)" != "off" && test -f $(top_srcdir)/errors/en.po; then \
	    lang=`basename $@ .lang`; \
	    mkdir -p $(top_builddir)/errors/$$lang; \
	    echo -n "Translate '$$lang' ..."; \
	    for f in $(ERROR_TEMPLATES); do \
		page=`basename $$f`; \
		$(PO2HTML) $(NOTIDY) --progress=none -i $(top_srcdir)/errors/$$lang.po -t $(top_srcdir)/errors/$$f >$(top_builddir)/errors/$$lang/$$page || exit 1; \
	    done; \
	    cp $(top_srcdir)/errors/templates/error-details.txt $(top_builddir)/errors/$$lang/error-details.txt || exit 1; \
	    echo "done."; \
	fi; \
	touch $@

install-exec-local: translate
	if test -f $(DESTDIR)$(DEFAULT_STYLESHEET) ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_STYLESHEET)" ; \
	else \
		$(mkinstalldirs) $(DESTDIR)`dirname $(DEFAULT_STYLESHEET)` ; \
		echo "$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET)"; \
		$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET); \
	fi

install-data-local: translate
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR) ; \
	for l in $(TRANSLATE_LANGUAGES) templates; do \
	    l=`basename $$l .lang`; \
	    echo "Located $$l for install..."; \
	    if test -d $(srcdir)/$$l || test -d $(builddir)/$$l; then \
		$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
	    fi; \
	    for f in $(ERROR_TEMPLATES) templates/error-details.txt; do \
		page=`basename $$f`; \
		if test -f $(builddir)/$$l/$$page; then \
		    echo "$(INSTALL_DATA) $(builddir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			    $(INSTALL_DATA) $(builddir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		elif test -f $(srcdir)/$$l/$$page; then \
		    echo "$(INSTALL_DATA) $(srcdir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			    $(INSTALL_DATA) $(srcdir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		fi; \
	    done; \
	done; \
	$(INSTALL_DATA) $(srcdir)/TRANSLATORS $(DESTDIR)$(DEFAULT_ERROR_DIR)/TRANSLATORS; \
	$(INSTALL_DATA) $(srcdir)/COPYRIGHT $(DESTDIR)$(DEFAULT_ERROR_DIR)/COPYRIGHT; \
	$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET).default; \
	$(ALIAS_LINKER) "$(srcdir)/aliases" || exit 1 ;

uninstall-local:
	for l in $(TRANSLATE_LANGUAGES) templates; do \
	  l=`basename $$l .lang`; \
	  echo "Located $$l for uninstall ..."; \
	  if test -d $(srcdir)/$$l; then \
		for f in $(srcdir)/$$l/ERR_* $(srcdir)/$$l/error-details.txt; do \
			if test -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; then \
		        	$(RM) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; \
			fi; \
		done; \
	  fi ; \
	  if test -d $(builddir)/$$l; then \
		for f in $(builddir)/$$l/ERR_* $(builddir)/$$l/error-details.txt; do \
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
	$(ALIAS_LINKER) "$(srcdir)/alias-upgrade" || exit 1 ;

dist-hook: translate
	for lang in $(TRANSLATE_LANGUAGES); do \
	  lang=`basename $$lang .lang`; \
	  if test -d $$lang ; then \
		mkdir -p $(distdir)/$$lang; \
		cp -p $(top_builddir)/errors/$$lang/ERR_*  $(distdir)/$$lang || exit 1; \
		cp -p $(top_builddir)/errors/$$lang/error-details.txt $(distdir)/$$lang || exit 1; \
	  fi; \
	done

clean: clean-am
	if test "$(PO2HTML)" != "" && test "$(PO2HTML)" != "no" && test "$(PO2HTML)" != "off" && test -f $(top_srcdir)/errors/en.po; then \
	  for lang in $(TRANSLATE_LANGUAGES); do \
	    lang=`basename $$lang .lang`; \
	    rm -rf $$lang; \
	  done; \
	fi

all: translate
