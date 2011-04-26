include $(top_srcdir)/icons/list

icondir = $(datadir)/icons/silk
icon_DATA = $(ICONS)
EXTRA_DIST = $(ICONS) list SN.png
DISTCLEANFILES = 

install-data-local: SN.png install-iconDATA
	$(INSTALL_DATA) $(srcdir)/SN.png "$(DESTDIR)$(datadir)/icons/"

uninstall-local:
	$(RM) $(DESTDIR)$(datadir)/icons/SN.png
