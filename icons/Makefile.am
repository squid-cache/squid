include $(top_srcdir)/icons/list

icondir = $(localstatedir)/www/squid/icons/silk
icon_DATA = $(ICONS)
EXTRA_DIST = $(ICONS) list SN.png
DISTCLEANFILES = 

install-data-local: SN.png install-iconDATA
	$(INSTALL_DATA) $(srcdir)/SN.png "$(DESTDIR)$(localstatedir)/www/squid/icons/"

uninstall-local:
	$(RM) $(DESTDIR)$(localstatedir)/www/squid/icons/SN.png
