# $Id: Makefile.am,v 1.11 2003/05/21 08:24:26 hno Exp $
#

ICON1	=	anthony-binhex.gif
ICON2 	=	anthony-bomb.gif \
		anthony-box.gif \
		anthony-box2.gif \
		anthony-c.gif \
		anthony-compressed.gif \
		anthony-dir.gif \
		anthony-dirup.gif \
		anthony-dvi.gif \
		anthony-f.gif \
		anthony-image.gif \
		anthony-image2.gif \
		anthony-layout.gif \
		anthony-link.gif \
		anthony-movie.gif \
		anthony-pdf.gif \
		anthony-portal.gif \
		anthony-ps.gif \
		anthony-quill.gif \
		anthony-script.gif \
		anthony-sound.gif \
		anthony-tar.gif \
		anthony-tex.gif \
		anthony-text.gif \
		anthony-unknown.gif \
		anthony-xbm.gif \
		anthony-xpm.gif

icondir = $(datadir)/icons
icon_DATA = $(ICON1) $(ICON2)
EXTRA_DIST = $(ICON1) $(ICON2) icons.shar
DISTCLEANFILES = 

# The magic with ICON1,2 is to have a single dependency
# for all of the icons.
$(ICON2): $(ICON1)

$(ICON1):
	@if [ ! -f "$(srcdir)/$(ICON1)" ]; then \
	    $(SHELL) "$(srcdir)/icons.shar" ; \
	    touch -r "$(srcdir)/icons.shar" *.gif ; \
	fi

update-icons.shar:
	shar --no-timestamp $(ICON1) $(ICON2) > $@ 2>/dev/null || \
	shar $(ICON1) $(ICON2) > $@

## DEFAULT_ICON_DIR        = $(sysconfdir)/icons

