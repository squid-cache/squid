DOC	= prog-guide

all: $(DOC).html $(DOC).ps

$(DOC).ps: $(DOC).dvi
	dvips $(DOC).dvi

$(DOC).dvi: $(DOC).sgml
	sgml2latex $(DOC)

#$(DOC).dvi: $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#
#$(DOC).tex: $(DOC).sgml
#	sgml2latex $(DOC)

$(DOC).html: $(DOC).sgml
	sgml2html $(DOC)

clean:
	rm -f *.html
	rm -f $(DOC).tex $(DOC).ps $(DOC).dvi $(DOC).aux $(DOC).log $(DOC).toc
