DOC	= release-2.5

all: $(DOC).html $(DOC).ps

$(DOC).ps: $(DOC).sgml
	linuxdoc -B latex -o ps $(DOC)

#$(DOC).dvi: $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#

$(DOC).txt: $(DOC).sgml
	linuxdoc -B txt --filter $(DOC)

$(DOC).html: $(DOC).sgml
	linuxdoc -B html --split=0 $(DOC)

$(DOC).man: $(DOC).sgml
	linuxdoc -B txt -m $(DOC)

clean:
	rm -f *.html
	rm -f $(DOC).tex $(DOC).ps $(DOC).dvi $(DOC).aux $(DOC).log $(DOC).toc
	rm -f $(DOC).txt $(DOC).man
