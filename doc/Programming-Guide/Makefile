DOC	= prog-guide

all: $(DOC).html $(DOC).ps $(DOC).txt

$(DOC).ps: $(DOC).dvi
	dvips -o $(DOC).ps $(DOC).dvi

$(DOC).tex: $(DOC).sgml
	linuxdoc --backend=latex --papersize=letter $(DOC)

$(DOC).dvi: $(DOC).tex
	latex $(DOC).tex
	latex $(DOC).tex
	latex $(DOC).tex

$(DOC).txt: $(DOC).sgml
	linuxdoc --backend=txt $(DOC)

$(DOC).html: $(DOC).sgml
	sgml2html $(DOC)

clean:
	rm -f *.html
	rm -f $(DOC).tex $(DOC).ps $(DOC).dvi $(DOC).aux $(DOC).log $(DOC).toc
