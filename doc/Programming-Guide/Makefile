DOC=prog-guide

$(DOC).dvi: $(DOC).tex references.bib
#	[ -w $(DOC).tex ] || co -kv $(DOC).tex
	latex $(DOC).tex
#	env BSTINPUTS=/usr/local/tex/lib/texinput/bibtex bibtex $(DOC)
	bibtex $(DOC)
	perl -pi.bak -00 -e 's/%\n//g;' $(DOC).bbl

xdvi: $(DOC).dvi
	xdvi $(DOC).dvi

$(DOC).ps: $(DOC).dvi
	dvips $(DOC).dvi

ps: $(DOC).ps

gs: $(DOC).ps
	gs -I/usr/local/lib/ghostscript $(DOC).ps

gv: $(DOC).ps
	ghostview $(DOC).ps

index:
	makeindex $(DOC)

clean:
	/bin/rm -f $(DOC).dvi $(DOC).ps

foo: clean $(DOC).dvi clean $(DOC).dvi

twice:
	@clear
	co -kv $(DOC).tex
	latex $(DOC).tex
	env BSTINPUTS=/usr/local/tex/lib/texinput/bibtex bibtex $(DOC)
	@clear
	latex $(DOC).tex
	env BSTINPUTS=/usr/local/tex/lib/texinput/bibtex bibtex $(DOC)

spell:
	co -l  $(DOC).tex
	ispell $(DOC).tex
	ci -u  $(DOC).tex
	co -l  references.bib
	ispell references.bib
	ci -u  references.bib

white-paper.dvi: white-paper.tex
	latex white-paper.tex

white-paper.ps: white-paper.dvi
	dvips white-paper.dvi

tar:
	tar cvf $(DOC).tar Makefile $(DOC).tex references.bib

scp: $(DOC).ps
	scp $(DOC).ps oceana:public_html
