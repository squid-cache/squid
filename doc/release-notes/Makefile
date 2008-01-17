all: release-3.1.html

$(DOC).ps: $(DOC).sgml
	linuxdoc -B latex -o ps $(DOC)

#$(DOC).dvi: $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#

%.txt: %.sgml
	linuxdoc -B txt --filter $<

%.html: %.sgml
	linuxdoc -B html --split=0 $<

%.man: %.sgml
	linuxdoc -B txt -m $(DOC)

clean:
	rm -f *.html
	rm -f *.tex *.ps *.dvi *.aux *.log *.toc
	rm -f *.txt *.man
