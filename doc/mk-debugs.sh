cat ../{src,lib,include}/*{.,/*.,/*/*.,/*/*/*.}{c,cc,h} 2>/dev/null \
	| grep " DEBUG:" \
	| sed -e 's/ \* DEBUG: //' \
	| sort -u \
	| sort -n
