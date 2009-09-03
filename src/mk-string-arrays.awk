# tested with gawk, mawk, and nawk.
# drop-in replacement for mk-string-arrays.pl.
# creates "enum.c" (on stdout) from "enum.h".
# invoke similarly: perl -f mk-string-arrays.pl	 enum.h
#		-->  awk -f mk-string-arrays.awk enum.h
#
# 2006 by Christopher Kerr.
#
# 2009 modified by Amos Jeffries
#   Adapted to convert individual enum headers
#

BEGIN {
	print "/*"
	print " * Auto-Generated File. Changes will be destroyed."
	print " */"
	print "#include \"squid.h\""
        codeSkip = 1
        e = 0
}

# Skip all lines outside of typedef {}
/^typedef/		{ codeSkip = 0; next }
codeSkip == 1		{ next }

/^[ \t]*[A-Z]/ {
	split($1, t, ",")			# remove ,
	Element[++e] = t[1]
	next
}

/^} / {
	split($2, t, ";")			# remove ;
	type = t[1]
        codeSkip = 1

	print "#include \"" type ".h\""
	print "\nconst char *" type "_str[] = {"
	for ( i = 1; i < e; ++i)
		print "\t\"" Element[i] "\","
	print "\t\"" Element[i] "\""
	print "};"
	next
}
