## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

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
        nspath = ""
}

# when namespace is encountered store it
/^namespace *[a-zA-Z]+/	{
	nspath = tolower($2) "/"		# nested folder
	namespace = $2				# code namespace reconstruct
	next
}

# Skip all lines outside of typedef {}
/^typedef/		{ codeSkip = 0; next }
codeSkip == 1		{ next }

/^[ \t]*[A-Z]/ {
	split($1, t, ",")			# remove ,
	if (sbuf) Element[++e] = "SBuf(\"" t[1] "\")"
	else Element[++e] = "\"" t[1] "\""
	next
}

/^#/ {
	if (codeSkip) next

	Wrapper[++e] = $0
	next
}

/^} / {
	split($2, t, ";")			# remove ;
	type = t[1]
        codeSkip = 1

	if (sbuf) print "#include \"SBuf.h\""
	print "#include \"" nspath type ".h\""

	# if namesapce is not empty ??
	if (namespace) print "namespace " namespace
	if (namespace) print "{"

	if (sbuf) print "\nconst SBuf " type "_sb[] = {"
	else print "\nconst char * " type "_str[] = {"
	for ( i = 1; i < e; ++i)
		if (Wrapper[i]) print Wrapper[i]
		else print "\t" Element[i] ","

	print "\t" Element[i]
	print "};"
	if (namespace) print "}; // namespace " namespace
	next
}
