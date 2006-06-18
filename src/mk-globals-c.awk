# tested with gawk, mawk, and nawk.
# drop-in replacement for mk-globals-c.pl.
# modified to work with Solaris awk (junk).
# creates "globals.c" (on stdout) from "globals.h".
# invoke similarly:  perl mk-globals-c.pl globals.h
#		-->  awk -f mk-globals-c.awk globals.h
#
# 2006 by Christopher Kerr.

BEGIN				{ Copyright = 0
				  print "#include \"squid.h\"" }

Copyright != 1	&&  /^ \*\/$/	{ Copyright = 1; print; next }
Copyright != 1			{		 print; next }
/SQUID_GLOBALS_H/		{			next }

# arrays defined elsewhere
/\[\];/				{			next }
/^extern \"C\"/			{		 print; next }

#
# Check exactly for lines beginning with "    extern", generated
# from astyle (grrrrr ...)
#
/^    extern / {			     # process "^extern " input lines.
					     #		 0 1	  2    #######
    # extern int variable; /* val */   -->   int variable; /* val */   #######
    ##########################################################################
    len = length($0) - 11				# sub(/extern /, "")
    str = substr($0, 12, len)				# strip "^extern ".

    pos0 = index(str, ";")				# position of ";".
    pos1 = index(str, "/*")				# position of "/*".
    pos2 = index(str, "*/")				# position of "*/".

    if ( pos1 != 0 ) {					# make assignment.

	val = substr(str, pos1+3, pos2-pos1-4)		# get comment value.
	str = substr(str, 1, pos0-1) " = " val ";"	# string to semi-colon.
    }
    print str; next					# get next input line.
}
{ print }						# C preprocessor lines.
