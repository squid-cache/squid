# tested with gawk, mawk, and nawk.
# drop-in replacement for mk-string-arrays.pl.
# creates "enum.c" (on stdout) from "enum.h".
# invoke similarly: perl -f mk-string-arrays.pl	 enum.h
#		-->  awk -f mk-string-arrays.awk enum.h
#
# 2006 by Christopher Kerr.

BEGIN { # converted to "const char *"TypedefEnum[?]"_str[]"
	TypedefEnum["err_type"] = 1
	TypedefEnum["lookup_t"] = 1
	TypedefEnum["icp_opcode"] = 1
	TypedefEnum["swap_log_op"] = 1
}

/^ \*\/$/ && Copyright != 1	{ Copyright = 1; print; next }
Copyright != 1			{ 		 print;	next }
/^typedef/			{ e = 0;		next }

/^[ \t]*[A-Z]/ {
	split($1, t, ",")			# remove ,
	Element[++e] = t[1]
	next
}

/^} / {
	split($2, t, ";")			# remove ;
	type = t[1]
	if (TypedefEnum[type]) {
		print "\nconst char *" type "_str[] = {"
		for ( i = 1; i < e; ++i)
			print "\t\"" Element[i] "\","
		print "\t\"" Element[i] "\""
		print "};"
	}
	next
}

