## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Filters the given input searching for "STUB" definitions
# to create a *.stub.cc file.
#
# The input file should be a C/C++ header file.
#
# All static variables, functions, and methods with external
# definitions in the .cc file should be marked up using
# the Squid stubs syntax: void functionFoo() STUB;
#

BEGIN {
	if (ENVIRON["STUB"]) {
		includeFile = ENVIRON["STUB"]
		gsub(/(src|include|[.]*)[/]/, "", includeFile)
		gsub(/[ ]/, "", includeFile)
		stubApi = includeFile
		sub(/[.]h$/, ".cc", stubApi)

		print "/* Generated automatically by scripts/mk-stub.awk DO NOT EDIT */"
		print "/*"
		print " * Copyright (C) 1996-2026 The Squid Software Foundation and contributors"
		print " *"
		print " * Squid software is distributed under GPLv2+ license and includes"
		print " * contributions from numerous individuals and organizations."
		print " * Please see the COPYING and CONTRIBUTORS files for details."
		print " */"
		print ""
		print "#include \"squid.h\""
		print ""
		print "#define STUB_API \"" stubApi "\""
		print "#include \"tests/STUB.h\""
		print ""
	}

	inClass=""
}

/^#if[ ]/	{ print ; next }
/^#ifndef/	{
	sub(/SQUID_SRC_/,"") sub(/_H$/,".h") sub(/_/,"/")
	print "#include \"" includeFile "\""
}
/^#endif/	{
	if ($0 ~ /[/][*][ ]SQUID_/) {
		next
	}
	print
}

/^namespace/	{
	print $0
	if (! ($0 ~ /[{]/))
		print "{\n"
	next
}
/^}[/ ]*namespace/	{ print ; next }

/^class.*;$/		{ next }
/^class[ ]+([^:]+)/	{ inClass=$2 }
/}[;]/			{ inClass="" ; next }

/[/]+STUB/	{
	if (inClass) {
		split($0, type, "(")
		split(type[1], typeWords, " ")
		name = typeWords[length(typeWords)]
		fullName = name
		sub(/[^*&]+$/, inClass "::&", fullName)
		sub(name, fullName)
	}
	sub(/^[ ]*static /,"")
	sub(/[;][ ]*[/]*STUB/," STUB")
	sub(/[;]/,"")
	sub(/^[ ]*/,"")
	print
}

END {
	print ""
}
