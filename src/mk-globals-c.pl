## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

print "#include \"squid.h\"\n";
while (<>) {
	$init = undef;
	next if (/ SQUID_GLOBALS_H/);
	if (/^#/) {
		print;
		next;
	}
	if (/^.\*/) {
		print;
		next;
	}
	if (/extern \"C\"/) {
		print;
		next;
	}
	if (/^}/) {
		print;
		next;
	}
	if (/^{/) {
		print;
		next;
	}
	next unless (/./);
	next if (/\[\];$/);
#
# Check exactly for lines beginning with "    extern", generated
# from astyle (grrrrr ...)
#
	die unless (/^    extern\s+([^;]+);(.*)$/);
	$var = $1;
	$comments = $2;
	if ($comments =~ m+/\*\s*(.*)\s*\*/+) {
		$init = $1;
		$init =~ s/\s$// while ($init =~ /\s$/);
	}
	print $var;
	print " = $init" if (defined $init);
	print ";\n";
}
exit 0;
