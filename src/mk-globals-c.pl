print "#include \"squid.h\"\n";
while (<>) {
	$init = undef;
	if (/^#/) {
		print;
		next;
	}
	next unless (/./);
	next if (/\[\];$/);
	die unless (/^extern\s+([^;]+);(.*)$/);
	$var = $1;
	$comments = $2;
	if ($comments =~ m+/\*\s*(\S*)\s*\*/+) {
		$init = $1;
	}
	print $var;
	print " = $init" if (defined $init);
	print ";\n";
}
exit 0;
