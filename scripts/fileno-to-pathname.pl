#!/usr/local/bin/perl

# $Id: fileno-to-pathname.pl,v 1.2 1997/07/16 20:31:55 wessels Exp $
# Convert hexadecimal cache file numbers (from swap log) into full pathnames.  
# Duane Wessels 6/30/97

require 'getopts.pl';

&Getopts('c:');
$L1 = 16;
$L2 = 256;

$CF = $opt_c || '/usr/local/squid/etc/squid.conf';
&usage unless (open (CF));
$ncache_dirs = 0;
while (<CF>) {
	$CD[$ncache_dirs++] = $1 if (/^cache_dir\s+(\S+)/);
	$L1 = $1 if (/^swap_level1_dirs\s+(\d+)/);
	$L2 = $1 if (/^swap_level2_dirs\s+(\d+)/);
}
close(CF);
unless ($ncache_dirs) {
	$CD[$ncache_dirs++] = '/usr/local/squid/cache';
}


while (<>) {
	chop;
	print &storeSwapFullPath(hex($_)), "\n";
}

sub storeSwapFullPath {
	local($fn) = @_;
	sprintf "%s/%02X/%02X/%08X",
		$CD[$fn % $ncache_dirs],
		($fn / $ncache_dirs) % $L1,
		($fn / $ncache_dirs) / $L1 % $L2,
		$fn;
}

sub usage {
	print STDERR "usage: $0 -c config\n";
	print STDERR "hexadecimal file numbers are read from stdin\n";
	exit 1;
}
