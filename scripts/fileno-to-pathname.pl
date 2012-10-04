#!/usr/bin/perl -w

# Convert hexadecimal cache file numbers (from swap log) into full pathnames.  
# Duane Wessels 6/30/97

# 2001-12-18 Adapted for squid-2.x Alain Thivillon <at@rominet.net>
#            -w and use strict;
#            Getopt::Std

use strict;
use vars qw($opt_c);
use Getopt::Std;

&getopts('c:');

my @L1 = ();
my @L2 = ();
my @CD = ();

my $SWAP_DIR_SHIFT=24;
my $SWAP_FILE_MASK=0x00FFFFFF;

my $CF = $opt_c || '/usr/local/squid/etc/squid.conf';
&usage unless (open (CF,"<$CF"));

my $ncache_dirs = 0;

while (<CF>) {
   # Squid 2.3 ===>
   # cache_dir ufs path size L1 L2
   if (/^cache_dir\s+(\S+)\s+(\S+)\s+\d+\s+(\S+)\s+(\S+)/i) {
     $CD[$ncache_dirs] = $2;
     $L1[$ncache_dirs] = $3;
     $L2[$ncache_dirs++] = $4;
   }
}
close(CF);

if ($ncache_dirs == 0) {
  print STDERR "No proper cache_dir line found\n";
  exit 2;
}

while (<>) {
	chop;
	print &storeSwapFullPath(hex($_)), "\n";
}

sub storeSwapFullPath {
	my($fn) = @_;

        my $dirn = ($fn >> $SWAP_DIR_SHIFT) % $ncache_dirs;
        my $filn = $fn & $SWAP_FILE_MASK;

	sprintf "%s/%02X/%02X/%08X",
		$CD[$dirn],
		(($fn / $L2[$dirn]) / $L2[$dirn]) % $L1[$dirn],
		($fn / $L2[$dirn]) % $L2[$dirn],
		$fn;
}

sub usage {
	print STDERR "usage: $0 -c config\n";
	print STDERR "hexadecimal file numbers are read from stdin\n";
	exit 1;
}
