#!/usr/local/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# check_cache.pl 
#
# Squid-1.0 version by martin hamilton <m.t.hamilton@lut.ac.uk>
# Squid-1.1 version by Bertold Kolics <bertold@tohotom.vein.hu>
#
# Check the Squid-1.1.x cache directory for stale objects - i.e. those
# which exist on disk but aren't listed in cached's log file.

require "getopts.pl";
&Getopts("c:drt:vh");
# -c		: the full path to squid.conf
# -d		: turn on debugging
# -r		: actually remove stale files
# -t tmpdir	: temporary directory
# -v 		: list stale files
# -h 		: print the help

if ($opt_h) {
	print "Usage: check_cache.pl -drvh -c squid.conf\n";
	print "\t-c the full path to squid.conf\n";
	print "\t-d turn on debugging\n";
	print "\t-r actually remove stale files\n";
	print "\t-t temporary directory\n";
	print "\t-v list stale files\n";
	print "\t-h print the help\n";
	exit;
}

$squidconf = $opt_c || "/usr/local/squid/etc/squid.conf";
open (squidconf) || die "$squidconf: $!\n";
$no_cachedir = 0;
$swaplog = '';
$level1dirno = 16;
$level2dirno = 256;
while (<squidconf>) {
	chop;
	if (/^cache_dir\s+(.*)/) {
		push (@cachedir, $1);
	} elsif (/cache_swap_log\s+(.*)/) {
		$swaplog = $1;
	} elsif (/swap_level1_dirs/) {
		$level1dirno = $1;
	} elsif (/swap_level21_dirs/) {
		$level2dirno = $1;
	}
}
close (squidconf);
push (@cachedir, '/usr/local/squid/cache') unless ($#cachedir > $[-1);
$swaplog = $cachedir[0] . '/log' unless ($swaplog);
$no_cachedir = $#cachedir + 1;
print "$no_cachedir CACHE DIRS: ", join(' ', @cachedir), "\n" if ($opt_d);
print "SWAP LOG: $swaplog\n" if ($opt_d);

$tmpdir = $opt_t || $ENV{TMPDIR} || "/var/tmp";
chdir($tmpdir);

# snarf file numbers from Squid log & sort em
system("cut -f1 -d' ' $swaplog |tr [a-z] [A-Z] >pl$$");
system("sort -T $tmpdir pl$$ >spl$$; rm pl$$");

# get list of files in cache & sort em
for ($i = 0 ; $i < $no_cachedir; $i++) {
	chdir($cachedir[i]);
	system("find ./ -print -type f > $tmpdir/fp$$");
	chdir($tmpdir);
# this cut prints only the lines with 4 fields so unnecessary lines
# are suppressed
	system("cut -d'/' -f4 -s fp$$ >> cd$$ ; rm fp$$")
}
system("sort -T $tmpdir cd$$ >scd$$; rm cd$$");

# get list of objects on disk (scd$$) but not in the log (spl$$)
system("comm -13 spl$$ scd$$ >comm$$; rm spl$$ scd$$");

chdir($tmpdir);
# iterate through it
open(IN, "comm$$") || die "Can't open temporary file $tmpdir/comm$$: $!";
unlink("comm$$");
while(<IN>) {
	chop;
	$filename = $_;

# calculate the full path of the current filename
	$fileno = hex($filename);
	$dirno = $fileno % $no_cachedir;
	$a = $fileno / $no_cachedir;
	$level1 = sprintf("%02X", $a % $level1dirno);
	$level2 = sprintf("%02X", $a / $level1dirno % $level2dirno);
	$filename = "$cachedir[dirno]/$level1/$level2/$filename";

	next if -d "$filename"; # don't want directories

	print "$filename\n" if $opt_v; # print filename if asked

	# skip if cached file appeared since script started running
	if (-M $filename < 0) {
		print STDERR "skipping $filename\n" if $opt_d;
		next;
	}
	print "Orphan: $filename\n";
	unlink($filename) if $opt_r; # only remove if asked!
}
close(IN);
