#!/usr/local/bin/perl

# check_cache.pl - martin hamilton <m.t.hamilton@lut.ac.uk>
#
# Check the Harvest cache directory for stale objects - i.e. those
# which exist on disk but aren't listed in cached's log file.
# Version 1 did all this in memory, but the log file can be a
# little on the large side... 8-(

# $Id: check_cache.pl,v 1.3 1996/07/09 03:41:16 wessels Exp $

require "getopts.pl";
&Getopts("c:dl:rt:v");

$cachedir = $opt_c || "/usr/local/harvest/cache";
# -d -> turn on debugging output
$logfile = $opt_l || "$cachedir/log";
# -r -> actually remove stale files
$tmpdir = $opt_t || $ENV{TMPDIR} || "/var/tmp";
# -v -> list stale files

chdir($tmpdir);

# snarf filenames from Harvest log & sort em
system("cut -f1 -d' ' $logfile >pl$$");
system("sort -T $tmpdir pl$$ >spl$$; rm pl$$");

# get list of files in cache & sort em
system("find $cachedir -print -type f >cd$$");
system("sort -T $tmpdir cd$$ >scd$$; rm cd$$");

# get list of objects in one file but not the other
system("comm -13 spl$$ scd$$ >comm$$; rm spl$$ scd$$");

# iterate through it
open(IN, "comm$$") || die "Can't open temporary file $tmpdir/comm$$: $!";
while(<IN>) {
	chop;
	print STDERR ">> inspecting $_\n" if $opt_d;
	next if -d "$_"; # don't want directories
	next if /(log|cached.out)/; # don't want to zap these!

	print "$_\n" if $opt_v; # print filename if asked

	# skip if cached file appeared since script started running
	if (-M $_ < 0) {
		print STDERR "skipping $_\n" if $opt_d;
		next;
	}
	unlink($_) if $opt_r; # only remove if asked!
}
close(IN);

unlink("comm$$");

