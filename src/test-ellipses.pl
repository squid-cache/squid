#!/usr/local/bin/perl -w
use strict;

# $Id: test-ellipses.pl,v 1.1 1998/03/09 07:32:53 rousskov Exp $

#
# Replaces printf-like function calls with printf and compiles with gcc -Wall
#    to catch %-escape bugs.
#

# params

die(&usage()) unless @ARGV;

# globals
my @FileNames = ();
my $CC = 'gcc';
my $CFlags = '-Wall -I../include -I. -DDEFAULT_CONFIG_FILE="config"'; #default

my $TmpDir = '/tmp';

my $ErrCount = 0;

exit(&main() == 0);

sub main {
    # find compiler options
    my ($fnames, $options) = split(/--/, join('|', @ARGV));
    @FileNames = split(/\|/, $fnames);
    die(&usage()) unless @FileNames;
    $CFlags = join(' ', split(/\|/, $options)) if defined $options;
    warn("Warning: no -Wall in cflags '$CFlags'\n") unless $CFlags =~ /\Q-Wall\E/;

    mkdir($TmpDir, umask()) unless -d $TmpDir;

    foreach (@FileNames) {
	&processFile($_);
    }
    warn("Found $ErrCount potential error(s)\n");
    return scalar @FileNames;
}

sub processFile {
    my $fname = shift;

    # test that the file is compilable
    my $cmd = "$CC $CFlags -c $fname -o /dev/null";
    my $result = `$cmd 2>&1`;
    if ($result) {
	warn("Warning: '$cmd' produced this output:\n$result\n");
	warn("Warning: skipping potentially un-compileable file: $fname\n");
	return;
    }

    my $fname_tmp = "$TmpDir/test-elipses.tmp.c";

    # replace printf-likes with printf
    open(IFH, "<$fname") or die("cannot open $fname: $!, stopped");
    open(OFH, ">$fname_tmp") or die("cannot create $fname_tmp: $!, stopped");
    $/ = ';';
    my $line;
    while (defined($line = <IFH>)) {
	# comments are a disaster
	# next if $line =~ m|\Q/*\E|;
	# debug
	next if $line =~ s|debug\(\d+,\s+\d+\)\s*|/*$&*/ printf|;
	# other (e.g., storeAppendPrintf) with '?' before format
	next if $line =~ s@\w+[pP]rintf\s*\((?![\)])(\n|[^\;\"])+\?\s+"@/*$&*/ printf(1 ? "@;
	# other (e.g., storeAppendPrintf)
	next if $line =~ s@\w+[pP]rintf\s*\((?![\)])(\n|[^\;\"])+"@/*$&*/ printf("@;
    } continue {
	print(OFH $line);
    }
    close(IFH);
    close(OFH) or die("cannot close $fname_tmp: $!, stopped");

    # compile
    $cmd = "$CC $CFlags -c $fname_tmp -o /dev/null";
    # warn("Exec: '$cmd'");
    open(CFH, "$cmd 2>&1 |") or die("cannot start '$cmd': $!, stopped");
    $/ = "\n";
    $| = 0;
    # read errors, restore file name, print;
    while (defined($line = <CFH>)) {
	if ($line =~ s/\Q$fname_tmp\E/$fname/g) {
	    $ErrCount++ if $line =~ /(warning|error)/i;
	}
	print($line);
    }
    (close(CFH) || !$!) or die("cannot close '$cmd': $!, stopped");
}

sub usage {
    my $buf = << "USAGE";
usage: $0 <file.c> ... -- [cflags]
USAGE

    return $buf;
}
