#!/usr/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This script reassembles a split configuration file back into a cf.data.pre
# file.

use strict;
use IO::File;
use File::Basename;

my ($path) = ".";

if (defined $ARGV[0]) {
    $path = dirname($ARGV[0]);
}

sub filename($)
{
	my ($name) = @_;
	return $path . "/" . $name . ".txt";
}

my ($in) = new IO::File;
while(<>) {
    if (/^NAME: (.*)/) {
	my (@aliases) = split(/ /, $1);
	my ($name) = shift @aliases;
	$in->open(filename($name), "r") || die "Couldn't open ".filename($name).":$!\n";
	while(<$in>) {
	    print $_;
	}
	$in->close();
    } else {
	print $_;
    }
}
undef $in;
