#!/usr/bin/perl -w
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

use strict;
use IO::File;
use Getopt::Long;
use File::Basename;

# This mess is designed to parse the squid config template file
# cf.data.pre and split it into separare files, one per option
#
# Henrik Nordstrom <henrik@henriknordstrom.net>

#
# The template file is reasonably simple to parse. There's a number of
# directives which delineate sections but there's no section delineation.
# A section will "look" somewhat like this, most of the time:
# NAME: <name>
# IFDEF: <the ifdef bit>
# TYPE: <the config type>
# DEFAULT: <the default value>
# LOC: <location in the Config struct>
# DOC_START
#   documentation goes here
# NOCOMMENT_START
#   stuff which goes verbatim into the config file goes here
# NOCOMMENT_END
# DOC_END
#
# or alternatively instead of the DOC_START/DOC_END block just
# DOC_NONE if the option is documented by the next option
#
# Configuration sections are broken up by COMMENT_START/COMMENT_END
# bits, which we can use in the top-level index page.
#

my $verbose = '';
my $path = ".";

my ($index) = new IO::File;
my ($out) = new IO::File;
my $name;

my $top = dirname($0);

GetOptions(
	'verbose' => \$verbose, 'v' => \$verbose,
	'out=s' => \$path,
	);

sub filename($)
{
	my ($name) = @_;
	return $path . "/" . $name . ".txt";
}

$index->open(filename("0-index"), "w") || die "Couldn't open ".filename("0-index").": $!\n";

while (<>) {
	chomp;
	print $index $_."\n" if !defined $name;
	last if (/^EOF$/);
	if ($_ =~ /^NAME: (.*)$/) {
		print "DEBUG: new option: $name\n" if $verbose;

		my (@aliases) = split(/ /, $1);
		$name = shift @aliases;

		$out->open(filename($name), "w") || die "Couldn't open ".filename($name).": $!\n";
	}
	print $out $_."\n" if defined $name;

	if ($_ =~ /^DOC_END/ ||
	    $_ =~ /^DOC_NONE/) {
		$out->close();
		undef $name;
	}
}
undef $out;
$index->close;
undef $index;
