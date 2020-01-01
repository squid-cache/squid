#!/usr/bin/perl -w
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This is a simple script that will summarise per-user traffic
# statistics.
#
# Adrian Chadd <adrian@squid-cache.org>
# CVS-Id: PerUser.pl,v 1.2 2007/01/24 08:03:52 adrian Exp

use strict;
use Squid::ParseLog;

my %u;
my $wh;

$wh = "username";
if (scalar @ARGV >= 1) {
	$wh = $ARGV[0];
	shift @ARGV;
}

while (<>) {
	chomp;
	my $l = Squid::ParseLog::parse($_);
	if (! defined $u{$l->{$wh}}) {
		$u{$l->{$wh}}->{"traffic"} = 0;
	}
	$u{$l->{$wh}}->{"traffic"} += $l->{"size"};
}

foreach (keys %u) {
	printf "%s\t\t%lu\n", $_, $u{$_}->{"traffic"};
}
