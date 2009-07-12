#!/usr/bin/perl -w


use strict;

# This is a simple script that will summarise per-user traffic
# statistics.
#
# Adrian Chadd <adrian@squid-cache.org>
# $Id: PerUser.pl,v 1.2 2007/01/24 08:03:52 adrian Exp $

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
