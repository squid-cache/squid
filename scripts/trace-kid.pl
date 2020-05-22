#!/usr/bin/perl -w
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Reads cache.log and displays lines that correspond to a given kid.
#
# Cache log format and logging bugs make accurate kid attribution impossible,
# but this script is much better than running "grep kidN cache.log" and missing
# all "kidless" lines that do not contain kidN ID, such as HTTP header dumps.

use strict;
use warnings;
use Getopt::Long;

my $IncludePrefix = 0; # include initial kidless lines
my $IncludeMentions = 0; # include other kid references to the targeted kid
GetOptions(
	"prefix!"  => \$IncludePrefix,
    "mentions!"  => \$IncludeMentions,
) or die(usage());

my $Kid = shift or die(usage());
die("$0: error: expecting an integer kid ID but got $Kid\n")
	unless $Kid =~ /^\d+$/;

my $lastKid;
while (<>) {
	my ($currentKid) = (/^\d[^a-z]+? kid(\d+)[|]/);
	$lastKid = $currentKid if defined $currentKid;

	if (!defined($currentKid) && !defined($lastKid)) { # kidless prefix
		print $_ if $IncludePrefix;
		next;
	}

	# targeted kid output or kidless output by, hopefully, the targeted kid
	if (defined $lastKid && $lastKid == $Kid) {
		print $_;
		next;
	}

	if (defined $currentKid) { # wrong kid output
		# print lines mentioning our kid if requested, isolating each such line
		print "\n$_\n" if $IncludeMentions && /\bkid(:\s*)?$Kid\b/o;
		next;
	}

	# ignore kidless output produced by, hopefully, wrong kids
}

exit(0);

sub usage() {
	return <<"USAGE";
usage: $0 [option...] <kid ID> [log file...]
options:
    --prefix   include initial kidless lines
    --mentions include other kid references to the targeted kid
USAGE
}
