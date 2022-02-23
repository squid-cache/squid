#!/usr/bin/perl -w
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Reads cache.log and displays lines that correspond to a given async job.
#
# If job entering/exiting line format changes, the script must be updated.
# Keep the old RE around for a while because they may be handy for working
# with folks running older Squids.

use strict;
use warnings;

my $XactId = shift or die("usage: $0 <xaction id> [log file]\n");

# Squid uses asyncNNN, jobNNN, icapxNNN for the same job/transaction
# TODO: use jobNNN everywhere
$XactId =~ s/^(?:async|job|icapx)(\d+)$/(async|job|icapx)$1/ and
    warn("Replacing xaction ID with $XactId\n");

my $inside = 0;

my $entering;

while (<>) {
    $entering = $_ if !$inside && /[|:] entering\b/;
    undef $entering if /[|:] leaving\b/;

    # if (!$inside && /\bcalled\b.*\b$XactId\b/o) {
    if (!$inside && /\bstatus in\b.*\b$XactId\b/o) {
        print $entering if defined $entering;
        $inside = 1;
    }

    my $external = !$inside && /\b$XactId\b/o;

    print $_ if $inside || $external;
    print "\n" if $external;

    next unless $inside;

    # if (/\bended\b.*\b$XactId\b/o || /\bswan\s+sang\b.*\b$XactId\b/o) {
    # if (/\bstatus out\b.*\b$XactId\b/o || /\bswan\s+sang\b.*\b$XactId\b/o ||
    if (/[|:] leaving\b/) {
        print "\n";
        $inside = 0;
    }
}

exit(0);
