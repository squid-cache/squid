#!/usr/bin/perl -w
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Reads cache.log and displays lines that correspond to a given CodeContext.

use strict;
use warnings;

die("usage: $0 <CodeContext id> [log filename]\n") unless @ARGV;
my $ContextId = shift;

my $GroupSeparator = "--\n";

my $inside = 0;
my $currentGroup = 0;
my $lastReportedGroup = undef();
while (<>) {
    if (/\bCodeContext.*?\bEntering: (.*)/) {
        my $wasInside = $inside;
        $inside = $1 eq $ContextId;

        # detect no-Leaving switches from our CodeContext to another
        ++$currentGroup if $wasInside && !$inside;
    }

    my $external = !$inside && /\b$ContextId\b/o;

    if ($inside || $external) {
        ++$currentGroup if $external;
        print $GroupSeparator if defined($lastReportedGroup) && $currentGroup != $lastReportedGroup;
        print $_;
        $lastReportedGroup = $currentGroup;
    } else {
        ++$currentGroup;
    }

    if ($inside && /\bCodeContext.*?\bLeaving: /) {
        $inside = 0;
        ++$currentGroup;
    }
}

exit(0);
