#!/usr/bin/perl -w
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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

my $inside = 0;

while (<>) {
    if (/\bCodeContext.*?\bEntering: (\S+)/) {
        my $wasInside = $inside;
        $inside = $1 eq $ContextId;

        # switched from our CodeContext to another
        print "\n" if $wasInside && !$inside;
    }

    my $external = !$inside && /\b$ContextId\b/o;

    print $_ if $inside || $external;
    print "\n" if $external;

    if ($inside && /\bCodeContext.*?\bLeaving:/) {
        $inside = 0;
        print "\n";
    }
}

exit(0);
