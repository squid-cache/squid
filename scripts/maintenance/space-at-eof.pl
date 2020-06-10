#!/usr/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# USAGE: space-at-eof.pl filename.cc >filename.cc.sorted

# ensure that there is an empty line at end of file

use strict;
use warnings;

my $lastline;
while (<>) {
    $lastline=$_;
    print;
}
print "\n" unless $lastline eq "\n";
