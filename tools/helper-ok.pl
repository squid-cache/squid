#!/usr/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

$|=1;
while (<>) {
    sleep 10;
    print "OK\n";
}
print STDERR "stdin closed, exit\n";
