#!/usr/bin/perl
#
## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

$|=1;
while (<>) {
	print "OK\n";
}
print STDERR "stdin closed, exit\n";
