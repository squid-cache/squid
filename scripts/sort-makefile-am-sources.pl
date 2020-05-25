#!/usr/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

use strict;
use warnings;

while (<>) {
    if (m!^#!) {
        print;
        next;
    }
    if (/^(\S+_SOURCES)\s*=\s*\\$/) {
        print "$1 = \\\n";
    } else {
        print;
        next;
    }
    # accumulate files and prep for sorting
    my %files;
    while (<>) {
        my $prefix='';
        my $filename='';

        chomp;
        m!\s*(tests/stub_|tests/test)?(\S+)(\s+\\\s*)?$! || die "no parse";
        $prefix=$1 if (defined $1);
        $filename=$2 if (defined $2);
        
        $files{"$filename.$prefix"}="$prefix$filename";
        if (! /\\$/ ) {  # last line in the list
            &print_files(\%files);
            last;
        }
    }
}

# arg is hash ref, print values in order of key
sub print_files
{
    my %files=%{$_[0]};
    my @q=();
    foreach my $k (sort {lc $a cmp lc $b} keys %files) {
        push @q, "\t".$files{$k};
    }
    print join(" \\\n", @q)."\n";
}
