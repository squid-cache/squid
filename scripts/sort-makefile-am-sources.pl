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

my $current_source_section='';
while (<>) {
    if (m!^#!) {
        print;
        next;
    }
    # accumulate files and prep for sorting
    my %files = ();
#    if (/^(\S+_SOURCES)\s*(\+?=)(\s+\S+)*\s*\\$/) {
    if (/^(\S+_SOURCES)\s*(\+?=)\s*\\$/) {
        $current_source_section=$1;
        print "$1 $2 \\\n";
        if (defined $3) {

        }
    } else {
        print;
        next;
    }
    while (<>) {
        chomp;
        &addfile(\%files, $_, $current_source_section);
        if (! /\\$/ ) {  # last line in the list
            &print_files(\%files);
            last;
        }
    }
}

exit 0;

# arg: ref to hash to add the file to, filename
sub addfile
{
    my $files = shift @_;
    my $fn = shift @_;
    my $current_source_section = shift @_;

    $fn =~ m!\s*(tests/stub_|tests/test)?(\S+)(\s+\\\s*)?$! || die "no parse";
    my $prefix = (defined $1) ? $1 : '';
    my $filename = (defined $2) ? $2 : '';

    print STDERR "WARNING: duplicate $prefix$filename ".
        "detected in $current_source_section"
        if exists($files->{"$filename.$prefix"});

    $files->{"$filename.$prefix"}="$prefix$filename";
}

# arg is hash ref, print values in order of key
sub print_files
{
    my %files=%{$_[0]};
    my @q=();
    foreach my $k (sort keys %files) {
        push @q, "\t".$files{$k};
    }
    print join(" \\\n", @q)."\n";
}
