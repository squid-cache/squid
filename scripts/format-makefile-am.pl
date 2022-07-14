#!/usr/bin/perl
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

use strict;
use warnings;

my $current_source_section='';
while (<>) {
    chomp;
    if (m!^#!) {
        print "$_\n";
        next;
    }
    # accumulate files and prep for sorting
    my %files = ();
    # TODO: Handle or rename /\S+SOURCE=/ and /\S*[^_]SOURCES=/
    my $groupNameRx = qr/\S+_SOURCES|ICONS|\S+_TEMPLATES|\S+_LANGUAGES|STUB_SOURCE/;
    if (/^($groupNameRx)\s*(\+?=)\s*(.*[^\\])$/ ) {
        my @parts = split(/\s+/, $3);
        if ($#parts == 0) { # one file only specified on same line as SOURCES
            print "$1 $2 $3\n";
            next;
        }
        foreach my $file (@parts) {
            &addfile(\%files, $file, $1);
        }
        print "$1 $2 \\\n";
        &print_files(\%files);
        next;
    }
    if (/^($groupNameRx)\s*(\+?=)\s*(.*?)\s*\\$/) {
        $current_source_section=$1;
        print "$1 $2 \\\n";
        if (defined $3) {
            foreach my $file (split(/\s+/, $3)) {
                &addfile(\%files, $file, $current_source_section);
            }
        }
    } else {
        print "$_\n";
        next;
    }
    while (<>) {
        chomp;
        m!^\s+(.*?)\s*\\?$!;
        foreach my $file (split(/\s+/, $1)) {
            &addfile(\%files, $file, $current_source_section) if (length $file);
        }
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
        "detected in $current_source_section\n"
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
