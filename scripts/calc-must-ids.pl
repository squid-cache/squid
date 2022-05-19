#!/usr/bin/perl
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##
#
# Author: Tsantilas Christos
# (C) 2010 The Measurement Factory
#
# Usage:
#     calc-must-ids.pl file1 file2 ...
# Compute the ids of Must expressions of the given files.
# It returns one line per Must expression in the form:
#     filename: line: MustID 'Must Text'
#

use warnings;
use strict;

# This constant should be synced with ERR_DETAIL_EXCEPTION_START enum
# defined in src/err_detail_type.h
use constant ERR_DETAIL_EXCEPTION_START => 110000;

my $file;
while ($file = shift @ARGV)  {
    ComputeMustIds($file);
}
sub FileNameHash
{
    my($name) = @_;

    # Keep in sync with FileNameHash() in src/base/Here.cc!

    $name =~  s/.*\///g;
    my($i) = 0;
    my($j) =0;
    my($n) = 0;
    my(@na) = split(//, $name);
    for($j=0; $j < @na; $j++) {
        $n = $n ^ (271 * ord($na[$j]));
    }
    return $n ^ ($j *271);
}

sub ComputeMustIds
{
    my($file) = @_;

    # Keep in sync with SourceLocation::id() in src/base/Here.cc!

    my $fullHash = &FileNameHash($file);
    my $hash = $fullHash % 0x3FFFF;

    if(!open(IN, "<$file")) {
        printf STDERR "error opening file $file. Ignore ...";
        return;
    }
    while(<IN>) {
        my($line) = $_;

        next if $line =~ /^\s*#/; # ignore simple single-line C++ macros
        $line =~ s@//.*@@; # strip simple // comments
        $line =~ s@/[*].*?[*]/@@; # strip simple single-line /* comments */

        my($id);
        if ($line =~ /\bMust\s*\(/ || # Must(...)
            $line =~ /\bTexcHere\s*\(/ || # TexcHere(...)
            $line =~ /\bHere\s*\(\s*\)/) { # Here()
            $line =~ s/^\s*//;
            $id= ($hash <<14) | ($. & 0x3FFF);
            $id += ERR_DETAIL_EXCEPTION_START;
#            print "$file:$.: $id $line";
            printf "%s:%d: 0x%X %s", $file, $., $id, $line;
        }
    }
    close(IN);
}
