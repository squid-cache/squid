#!/usr/bin/perl
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
# Please keep in sync this function with the FileNameHash function in
# src/base/TextException.cc file
    my($name) = @_;
    $name =~  s/.*\///g;
    my($i) = 0;
    my($j) =0;
    my($n) = 0;
    my(@na) = split(//, $name);
    for($j=0; $j < @na; $j++) {
        $n = $n ^ (271 * ord($na[$j])); 
    }
    $i = $n ^ ($j *271);
    
    # Currently 18bits of a 32 bit integer used  for filename hash 
    # (max hash=262143),  and 14 bits for storing line number
    $i = $i % 262143;
    return $i;
}

sub ComputeMustIds
{
    my($file) = @_;
    my($hash) = FileNameHash($file);
    if(!open(IN, "<$file")) {
        printf STDERR "error opening file $file. Ignore ...";
        return;
    }
    while(<IN>) {
        my($line) = $_;
        my($id);
        if ( $line =~ /^\s*Must\s*\(/  || $line =~ /^\s*throw\s*TexcHere\s*\(/){
            $line =~ s/^\s*//;
            $id= ($hash <<14) | ($. & 0x3FFF);
            $id += ERR_DETAIL_EXCEPTION_START;
#            print "$file:$.: $id $line";
            printf "%s:%d: 0x%X %s", $file, $., $id, $line;
        }            
    }    
    close(IN);
}
