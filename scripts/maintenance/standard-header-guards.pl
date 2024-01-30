#!/usr/bin/perl

## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# source-maintenance plugin to standardize the header guards

use strict;
use warnings;

my $filename = $ARGV[0];

if ($filename !~ /\.h$/i || $filename =~ /^scripts\/boilerplate.h/i) {
    while (<>) { print; }
    exit(0);
}

my @accumulate=();
my $current_guard = undef;

my $first_ifndef_pos = undef;
my $last_endif_pos = undef;
while (<>) {
    push(@accumulate, $_);
    if (!defined($first_ifndef_pos) && /^#ifndef\s+(\w+_H)/ ) {
        $current_guard = $1;
        $first_ifndef_pos = $#accumulate;
    } elsif (/^#endif/) {
        $last_endif_pos = $#accumulate;
    }
}

die("Cannot decect header guard #ifndef in $filename")
    unless defined($first_ifndef_pos);
die("cannot detect header guard in $filename")
    unless defined($current_guard);
die("no #endif in $filename - incomplete file or header guard?")
    unless defined($last_endif_pos);
die("last endif in $filename is not after first ifndef")
    unless ($last_endif_pos > $first_ifndef_pos);
die("first #ifndef in $filename seems to be the last line in the file")
    unless ($first_ifndef_pos < $#accumulate);
die ("#define $current_guard doesn't immediately follow first #ifndef in $filename")
    unless ($accumulate[$first_ifndef_pos+1] =~ /^#define\s+$current_guard/);
for (@accumulate[$last_endif_pos+1..$#accumulate]) {
    die("unexpected content '$_' after last #ifndef in $filename") unless(/^$/);
}

my $new_guard = $filename;
$new_guard =~ s/[\/\-\.]/_/g;
$new_guard = "SQUID_".uc($new_guard);

$accumulate[$first_ifndef_pos] = "#ifndef $new_guard\n";
$accumulate[$first_ifndef_pos+1] = "#define $new_guard\n";
$accumulate[$last_endif_pos] = "#endif /* $new_guard */\n";

print @accumulate;
