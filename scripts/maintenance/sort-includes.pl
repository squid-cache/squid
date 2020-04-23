#!/usr/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# USAGE: sort-includes.pl filename.cc >filename.cc.sorted
#
# This tool helps to sort the #include directives in a c or c++ source file
# according to the Squid Coding guidelines.
# 
# The output of the tool is a source file where each block of consecutive
# include directives for project-specific files (#include "header.h")
# is sorted with this specification: squid.h (if present) is always first,
# then the other directives are sorted in case-insensitive alphabetical order.
#
# Suggested usage:
# for file in $(find . -name \*.cc); do /full/path/to/sort-includes.pl $file >$file.sorted; mv $file.sorted $file; done

use strict;
use warnings;

my %Seen = (); # preprocessor #include lines, indexed by file name

while (<>) {
  if (/^\s*#\s*include\s*"(.+?)"/) {
    my $fname = $1;
    # skip repeated file names that have identical #include lines
    if (defined $Seen{$fname}) {
      next if $Seen{$fname} eq $_;
      warn("$ARGV:$.: Warning: inconsistent $fname #include lines:\n");
      warn("    $Seen{$fname}");
      warn("    $_");
      # fall through to preserve every unique #include line
    }
    $Seen{$fname} = $_;
  } else {
    &dumpSeen();
    print;
  }
}
&dumpSeen();

sub dumpSeen {
  my $alwaysFirst = 'squid.h';
  if (defined $Seen{$alwaysFirst}) {
    print $Seen{$alwaysFirst};
    delete $Seen{$alwaysFirst};
  }
  print sort { lc($a) cmp lc($b) } values %Seen;
  %Seen = ();
}
