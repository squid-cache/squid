#!/usr/local/bin/perl
#
## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# flag_truncs.pl - martin hamilton <m.t.hamilton@lut.ac.uk>
#
# Check the CERN/Harvest/Netscape cache for truncated objects
# - i.e. those for which there is a "Content-length:" HTTP header,
#   and this does not match the size of the cached object

require "getopts.pl";
require "stat.pl";
&Getopts("cd");
# -c -> just count the number of objects with a Content-length header
# -d -> turn on debugging output

# pass filenames on command line or via STDIN
@things = $#ARGV >= 0 ? @ARGV : <STDIN>; 

$total_objects = 0, $content_length = 0;

# iterate through them
foreach $thing (@things) {
  chop $thing;

  $opt_d && (print STDERR ">> inspecting: $thing\n");
  next if -d "$thing"; # don't want directories

  $size = (stat($thing))[$ST_SIZE]||next;
  $opt_d && (print STDERR ">> stat: $size\n");
  print "$thing\n", next if ($size == 0);

  $total_objects++;

  $count = 0, $expected = 0;
  open(IN, "$thing") || die "Can't open cached object $thing: $!";
  while(<IN>) {
    $count += length($_);
    chop;
    print STDERR ">> inspecting $_\n" if $opt_d;
    last if /^(\s+|)$/; # drop out after the end of the HTTP headers

    # skip if cached file appeared since script started running
    if (-M $_ < 0) {
      print STDERR ">> skipping $_\n" if $opt_d;
      next;
    }
    
    if (/^Content-length:\s+(\d+)/i) {
      $expected = $1;
      $content_length++;
    }
  }
  close(IN);

  next if $opt_c;
  next if $expected == 0; # no Content-length header

  # looked at the headers now
  $difference = $size - $count;
  $opt_d && print STDERR ">> real: ", $difference, ", expected: $expected\n";
  if ($difference != $expected) {
    print "$thing (expected: $expected, got: $difference)\n";
  }
}

print "$content_length out of $total_objects had Content-length: header\n"
  if $opt_c;
