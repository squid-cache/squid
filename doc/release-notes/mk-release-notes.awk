#!/usr/bin/awk
#
# * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
# *
# * Squid software is distributed under GPLv2+ license and includes
# * contributions from numerous individuals and organizations.
# * Please see the COPYING and CONTRIBUTORS files for details.
#
BEGIN {
  FS="@"
  ORS=""
  ENVIRON["SQUID_RELEASE_OLD"] = ENVIRON["SQUID_RELEASE"]-1
}
{
  for(i=1;i<=NF;i++) {
    if (i%2 == 0) {
      print ENVIRON[$i]
    } else {
      print $i
    }
  }
  print "\n"
}
