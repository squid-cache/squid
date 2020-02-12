## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# This script reassembles a split configuration file back into a cf.data.pre
# file.

/^NAME: / {
    tag = $2;
    dir = FILENAME;
    gsub(/[^/\\]*$/, "", dir);
    file=dir tag ".txt";
    $0 = "FILE_NOT_FOUND";
    if (!getline < file)
	$0 = "FILE_NOT_FOUND";
    if (/^FILE_NOT_FOUND/) {
	print "ERROR: '" file "' not found!" > "/dev/stderr";
	exit 1;
    }
    print;
    while (getline < file) {
    	print;
    }
    next;
}
{print}
