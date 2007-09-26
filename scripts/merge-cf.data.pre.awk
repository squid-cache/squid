#
# This script reassembles a split configuration file back into a cf.data.pre
# file.

BEGIN { dir = SRCDIR "conf/"; }
/^NAME: / {
    tag = $2;
    file=dir tag ".txt";
    $0 = "FILE_NOT_FOUND";
    getline < file;
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
