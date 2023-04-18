#!/usr/bin/perl

# sweep over the squid repository, looking for patterns of
# c standard library header files that have a c++ equivalent,
# replacing these includes with the sequivalent standard c++ header.


# header files to consider (without the .h extension)
# stdbool, complex, tgmath, iso646, and stdalign are deprecated in c++20
# and not used in squid
@headers=qw(
assert
ctype
errno
fenv
float
inttypes
limits
locale
math
setjmp
signal
stdarg
stddef
stdint
stdio
stdlib
string
time
uchar
wchar
wctype
);

foreach $header (@headers) {
    $headerguard="HAVE_".uc($header)."_H";
    print "headerguard: $headerguard\n";
    @files=`git grep -lF $headerguard -- *.cc *.h *.cci`;
    @files=grep (!/^compat/, @files);
    chomp(@files);
    foreach $file (@files) {
        print "file: $file\n";
        $pre="";
        open(FILE,"<", $file);
        read(FILE, $pre ,1000000) || die("read error on file $file: $!");
        close(FILE) || die("close error on file $file: $!");
        $post = $pre;
        $post =~ s/#if(def)? $headerguard\n#include <$header.h>(.*)\n#endif/#include <c$header>$2/m;
        if ($pre eq $post) {
            print "$header: $file no differ\n";
        }
        # now write the output
        open(FILE, ">", $file);
        print FILE "$post" || die("write error on file $file: $!");;
        close(FILE);
    }
}
