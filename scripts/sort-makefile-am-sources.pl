#!/usr/bin/perl

while (<>) {
    if (/^(\S+_SOURCES)\s*=\s*\\$/) {
        print "$1 = \\\n";
    } else {
        print;
        next;
    }
    # accumulate files and prep for sorting
    my %files;
    while (<>) {
        chop;
        /\s*(tests\/stub_|tests\/test)?(\S+)(\s+\\\s*)?$/ || die "no parse";
        $files{"$2.$1"}="$1$2";
        if (! /\\$/ ) {  # last line in the list
            &print_files(\%files);
            last;
        }
    }
}

# arg is hash ref, print values in order of key
sub print_files
{
    my %files=%{$_[0]};
    my @q=();
    foreach my $k (sort {lc $a cmp lc $b} keys %files) {
        push @q, "\t".$files{$k};
    }
    print join(" \\\n", @q)."\n";
}
