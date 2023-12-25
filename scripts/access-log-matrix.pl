#!/usr/local/bin/perl
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##
#
# access-log-matrix.pl
#
# Duane Wessels, Dec 1995
#
# Stdin is a Harvest access log (in the old, non-common logfile format!).
# The output is a matrix of hostnames and log entry types, plus totals.

while (<>) {
    chop;
    @F = split;
    $when = $F[0];
    $first = $when unless ($first);
    $last = $when;

    $what = pop @F;
    $size = pop @F;
    $host = pop @F;

    $HOSTS{$host}++;
    $HOSTS{'TOTAL'}++;

    if ($what eq 'TCP_DONE') {
        $TCP_DONE{$host}++;
        $TCP_DONE{'TOTAL'}++;
    } elsif ($what eq 'TCP_HIT') {
        $TCP_HIT{$host}++;
        $TCP_HIT{'TOTAL'}++;
    } elsif ($what eq 'TCP_MISS') {
        $TCP_MISS{$host}++;
        $TCP_MISS{'TOTAL'}++;
    } elsif ($what eq 'TCP_MISS_TTL') {
        $TCP_MISS_TTL{$host}++;
        $TCP_MISS_TTL{'TOTAL'}++;
    } elsif ($what eq 'UDP_HIT') {
        $UDP_HIT{$host}++;
        $UDP_HIT{'TOTAL'}++;
    } elsif ($what eq 'UDP_MISS') {
        $UDP_MISS{$host}++;
        $UDP_MISS{'TOTAL'}++;
    } else {
        $OTHER{$host}++;
        $OTHER{'TOTAL'}++;
    }
}

print  '       HOSTNAME: '. `hostname`;
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdat) = localtime($first);
printf "FIRST LOG ENTRY: %04d/%02d/%02d %.2d:%.2d:%.2d\n", $year+1900,$mon+1,$mday, $hour,$min,$sec;
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdat) = localtime($last);
printf " LAST LOG ENTRY: %04d/%02d/%02d %.2d:%.2d:%.2d\n", $year+1900,$mon+1,$mday, $hour,$min,$sec;
print "\n";

printf ("%25.25s %5s %5s %5s %5s %5s %5s %5s %5s\n",
    '',
    'TCP', 'TCP', 'TCP', 'TCP',
    'UDP', 'UDP', '',
    '');
printf ("%25.25s %5s %5s %5s %5s %5s %5s %5s %5s\n",
    'HOST',
    'HIT', 'MISS', 'TTL', 'DONE',
    'HIT', 'MISS', 'OTHER',
    'TOTAL');

printf ("%25.25s %5s %5s %5s %5s %5s %5s %5s %5s\n",
    '-'x25,
    '-'x5, '-'x5, '-'x5, '-'x5, '-'x5, '-'x5, '-'x5, '-'x5);

foreach $h (sort totalcmp keys %HOSTS) {
    next if ($h eq 'TOTAL');
    ($a1,$a2,$a3,$a4) = split('\.', $h);
    ($fqdn, @F) = gethostbyaddr(pack('C4',$a1,$a2,$a3,$a4),2);
    $fqdn = $h unless ($fqdn ne '');

    printf "%25.25s %5d %5d %5d %5d %5d %5d %5d %5d\n",
        $fqdn,
        $TCP_HIT{$h},
        $TCP_MISS{$h},
        $TCP_MISS_TTL{$h},
        $TCP_DONE{$h},
        $UDP_HIT{$h},
        $UDP_MISS{$h},
        $OTHER{$h},
        $HOSTS{$h};

}


printf ("%25.25s %5s %5s %5s %5s %5s %5s %5s %5s\n",
    '-'x25,
    '-'x5, '-'x5, '-'x5, '-'x5, '-'x5, '-'x5, '-'x5, '-'x5);
printf "%25.25s %5d %5d %5d %5d %5d %5d %5d %5d\n",
    'TOTAL',
    $TCP_HIT{'TOTAL'},
    $TCP_MISS{'TOTAL'},
    $TCP_MISS_TTL{'TOTAL'},
    $TCP_DONE{'TOTAL'},
    $UDP_HIT{'TOTAL'},
    $UDP_MISS{'TOTAL'},
    $OTHER{'TOTAL'},
    $HOSTS{'TOTAL'};

exit 0;

sub hostcmp {
    $a cmp $b
}

sub totalcmp {
    $HOSTS{$b} <=> $HOSTS{$a}
}
