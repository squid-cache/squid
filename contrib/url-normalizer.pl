#!/usr/local/bin/perl -Tw

# From:    Markus Gyger <mgyger@itr.ch>
#
# I'd like to see a redirector which "normalizes" URLs to have
# a higher chance to get a hit. I didn't see such a redirector,
# so I thought I would send my little attempt. However, I have
# no real idea how much CPU time it needs using the LWP modules,
# but it seems to work.

require 5.003;
use strict;
use URI::URL;

$| = 1;  # force a flush after every print on STDOUT

my ($url, $addr, $fqdn, $ident, $method);

while (<>) {
    ($url, $addr, $fqdn, $ident, $method) = m:(\S*) (\S*)/(\S*) (\S*) (\S*):;

    # "normalize" URL
    $url = url $url;                    # also removes default port number
    $url->host(lc $url->host);          # map host name to lower case
    my $epath = $url->epath;
    $epath =~ s/%7e/~/ig;               # unescape ~
    $epath =~ s/(%[\da-f]{2})/\U$1/ig;  # capitalize escape digits
    if ($url->scheme =~ /^(http|ftp)$/) {
	$epath =~ s:/\./:/:g;           # safe?
	$epath =~ s://:/:g;             # safe?
    }
    $url->epath($epath);


    # ...


} continue {
    print "$url $addr/$fqdn $ident $method\n"
}


BEGIN {
    unless (URI::URL::implementor('cache_object')) {
	package cache_object;
	@cache_object::ISA = (URI::URL::implementor());
	URI::URL::implementor('cache_object', 'cache_object');

	sub default_port { 3128 }
    }
}
