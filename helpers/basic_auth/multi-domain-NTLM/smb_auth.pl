#!/usr/bin/perl
# $Id: smb_auth.pl,v 1.5 2003/05/17 17:13:05 hno Exp $

#if you define this, debugging output will be printed to STDERR.
#$debug=1;

#to force using some DC for some domains, fill in this hash.
#the key is a regexp matched against the domain name
# the value is an array ref with PDC and BDC.
# the order the names are matched in is UNDEFINED.
#i.e.:
# %controllers = ( "domain" => ["pdc","bdc"]);

#%controllers = ( ".*" => ["pdcname","bdcname"]);

#define this if you wish to use a WINS server. If undefined, broadcast
# will be attempted.
#$wins_server="winsservername";

# Some servers (at least mine) really really want to be called by address.
# If this variable is defined, we'll ask nmblookup to do a reverse DNS on the
#  DC addresses. It might fail though, for instance because you have a crappy
#  DNS with no reverse zones or records. If it doesn't work, you'll have to
#  fall back to the %controllers hack.
$try_reverse_dns=1;

# Soem servers (at least mine) don't like to be called by their fully
#  qualified name. define this if you wish to call them ONLY by their
#  hostname.
$dont_use_fqdn=1;

#no more user-serviceable parts
use Authen::Smb;

#variables: 
# %pdc used to cache the domain -> pdc_ip values. IT NEVER EXPIRES!


$|=1;
while (<>) {
	chomp;
	if (! m;^(\S+)(/|%5c)(\S+)\s(\S+)$; ) { #parse the line
		print "ERR\n";
		next;
	}
	$domain=$1;
	$user=$3;
	$pass=$4;
	$domain =~ s/%([0-9a-f][0-9a-f])/pack("H2",$1)/gie;
        $user =~ s/%([0-9a-f][0-9a-f])/pack("H2",$1)/gie;
        $pass =~ s/%([0-9a-f][0-9a-f])/pack("H2",$1)/gie;
	print STDERR "domain: $domain, user: $user, pass=$pass\n" 
		if (defined ($debug));
	# check out that we know the PDC address
	if (!$pdc{$domain}) {
    ($pdc,$bdc)=&discover_dc($domain);
    if ($pdc) {
      $pdc{$domain}=$pdc;
      $bdc{$domain}=$bdc;
    }
	}
	$pdc=$pdc{$domain};
	$bdc=$bdc{$domain};
	if (!$pdc) {
		#a pdc was not found
		print "ERR\n";
		print STDERR "No PDC found\n" if (defined($debug));
		next;
	}

  print STDERR "querying '$pdc' and '$bdc' for user '$domain\\$user', ".
    "pass $pass\n" if (defined($debug));
  $result=Authen::Smb::authen($user,$pass,$pdc,$bdc,$domain);
  print STDERR "result is: $nt_results{$result} ($result)\n"
    if (defined($debug));
  if ($result == NTV_NO_ERROR) {
    print STDERR ("OK for user '$domain\\$user'\n") if (defined($debug));
    print ("OK\n");
  } else {
    print STDERR "Could not authenticate user '$domain\\$user'\n";
    print ("ERR\n");
  }
}

#why do Microsoft servers have to be so damn picky and convoluted?
sub discover_dc {
  my $domain = shift @_;
  my ($pdc, $bdc, $lookupstring, $datum);

  foreach (keys %controllers) {
    if ($domain =~ /$_/) {
      print STDERR "DCs forced by user: $_ => ".
        join(',',@{$controllers{$_}}).
        "\n" if (defined($debug));
      return @{$controllers{$_}};
    }
  }
  $lookupstring="nmblookup";
  $lookupstring.=" -R -U $wins_server" if (defined($wins_server));
  $lookupstring.=" -T" if (defined($try_reverse_dns));
  $lookupstring.=" '$domain#1c'";
  print STDERR "Discovering PDC: $lookupstring\n"
    if (defined($debug));
  #discover the PDC address
  open(PDC,"$lookupstring|");
  while (<PDC>) {
    print STDERR "response line: $_" if (defined($debug));
    if (m|(.*), (\d+\.\d+\.\d+\.\d+)|) {
      $datum=$1;
      print STDERR "matched $datum\n" if (defined($debug));
      if (defined($dont_use_fqdn) && $datum =~ /^([^.]+)\..*/) {
        $datum=$1;
        print STDERR "stripped domain name: $datum\n" if (defined($debug));
      }
    } elsif (m|^(\d+\.\d+\.\d+\.\d+)|) {
      $datum=$1;
    } else {
      #no data here, go to next line
      next;
    }
    if ($datum) {
      if ($pdc) {
        $bdc=$datum;
        print STDERR "BDC is $datum\n" if (defined($debug));
        last;
      }	else {
        $pdc=$datum;
        print STDERR "PDC is $datum\n" if (defined($debug));
      }
      last;
    }
  }
  close(PDC);
  return ($pdc,$bdc) if ($pdc);
  return 0;
}

