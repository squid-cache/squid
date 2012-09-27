#!/usr/bin/perl -w
#
# A dummy SSL certificate validator helper that
# echos back all the SSL errors sent by Squid.
#

use warnings;
# TODO:
# use strict;

use Crypt::OpenSSL::X509;
use FileHandle;

my $LOGFILE = "/tmp/ssl_cert_valid.log";

open(LOG, ">>$LOGFILE") or die("Cannot open logfile $LOGFILE, stopped");
LOG->autoflush(1);

$|=1;
while (<>) {
    my $first_line = $_;
    my @line_args = split;

    if ($first_line =~ /^\s*$/) {
        next;
    }

    my $response;
    my $haserror = 0;
    my $code = $line_args[0];
    my $bodylen = $line_args[1];
    my $body = $line_args[2] . "\n";
    if ($bodylen =~ /\d+/) {
        my $readlen = length($body);
        my %certs = ();
        my @errors = ();
        my @responseErrors = ();

        while($readlen < $bodylen) {
	    my $t = <>;
            if (defined $t) {
                $body  = $body . $t;
                $readlen = length($body);
            }
        }

        print LOG "GOT ". "Code=".$code." $bodylen \n"; #.$body;
        parseRequest($body, \$hostname, \@errors, \%certs);
        print LOG " Parse result: \n";
        print LOG "\tFOUND host:".$hostname."\n";
        print LOG "\tFOUND ERRORS:";
        foreach $err(@errors) {
            print LOG "$err ,";
        }
        print LOG "\n";
        foreach $key (keys %certs) {
            ## Use "perldoc Crypt::OpenSSL::X509" for X509 available methods.
            print LOG "\tFOUND cert ".$key.": ".$certs{$key}->subject() . "\n";
        }

        #got the peer certificate ID. Assume that the peer certificate is the first one.
        my $peerCertId = (keys %certs)[0];

        # Echo back the errors: fill the responseErrors array  with the errors we read.
        foreach $err (@errors) {
            $haserror = 1;
            appendError (\@responseErrors, 
                         $err, #The error name
                         "Checked by Cert Validator", # An error reason
                         $peerCertId # The cert ID. We are always filling with the peer certificate.
                );
        }

        $response = createResponse(\@responseErrors);
        my $len = length($response);
        if ($haserror) {
            $response = "ERR ".$len." ".$response."\1";
        } else {
            $response = "OK ".$len." ".$response."\1";
        }
    } else {
        $response = "BH 0 \1";
    }

    print $response;
    print LOG ">> ".$response;
}
close(LOG);

sub trim
{
    my $s = shift;
    $s =~ s/^\s+//;
    $s =~ s/\s+$//;
    return $s;
}

sub appendError
{
    my ($errorArrays) = shift;
    my($errorName) = shift;
    my($errorReason) = shift;
    my($errorCert) = shift;
    push @$errorArrays, { "error_name" => $errorName, "error_reason" => $errorReason, "error_cert" => $errorCert};
}

sub createResponse
{
    my ($responseErrors) = shift;
    my $response="";
    my $i = 0;
    foreach $err (@$responseErrors) {
        $response=$response."error_name_".$i."=".$err->{"error_name"}."\n".
            "error_reason_".$i."=".$err->{"error_reason"}."\n".
            "error_cert_".$i."=".$err->{"error_cert"}."\n";
        $i++;
    }
    return $response;
}

sub parseRequest
{
    my($request)=shift;
    my $hostname = shift;
    my $errors = shift;
    my $certs = shift;
    while ($request !~ /^\s*$/) {
        $request = trim($request);
        if ($request =~ /^host=/) {
            my($vallen) = index($request, "\n");
            my $host = substr($request, 5, $vallen - 5);
            $$hostname = $host;
            $request =~ s/^host=.*\n//;
        }
        if ($request =~ /^errors=/) {
            my($vallen) = index($request, "\n");
            my $listerrors = substr($request, 7, $vallen - 7);
            @$errors = split /,/, $listerrors;
            $request =~ s/^errors=.*\n//;
        }
        elsif ($request =~ /^cert_(\d+)=/) {
            my $certId = "cert_".$1;
            my($vallen) = index($request, "-----END CERTIFICATE-----") + length("-----END CERTIFICATE-----");
            my $x509 = Crypt::OpenSSL::X509->new_from_string(substr($request, index($request, "-----BEGIN")));
            $certs->{$certId} = $x509;
            $request = substr($request, $vallen);
        }
        else {
            print LOG "ParseError on \"".$request."\"\n";
            $request = "";# finish processing....
        }
    }
}
