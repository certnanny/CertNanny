#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
#
# DBCA::Util
#
# 2002-11-11 Martin Bartosch; Cynops GmbH <m.bartosch@cynops.de>
#

package CertNanny::Util;

use base qw(Exporter);

use IO::File;
use File::Glob qw(:globally :nocase);
use File::Spec;
use strict;
use Time::Local;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;

$VERSION = 0.10;

@EXPORT      = qw(timestamp isodatetoepoch epochtoisodate addisodate printableisodate run_command system);       # Symbols to autoexport (:DEFAULT tag)

#sub system {
#	die "do not use system() in CertNanny, it is broken when CertNanny is used as a Windows service";
#}

sub run_command
{
	my $command = shift;
	
	open my $PROGRAM, "$command|" or die "could not execute $command";
	my $output = do {
		local $/;
		<$PROGRAM>;
	};
	close($PROGRAM);
	print $output; #TODO Logging
	return $?;
}

# returns current time as ISO timestamp (UTC)
# format: yyyymmddhhmmss
sub timestamp
{
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) =
	gmtime(time);
    return sprintf("%04d%02d%02d%02d%02d%02d", 
		   $year + 1900,
		   $mon + 1,
		   $mday,
		   $hour,
		   $min,
		   $sec);
}


# convert ISO date to Unix timestamp (seconds since the Epoch)
# arg: ISO date (YYYYMMDDHHMMSS)
# return: Epoch (seconds) or undef on error
sub isodatetoepoch
{
    my $isodate = shift;

    return unless defined $isodate;

    if (my ($year, $mon, $mday, $hours, $min, $sec) = ($isodate =~ /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/))
    {
	$mon -= 1;
	$year -= 1900;
	return timegm($sec, $min, $hours, $mday, $mon, $year);
    }
    return;
}

# convert Unix Epoch to ISO Date
# arg: Epoch seconds
# return: ISO Date (YYYYMMDDHHMMSS)
sub epochtoisodate
{
    my $epoch = shift;
    my ($seconds, $minutes, $hours, $day_of_month, $month, $year,
	$wday, $yday, $isdst) = gmtime($epoch);
    return sprintf("%04d%02d%02d%02d%02d%02d", 
		   $year + 1900, 
		   $month + 1, 
		   $day_of_month,
		   $hours,
		   $minutes,
		   $seconds);
}



# expand time format controls (subset as specified by date(1))
# %y last two digits of year (00..99)
# %Y year (1970...)
# %m month (01..12)
# %d day of month (01..31)
# %H hour (00..23)
# %M minute (00..59)
# %S second (00..59)
sub expanddate
{
    my $arg = shift;

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
	localtime(time);

    $arg =~ s/%y/sprintf("%02d", ($year + 1900) % 100)/ge;
    $arg =~ s/%Y/$year + 1900/ge;
    $arg =~ s/%m/sprintf("%02d", $mon + 1)/ge;
    $arg =~ s/%d/sprintf("%02d", $mday)/ge;
    $arg =~ s/%H/sprintf("%02d", $hour)/ge;
    $arg =~ s/%M/sprintf("%02d", $min)/ge;
    $arg =~ s/%S/sprintf("%02d", $sec)/ge;

    $arg;
}


# return a printable represantation of a compacted ISO date
# arg: ISO Date, format YYYYMMDDHHMMSS
sub printableisodate
{
    my $arg = shift;
    my @date = ($arg =~ /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    sprintf("%04d-%02d-%02d %02d:%02d:%02d", @date);
}


# read (slurp) file from disk
# Example: $self->read_file($filename);
sub read_file
{
    my $self     = shift;
    my $filename = shift;

    if (! -e $filename)
    {
	CertNanny::Logging->error("read_file(): file does not exist");
	return;
    }

    if (! -r $filename)
    {
	CertNanny::Logging->error("read_file(): file is not readable");
	return;
    }

    my $result = do {
	open my $fh, '<', $filename;
	if (! $fh) {
	    CertNanny::Logging->error("read_file(): file open failed");
	    return;
	}
	binmode $fh;
	local $/;
	<$fh>;
    };

    return $result;
}


# write file to disk
#
# Example: $self->write_file(FILENAME => $filename, CONTENT => $data);
#
# The method will return false if the file already exists unless
# the optional argument FORCE is set. In this case the method will overwrite
# the specified file.
# 
# Example: $self->write_file(FILENAME => $filename, CONTENT => $data, FORCE => 1);
# 

sub write_file
{
    my $self     = shift;
    my $keys     = { @_ };
    my $filename = $keys->{FILENAME};
    my $content  = $keys->{CONTENT};

    if (! defined $filename)
    {
	CertNanny::Logging->error("write_file(): no filename specified");
	return;
    }

    if (! defined $content)
    {
	CertNanny::Logging->error("write_file(): no content specified");
	return;
    }

    if ((-e $filename) && (! $keys->{FORCE}))
    {
	CertNanny::Logging->error("write_file(): file already exists");
	return;
    }


    my $mode = O_WRONLY;
    if (! -e $filename) {
	$mode |= O_EXCL | O_CREAT;
    }

    my $fh;
    if (not sysopen($fh, $filename, $mode))
    {
	CertNanny::Logging->error("write_file(): file open failed");
	return;
    }
    binmode $fh;
    print {$fh} $content;
    close $fh;

    return 1;
}

# parse DER encoded X.509v3 certificate and return certificate information 
# in a hash ref
# Prerequisites: requires external openssl executable
# options: hash
#   CERTDATA => directly contains certificate data
#   CERTFILE => cert file to parse
#   CERTFORMAT => PEM|DER (default: DER)
#
# return: hash reference containing the certificate information
# returns undef if both CERTDATA and CERTFILE are specified or on error
#
# Returned hash reference contains the following values:
# Version => <cert version, optional> Values: 2, 3
# SubjectName => <cert subject common name>
# IssuerName => <cert issuer common name>
# SerialNumber => <cert serial number> Format: xx:xx:xx... (hex, upper case)
# NotBefore => <cert validity> Format: YYYYDDMMHHMMSS
# NotAfter  => <cert validity> Format: YYYYDDMMHHMMSS
# PublicKey => <cert public key> Format: Base64 encoded (PEM)
# Certificate => <certifcate> Format: Base64 encoded (PEM)
# BasicConstraints => <cert basic constraints> Text (free style)
# KeyUsage => <cert key usage> Format: Text (free style)
# CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex, 
#   upper case)
#
# optional:
# SubjectAlternativeName => <cert alternative name> 
# IssuerAlternativeName => <issuer alternative name>
# SubjectKeyIdentifier => <X509v3 Subject Key Identifier>
# AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>
# CRLDistributionPoints => <X509v3 CRL Distribution Points>
# 
sub getcertinfo
{
    my $self = shift;
    my %options = (
           CERTFORMAT => 'DER',
           @_,         # argument pair list
           );
    

    my $certinfo = {};
    my %month = (
         Jan => 1, Feb => 2,  Mar => 3,  Apr => 4,
         May => 5, Jun => 6,  Jul => 7,  Aug => 8,
         Sep => 9, Oct => 10, Nov => 11, Dec => 12 );

    my %mapping = (
           'serial' => 'SerialNumber',
           'subject' => 'SubjectName',
           'issuer' => 'IssuerName',
           'notBefore' => 'NotBefore',
           'notAfter' => 'NotAfter',
           'SHA1 Fingerprint' => 'CertificateFingerprint',
           'PUBLIC KEY' => 'PublicKey',
           'CERTIFICATE' => 'Certificate',
           'ISSUERALTNAME' => 'IssuerAlternativeName',
           'SUBJECTALTNAME' => 'SubjectAlternativeName',
           'BASICCONSTRAINTS' => 'BasicConstraints',
           'SUBJECTKEYIDENTIFIER' => 'SubjectKeyIdentifier',
           'AUTHORITYKEYIDENTIFIER' => 'AuthorityKeyIdentifier',
           'CRLDISTRIBUTIONPOINTS' => 'CRLDistributionPoints',
           );
    

    # sanity checks
    if (! (defined $options{CERTFILE} or defined $options{CERTDATA}))
    {
    CertNanny::Logging->error("getcertinfo(): No input data specified");
    return;
    }
    if ((defined $options{CERTFILE} and defined $options{CERTDATA}))
    {
    CertNanny::Logging->error("getcertinfo(): Ambigous input data specified");
    return;
    }
    
    my $outfile = $self->gettmpfile();
    my $openssl = $self->{OPTIONS}->{openssl_shell};

    my $inform = $options{CERTFORMAT};

    my @input = ();
    if (defined $options{CERTFILE}) {
    @input = ('-in', qq("$options{CERTFILE}"));
    }

    # export certificate
    my @cmd = (qq("$openssl"),
           'x509',
           @input,
           '-inform',
           $inform,
           '-text',
           '-subject',
           '-issuer',
           '-serial',
           '-email',
           '-startdate',
           '-enddate',
           '-modulus',
           '-fingerprint','-sha1',
           '-pubkey',
           '-purpose',
           '>',
           qq("$outfile"));

    CertNanny::Logging->log({ MSG => "Execute: " . join(" ", @cmd),
         PRIO => 'debug' });    
    my $fh;
    if (!open $fh, "|" . join(' ', @cmd))
    {
        CertNanny::Logging->error("getcertinfo(): open error");
    unlink $outfile;
    return;

    }

    binmode $fh;
    if (defined $options{CERTDATA}) {
    print $fh $options{CERTDATA};
    }

    close $fh;
    
    if ($? != 0)
    {
        CertNanny::Logging->error("getcertinfo(): Error ASN.1 decoding certificate");
    unlink $outfile;
    return;
    }

    open $fh, '<', $outfile;
    if (! $fh)
    {
        CertNanny::Logging->error("getcertinfo(): Error analysing ASN.1 decoded certificate");
    unlink $outfile;
        return;
    }

    my $state = "";
    my @purposes;
    while (<$fh>)
    {
    chomp;
    tr/\r\n//d;

    $state = "PURPOSE" if (/^Certificate purposes:/);
    $state = "PUBLIC KEY" if (/^-----BEGIN PUBLIC KEY-----/);
    $state = "CERTIFICATE" if (/^-----BEGIN CERTIFICATE-----/);
    $state = "SUBJECTALTNAME" if (/X509v3 Subject Alternative Name:/);
    $state = "ISSUERALTNAME" if (/X509v3 Issuer Alternative Name:/);
    $state = "BASICCONSTRAINTS" if (/X509v3 Basic Constraints:/);
    $state = "SUBJECTKEYIDENTIFIER" if (/X509v3 Subject Key Identifier:/);
    $state = "AUTHORITYKEYIDENTIFIER" if (/X509v3 Authority Key Identifier:/);
    $state = "CRLDISTRIBUTIONPOINTS" if (/X509v3 CRL Distribution Points:/);

    if ($state eq "PURPOSE")
    {
        my ($purpose, $bool) = (/(.*?)\s*:\s*(Yes|No)/);
        next unless defined $purpose;
        push (@purposes, $purpose) if ($bool eq "Yes");

        # NOTE: state machine will leave PURPOSE state on the assumption
        # that 'OCSP helper CA' is the last cert purpose printed out
        # by OpenCA. It would be best to have OpenSSL print out
        # purpose information, just to be sure.
        $state = "" if (/^OCSP helper CA :/);
        next;
    }
    # Base64 encoded sections
    if ($state =~ /^(PUBLIC KEY|CERTIFICATE)$/)
    {
        my $key = $state;
        $key = $mapping{$key} if (exists $mapping{$key});

        $certinfo->{$key} .= "\n" if (exists $certinfo->{$key});
        $certinfo->{$key} .= $_ unless (/^-----/);

        $state = "" if (/^-----END $state-----/);
        next;
    }

    # X.509v3 extension one-liners
    if ($state =~ /^(SUBJECTALTNAME|ISSUERALTNAME|BASICCONSTRAINTS|SUBJECTKEYIDENTIFIER|AUTHORITYKEYIDENTIFIER|CRLDISTRIBUTIONPOINTS)$/)
    {
        next if (/X509v3 .*:/);
        my $key = $state;
        $key = $mapping{$key} if (exists $mapping{$key});
        # remove trailing and leading whitespace
        s/^\s*//;
        s/\s*$//;
        $certinfo->{$key} = $_ unless ($_ eq "<EMPTY>");
        
        # alternative line consists of only one line 
        $state = "";
        next;
    }
    
    if (/(Version:|subject=|issuer=|serial=|notBefore=|notAfter=|SHA1 Fingerprint=)\s*(.*)/)
    {
        my $key = $1;
        my $value = $2;
        # remove trailing garbage
        $key =~ s/[ :=]+$//;
        # apply key mapping
        $key = $mapping{$key} if (exists $mapping{$key});

        # store value
        $certinfo->{$key} = $value;
    }
    }
    close $fh;
    unlink $outfile;

    # compose key usage text field
    $certinfo->{KeyUsage} = join(", ", @purposes);
    
    # sanity checks
    foreach my $var qw(Version SerialNumber SubjectName IssuerName NotBefore NotAfter CertificateFingerprint)
    {
    if (! exists $certinfo->{$var})
    {
        CertNanny::Logging->error("getcertinfo(): Could not determine field '$var' from X.509 certificate");
        return;
    }
    }


    ####
    # Postprocessing, rewrite certain fields

    ####
    # serial number
    # extract hex certificate serial number (only required for -text format)
    #$certinfo->{SerialNumber} =~ s/.*\(0x(.*)\)/$1/;

    # store decimal serial number
    #$certinfo->{Serial} = hex($certinfo->{SerialNumber});

    # pad with a leading zero if length is odd
    if (length($certinfo->{SerialNumber}) % 2)
    {
    $certinfo->{SerialNumber} = '0' . $certinfo->{SerialNumber};
    }
    # convert to upcase and insert colons to separate hex bytes
    $certinfo->{SerialNumber} = uc($certinfo->{SerialNumber});
    $certinfo->{SerialNumber} =~ s/(..)/$1:/g;
    $certinfo->{SerialNumber} =~ s/:$//;

    ####
    # get certificate version
    $certinfo->{Version} =~ s/(\d+).*/$1/;

    ####
    # reverse DN order returned by OpenSSL
    foreach my $var qw(SubjectName IssuerName)
    {
    $certinfo->{$var} = join(", ", 
                 reverse split(/[\/,]\s*/, $certinfo->{$var}));
    # remove trailing garbage
    $certinfo->{$var} =~ s/[, ]+$//;
    }

    ####
    # rewrite dates from human readable to ISO notation
    foreach my $var qw(NotBefore NotAfter)
    {
    my ($mon, $day, $hh, $mm, $ss, $year, $tz) =
        $certinfo->{$var} =~ /(\S+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)\s*(\S*)/;
    my $dmon = $month{$mon};
    if (! defined $dmon)
    {
        CertNanny::Logging->error("getcertinfo(): could not parse month '$mon' in date '$certinfo->{$var}' returned by OpenSSL");
        return;
    }
    
    $certinfo->{$var} = sprintf("%04d%02d%02d%02d%02d%02d",
                    $year, $dmon, $day, $hh, $mm, $ss);
    }
    
    return $certinfo;
}

# NOTE: this is UNSAFE (beware of race conditions). We cannot use a file
# handle here because we are calling external programs to use these
# temporary files.
sub gettmpfile
{
    my $self = shift;

    my $tmpdir = $self->{OPTIONS}->{tmp_dir};
    #if (! defined $tmpdir);
    my $template = File::Spec->catfile($tmpdir,
                       "cbXXXXXX");

    my $tmpfile =  mktemp($template);
    
    push (@{$self->{TMPFILE}}, $tmpfile);
    return ($tmpfile);
}

1;
