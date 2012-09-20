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
use File::Temp;
use strict;
use Time::Local;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;

$VERSION = 0.10;

@EXPORT      = qw(timestamp isodatetoepoch epochtoisodate addisodate printableisodate run_command system);       # Symbols to autoexport (:DEFAULT tag)

# This variable stores arbitrary data like created temporary files
my $INSTANCE;

sub new {
	my $proto = shift;
	my $class = ref($proto)  || $proto;
	my $self = {};
	
	bless $self, $class;
	
	my $options = CertNanny::Config->getInstance();
	
	$self->{OPTIONS}->{tmp_dir} = $options->get('path.tmpdir', 'FILE');
	$self->{OPTIONS}->{openssl_shell} = $options->get('cmd.openssl', 'FILE');
	return $self;
}

sub DESTROY
{
    my $self = shift;
    
    return unless (exists $self->{TMPFILE});

    foreach my $file (@{$self->{TMPFILE}}) {
	unlink $file;
    }
}

sub getInstance() {
	unless(defined $INSTANCE) {
		$INSTANCE = CertNanny::Util->new();
	}
	
	return $INSTANCE;
}

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
	CertNanny::Logging->debug("$output");
	return $? >> 8;
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
	shift;
    my $self     = CertNanny::Util->getInstance();
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
	shift;
    my $self     = CertNanny::Util->getInstance();
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
	shift;
    my $self = CertNanny::Util->getInstance();
    my %options = (
           CERTFORMAT => 'DER',
           @_,         # argument pair list
           );
    my %month = (
         Jan => 1, Feb => 2,  Mar => 3,  Apr => 4,
         May => 5, Jun => 6,  Jul => 7,  Aug => 8,
         Sep => 9, Oct => 10, Nov => 11, Dec => 12 );
    my $certinfo = {};
   
    

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

    $certinfo = $self->parsecertdata(\$fh);
    close $fh;
    unlink $outfile;

    ####
    # rewrite dates from human readable to ISO notation
    foreach my $var (qw(NotBefore NotAfter))
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

    # sanity checks
    foreach my $var (qw(Version SerialNumber SubjectName IssuerName NotBefore NotAfter CertificateFingerprint Modulus))
    {
	    if (! exists $certinfo->{$var})
	    {
	        CertNanny::Logging->error("getcertinfo(): Could not determine field '$var' from X.509 certificate");
	        return;
	    }
    }   
    
    return $certinfo;
}

sub getcsrinfo {
	shift;
	my $self = CertNanny::Util->getInstance();
	my %options = (
           CERTFORMAT => 'PEM',
           @_,         # argument pair list
           );
           
	 # sanity checks
    if (! (defined $options{CERTFILE} or defined $options{CERTDATA}))
    {
    	CertNanny::Logging->error("getcsrinfo(): No input data specified");
    	return;
    }
    
	if ((defined $options{CERTFILE} and defined $options{CERTDATA}))
    {
    	CertNanny::Logging->error("getcsrinfo(): Ambigous input data specified");
    	return;
    }
    
    my $outfile = $self->gettmpfile();
	my $openssl = $self->{OPTIONS}->{"openssl_shell"};
	my @input = ();
    if (defined $options{CERTFILE}) {
    	@input = ('-in', qq("$options{CERTFILE}"));
    }
    #C:\Users\tob130\Work\eclipse\CertNanny\agent\lib\state>openssl req -in capi.csr -inform PEM -modulus -subject -text
	my @cmd = (
		qq("$openssl"),
		'req',
		@input,
		'-inform',
		$options{CERTFORMAT},
		'-modulus',
		'-subject',
		'-text',
        '>',
        qq("$outfile")
	);
	
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
    
    my $csrinfo = $self->parsecertdata(\$fh);
    close $fh;
    unlink $outfile;
    
    # sanity checks
    foreach my $var (qw(Version SubjectName Modulus))
    {
	    if (! exists $csrinfo->{$var})
	    {
	        CertNanny::Logging->error("getcsrinfo(): Could not determine field '$var' from certificate signing request.	");
	        return;
	    }
    } 
    
    return $csrinfo;
}

sub parsecertdata {
	shift;
	my $self = CertNanny::Util->getInstance();
	my $fh = ${shift @_};
	my $certinfo = {};
	my $state = "";
    my @purposes;

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
           'Modulus' => 'Modulus',
           );
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
    
	    if (/(Version:|subject=|issuer=|serial=|notBefore=|notAfter=|SHA1 Fingerprint=|Modulus=)\s*(.*)/)
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
    
	# compose key usage text field
    $certinfo->{KeyUsage} = join(", ", @purposes);
    
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
    foreach my $var (qw(SubjectName IssuerName))
    {
    $certinfo->{$var} = join(", ", 
                 reverse split(/[\/,]\s*/, $certinfo->{$var}));
    # remove trailing garbage
    $certinfo->{$var} =~ s/[, ]+$//;
    }
    
    return $certinfo;
}


# NOTE: this is UNSAFE (beware of race conditions). We cannot use a file
# handle here because we are calling external programs to use these
# temporary files.
sub gettmpfile
{
	shift;
    my $self = CertNanny::Util->getInstance();

    my $tmpdir = $self->{OPTIONS}->{tmp_dir};
    #if (! defined $tmpdir);
    my $template = File::Spec->catfile($tmpdir,
                       "cbXXXXXX");

    my $tmpfile =  mktemp($template);
    
    push (@{$self->{TMPFILE}}, $tmpfile);
    return ($tmpfile);
}

sub staticEngine     {
    shift;
    my $self = CertNanny::Util->getInstance();
    my $engine_id = shift;
    
    unless(defined $engine_id) {
        CertNanny::Logging->error("No engine_id passed to staticEngine() as first argument!");
        die;
    }
    
    my @cmd;
    my $openssl = $self->{OPTIONS}->{openssl_shell};
    push(@cmd, $openssl);
    push(@cmd, 'engine');
    $engine_id =~ s/[^A-Za-z0-9]*//g;
    push(@cmd, $engine_id);
    push(@cmd, '-t');
    
    my $cmd = join(' ', @cmd);
    CertNanny::Logging->debug("Execute: $cmd\n");
    my $output = "";
    open FH, "$cmd |" or die "Couldn't execute $cmd: $!\n"; 
	while(defined(my $line = <FH>)) {
	    chomp($line);
	    $output .= $line;
	}
	close FH;
	CertNanny::Logging->debug("Output is $output\n");
	return $output=~m/\(cs\).*\[ available \]/s;
}

sub writeOpenSSLConfig {
    shift;
    my $self = CertNanny::Util->getInstance();

    my $config_hash = shift;
    my $config_filename = shift || $self->gettmpfile();
    open(my $configfile, ">", $config_filename) or die "Cannot write $config_filename";
	
	if(defined $config_hash->{openssl_conf}) {
	    print $configfile "openssl_conf=$config_hash->{openssl_conf}\n";
	    delete $config_hash->{openssl_conf};
	}
		
	foreach my $section ( keys %{$config_hash}) {
		print $configfile "[$section]\n";
        foreach my $entry_hash (@{$config_hash->{$section}}) {
            foreach my $key (keys(%{$entry_hash})) {
                my $value = $entry_hash->{$key};
            	if(-e $value and $^O eq "MSWin32") {
    	        	#on Windows paths have a backslash, so in the string it is \\.
    	        	#In the config it must keep the doubled backslash so the actual 
    	        	#string would contain \\\\. Yes this is ridiculous...
    	        	$value =~ s#/#\\#g;
    				$value =~ s/\\/\\\\/g;        		
            	}
                print $configfile "$key=$value\n";
            }
        }
    }
    
    close $configfile;
	return $config_filename;
}

sub getDefaultOpenSSLConfig {
    shift;
    my $self = CertNanny::Util->getInstance();
    
    
    
    my $default_config = {
        openssl_conf => "openssl_def",
        openssl_def => [
            {engines => "engine_section"},
        ],
        
        engine_section => []
    };
    
    return $default_config;
}

1;

=head1 NAME

CertNanny::Util - Utility functions for CertNanny.

=head1 SYNOPSIS

    CertNanny::Util->getcertinfo();
    CertNanny::Util->write_file();
    ...

=head1 DESCRIPTION

Provides utility functions for CertNanny. Some functions should be called without any object/instance, some are called via class or instance. On functions that are called via class/instance it does not matter which is used, there is always a singleton instance which will be used.

=head1 FUNCTIONS

=head2 Function List

=over 4

C<new()>

C<getInstance()>

C<run_command()>

C<timestamp()>

C<isodatetoepoch()>

C<expanddate()>

C<printableisodate()>

C<read_file()>

C<write_file()>

C<getcertinfo()>

C<getcsrinfo()>

C<parsecertdata()>

C<gettmpfile()>

C<staticEngine()>

C<writeOpenSSLConfig()>

C<getDefaultOpenSSLConfig()>

=back

=head2 Function Descriptions

=over 4

=item new()

Should not be called directly. Will be uncallable in a future version. Instead call C<getInstance()>. Normally you do not need to call for any instance at all. Just make calls like CertNanny::Util->functionname().

=item getInstance()

Returns a singleton instance of this class. Can be called, but normally does not need to be.

=item run_command($command)

Called globally, do not call it via class or instance. Runs a command  and returns its exit code. Prints the output to STDOUT (in CertNanny context this is most likely the logfile).

=over 4

=item $command

The command to execute

=back

=item timestamp()

Returns the current time in ISO (UTC) timestamp format. Called globally.

=item isodatetoepoch($time)

Convert an ISO date to a Unix timestamp (seconds since the Epoch). Returns Unix timestamp.

=over 4

=item $time

Time in ISO format (YYYYMMDDHHMMSS)

=back

=item expanddate($time)

Expand time format controls (subset as specified by date(1)). Always uses current time.

=over 4

=item %y last two digits of year (00..99)

=item %Y year (1970...)

=item %m month (01..12)

=item %d day of month (01..31)

=item %H hour (00..23)

=item %M minute (00..59)

=item %S second (00..59)

=back

=over 4

=item $time

Format string of expected time format.

=back

=item printableisodate($isodate)

Return a printable represantation of a compacted ISO date.

=over 4

=item $isodate

ISO Date, format YYYYMMDDHHMMSS

=back

=item read_file($filename)
Read (slurp) file from disk.

=over 4

=item $filename

The filename to read.

=back

=item write_file(%args)

Write file to disk. Returns false if file already existss unless $args{FORCE} is set. In this case the method will overwrite the specified file.

=over 4

=item $args{FILENAME}

The name of the file to write.

=item $args{CONTENT}

The data to write.

=item $args{FORCE}

If set, will overwrite existing file.

=back

=item getcertinfo(%args)

Parse DER/PEM encoded X.509v3 certificate and return certificate information in a hash ref.
Prerequisites: requires external openssl executable.
Returns hash reference containing the certificate infomration or undef if conflicts occur.
Returned hash reference contains the following values:

=over 4

=item Version => <cert version, optional> Values: 2, 3

=item SubjectName => <cert subject common name>

=item IssuerName => <cert issuer common name>

=item SerialNumber => <cert serial number> Format: xx:xx:xx... (hex, upper case)

=item Modulus => <cert modulus> Format: hex

=item NotBefore => <cert validity> Format: YYYYDDMMHHMMSS

=item NotAfter  => <cert validity> Format: YYYYDDMMHHMMSS

=item PublicKey => <cert public key> Format: Base64 encoded (PEM)

=item Certificate => <certifcate> Format: Base64 encoded (PEM)

=item BasicConstraints => <cert basic constraints> Text (free style)

=item KeyUsage => <cert key usage> Format: Text (free style)

=item CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex, upper case)

=back

optional:

=over 4

=item SubjectAlternativeName => <cert alternative name>
 
=item IssuerAlternativeName => <issuer alternative name>

=item SubjectKeyIdentifier => <X509v3 Subject Key Identifier>

=item AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>

=item CRLDistributionPoints => <X509v3 CRL Distribution Points>

=back

=over 4

=item $args{CERTDATA}

Directly contains certificate data. Conflicts with $args{CERTFILE}.

=item $args{CERTFILE}

Filename to a certificate. Conflicts with $args{CERTDATA}.

=item $args{CERTFORMAT}

Optional argument for data format. Options are all formats understood by OpenSSL (currently: PEM/DER). Defaults to DER.

=back

=item getcsrinfo()

Format is the same a with C<getcertinfo()> but does not provide all the information since values like NotAfter are not set until issuance.

=item parsecertdata($fh)

Internal function that uses openssl output to retrieve csr/cert information. Can be used externally, but is not intended for use and only works with specific params.

=over 4

=item $fh

Filehandle to the output that should be parsed. See C<getcertinfo> and C<getcsrinfo> for usage exmaples.

=back

=item gettmpfile()

Returns filename for a temporary file. All requested files get deleted automatically upon destruction of the object.
NOTE: this is UNSAFE (beware of race conditions). We cannot use a file handle here because we are calling external programs to use these temporary files.

=item staticEngine($engine_id)

Checks whether the engine was compiled into OpenSSL statically by checking if it is available to OpenSSL. This will also report true if the engine is already made available dynamically.
Returns true if the engine is available, false otherwise.

=over 4

=item $engine_id

The engine_id which should be checked.

=back

=item writeOpenSSLConfig($config_hash, $config_filename)

Writes an OpenSSL configuration file either to $config_filename or to a temporary file. Returns filename of configuration file.

=over 4

=item $config_hash

Configuration hash reference. This hash reference requires a special structure: It has to contain multiple hash references. The key of each of them is the section name for the OpenSSL configuration. Inside it is another hash which contains key => value pairs that are entered as key=value in the OpenSSL configuration.
For example, you pass:
 
{section_name}->{key_name}=value
 
This will lead to:

[section_name]
    
key_name=value


=item $config_filename

Optional string that contains the desired filename. If none is passed then a temporary one is created. The filename is always returned, regardless of this setting. 

=back

=item getDefaultOpenSSLConfig()

Returns an OpenSSL default configuration hash. For the of the hash syntax see C<writeOpenSSLConfig()>. It contains an out-of-section default value openssl_conf=openssl_def denoting the OpenSSL section used as a starting point and contains a default engines=engine_section inside it.