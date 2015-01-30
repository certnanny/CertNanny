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
use strict;

use IO::File;
use File::Glob qw(:globally :nocase);
use File::Spec;
use File::Temp;

use Time::Local;

use MIME::Base64;

use Data::Dumper;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;

@EXPORT = qw(runCommand timeStamp isoDateToEpoch epochToIsoDate 
             expandDate printableIsoDate readFile writeFile getCertSHA1
             getCertFormat getCertInfoHash getCSRInfoHash parseCertData 
             getTmpFile staticEngine encodeBMPString writeOpenSSLConfig 
             getDefaultOpenSSLConfig backoffTime getMacAddresses 
             fetchFileList callOpenSSL);    # Symbols to autoexport (:DEFAULT tag)

# This variable stores arbitrary data like created temporary files
my $INSTANCE;


sub getInstance() {
  $INSTANCE ||= (shift)->new(@_);

  # If Configuration is not present, we are still in initialisation phase
  if (!defined $INSTANCE->{CONFIG}) {
    shift;
    my %args = (@_);
    $INSTANCE->{CONFIG} = $args{CONFIG};
  }
  return $INSTANCE;
}


sub new {
  if (!defined $INSTANCE) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};
    my %args  = (@_);    # argument pair list

    bless $self, $class;
    $INSTANCE = $self;
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  my $self = shift;

  return unless (exists $self->{TMPFILE});

  foreach my $file (@{$self->{TMPFILE}}) {
    unlink $file;
  }
} ## end sub DESTROY


sub hidePin() {
  my $self    = (shift)->getInstance();
  my @cmd = @_;
  
  for (my $ii = 0; $ii < $#cmd; $ii++) {
    $cmd[$ii + 1] = "*HIDDEN*" if ($cmd[$ii] =~ /(-pw|-target_pw|-storepass|-keypass|-srcstorepass|-deststorepass|-srckeypass|-destkeypass)/);
    $cmd[$ii] =~ s/Login=\S+/Login=*HIDDEN*/;
  }
  my $commando = join(' ', @cmd);
  
  return $commando;
}


sub runCommand {
  my $self    = (shift)->getInstance();
  my $cmd     = shift;

  my %args = (WANTOUT => 0,
              HIDEPWD => 0,
              @_);                 # argument pair list
               
  my @cmdarr;
  if (ref($cmd) eq 'ARRAY') {
    @cmdarr = @$cmd;
  } else {
    push(@cmdarr, $cmd);
  }
  my $logCmd = $args{HIDEPWD} ? $self->hidePin(@cmdarr) : join(' ' , @cmdarr);

  CertNanny::Logging->debug("Execute: $logCmd");

  open my $PROGRAM, join(' ' , @cmdarr) . "|" or die "could not execute $logCmd";
  my ($output, @outputArr);
  
  if (wantarray()) {
    @outputArr = do {
      <$PROGRAM>;
    };
    close($PROGRAM);
    #CertNanny::Logging->debug("@outputArr") if (@outputArr);
  } else {
    $output = do {
      local $/;
      <$PROGRAM>;
    };
    close($PROGRAM);
    
    if (($output =~ m/\A [[:ascii:]]* \Z/xms)) {
     	#CertNanny::Logging->debug("$output") if ($output);
    } else {
      #CertNanny::Logging->debug("---Binary Data---") if ($output);
    }
  }
    
  if ($args{WANTOUT}) {
    if (wantarray()) {
      return @outputArr;
    } else {
      return $output;
    }
  } else {
    return $? >> 8;
  }
} ## end sub runCommand


sub timeStamp {
  # returns current time as ISO timestamp (UTC)
  # format: yyyymmddhhmmss
  my $self = (shift)->getInstance();

  my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday) = gmtime(time);
  return sprintf("%04d%02d%02d%02d%02d%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}


sub isoDateToEpoch {
  # convert ISO date to Unix timestamp (seconds since the Epoch)
  # arg: ISO date (YYYYMMDDHHMMSS)
  # return: Epoch (seconds) or undef on error
  my $self = (shift)->getInstance();
  my $isodate     = shift;
  my $isLocalTime = shift;

  return undef unless defined $isodate;
  if (!defined $isLocalTime) {
    if (my ($year, $mon, $mday, $hours, $min, $sec) = ($isodate =~ /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/)) {
      $mon  -= 1;
      $year -= 1900;

      return timegm($sec, $min, $hours, $mday, $mon, $year);
    }
  } else {
    if (my ($year, $mon, $mday, $hours, $min, $sec) = ($isodate =~ /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/)) {
      $mon  -= 1;
      $year -= 1900;

      return timelocal($sec, $min, $hours, $mday, $mon, $year);
    }
  }

  return undef;
} ## end sub isoDateToEpoch


sub epochToIsoDate {
  # convert Unix Epoch to ISO Date
  # arg: Epoch seconds , use localtime flag
  # return: ISO Date (YYYYMMDDHHMMSS)
  my $self = (shift)->getInstance();
  my $epoch       = shift;
  my $isLocalTime = shift;

  if (!defined $isLocalTime) {
    my ($seconds, $minutes, $hours, $day_of_month, $month, $year, $wday, $yday, $isdst) = gmtime($epoch);
    return sprintf("%04d%02d%02d%02d%02d%02d", $year + 1900, $month + 1, $day_of_month, $hours, $minutes, $seconds);

  } else {
    my ($seconds, $minutes, $hours, $day_of_month, $month, $year, $wday, $yday, $isdst) = localtime($epoch);
    CertNanny::Logging->debug("Localtime daylightsaving $isdst");

    return sprintf("%04d%02d%02d%02d%02d%02d", $year + 1900, $month + 1, $day_of_month, $hours, $minutes, $seconds);

  }

} ## end sub epochToIsoDate


sub expandDate {
  # expand time format controls (subset as specified by date(1))
  # %y last two digits of year (00..99)
  # %Y year (1970...)
  # %m month (01..12)
  # %d day of month (01..31)
  # %H hour (00..23)
  # %M minute (00..59)
  # %S second (00..59)
  my $self = (shift)->getInstance();
  my $arg  = shift;

  my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time);

  $arg =~ s/%y/sprintf("%02d", ($year + 1900) % 100)/ge;
  $arg =~ s/%Y/$year + 1900/ge;
  $arg =~ s/%m/sprintf("%02d", $mon + 1)/ge;
  $arg =~ s/%d/sprintf("%02d", $mday)/ge;
  $arg =~ s/%H/sprintf("%02d", $hour)/ge;
  $arg =~ s/%M/sprintf("%02d", $min)/ge;
  $arg =~ s/%S/sprintf("%02d", $sec)/ge;

  $arg;
} ## end sub expandDate


sub printableIsoDate {
  # return a printable represantation of a compacted ISO date
  # arg: ISO Date, format YYYYMMDDHHMMSS
  my $self = (shift)->getInstance();
  my $arg  = shift;

  my @date = ($arg =~ /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
  sprintf("%04d-%02d-%02d %02d:%02d:%02d", @date);
} ## end sub printableIsoDate


sub readFile {
  # read (slurp) file from disk
  # Example: $self->readFile($filename);
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "write file/content to disk");
  my $self = (shift)->getInstance();
  my $filename = shift;

  my $result = 1;
  if (!-e $filename) {
    $result = CertNanny::Logging->error("readFile(): file does not exist: $filename");
  }

  if ($result && !-r $filename) {
    CertNanny::Logging->error("readFile(): file is not readable: $filename");
  }

  if ($result) {
    $result = do {
      open my $fh, '<', $filename;
      if (!$fh) {
        $result = CertNanny::Logging->error("readFile(): file open failed: $filename");
      }
      if ($result) {
        binmode $fh;
        local $/;
        <$fh>;
      }
    }
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "write file/content to disk");
  return $result;
} ## end sub readFile


sub writeFile {
  ###########################################################################
  #
  # write file/content to disk
  #
  # Input: caller must provide a hash ref:
  #           SRCFILE    => file name to be read
  #        or SRCCONTENT => content to be read
  #           DSTFILE    => file name to be written
  #
  #           FORCE      => overwrite file if it already exists
  #           APPEND     => append to file if it already exists
  #        APPEND wins against FORCE
  #
  # Output: 1: success
  #         or undef/0 on error
  #
  # Example: $self->writeFile(DSTFILE => $filename, SRCCONTENT => $data);
  #
  # The method will return false if the file already exists unless
  # the optional argument FORCE is set. In this case the method will overwrite
  # the specified file.
  #
  # Example: $self->writeFile(DSTFILE => $filename, SRCCONTENT => $data, FORCE => 1);
  #
  #CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "write file/content to disk");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $rc = 0;
  
  if ((!defined $args{SRCFILE} && !defined $args{SRCCONTENT}) || (defined $args{SRCFILE} && defined $args{SRCCONTENT})) {
    $rc = CertNanny::Logging->error("writeFile(): Either SRCFILE or SRCCONTENT must be defined.");
  }
  
  if (!$rc && !defined $args{DSTFILE}) {
    $rc = CertNanny::Logging->error("writeFile(): Destination File DSTFILE must be defined.");
  }

  my $srcfile    = $args{SRCFILE};
  my $srccontent = $args{SRCCONTENT};
  my $dstfile    = $args{DSTFILE};

  if (!$rc && (-e $dstfile) && (!$args{FORCE}) && (!$args{APPEND})) {
    $rc = CertNanny::Logging->error("writeFile(): output file already exists");
  }

  if (!$rc && defined($srccontent)) {
    my $mode = O_WRONLY;
    if (!-e $dstfile) {
      $mode |= O_EXCL | O_CREAT;
    } else {
      if ($args{APPEND}) {
        $mode |= O_APPEND;
      }
    }

    my $fh;
    if (not sysopen($fh, $dstfile, $mode)) {
      $rc = CertNanny::Logging->error("writeFile(): output file open failed");
    }
    binmode $fh;
    print {$fh} $srccontent;
    close $fh
  }
  
  if (!$rc && defined($srcfile)) {
    if ($args{APPEND}) {
      if (!open OUT, '>>'.$dstfile) {
        $rc = CertNanny::Logging->error("writeFile(): output file open failed");
      }
    } else {
      if (!open OUT, '>'.$dstfile) {
        $rc = CertNanny::Logging->error("writeFile(): output file open failed");
      }
    }
    if (!$rc) {
      if (!open IN, $srcfile) {
        $rc = CertNanny::Logging->error("writeFile(): input file open failed");
      }
      if (!$rc) {
        binmode IN;
        binmode OUT;
        while (<IN>) {
          print OUT;
        }
        close IN;
        close OUT;
      }
    }
  }
  #CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "write file/content to disk");
  return !$rc;
} ## end sub writeFile


sub getCertFormat {
  ###########################################################################
  # Analyses certificate and decides whether it's DER or PEM format
  #
  # Input:  String with Certificate
  # Output: String with Format
  #
  my $self     = (shift)->getInstance();
  my $certdata = shift;
  
  return ($certdata =~ m{ -----.*CERTIFICATE.*----- }xms) ? 'PEM' : 'DER';
} ## end sub getCertFormat


sub callOpenSSL {
  # call openssl programm
  #
  # Input:
  #   command   : openSSL command to be executed
  #   params    : Parameterarray
  #   args      : CERTDATA   => directly contains certificate data
  #               CERTFILE   => cert file to parse
  #               CERTFORMAT => PEM|DER (optional, default: DER)
  #
  # Output: Hash with all detected certificate information
  # i.E.:
  # always:
  #   Version                => <cert version, optional> Values: 2, 3
  #   SubjectName            => <cert subject common name>
  #   IssuerName             => <cert issuer common name>
  #   SerialNumber           => <cert serial number> Format: xx:xx:xx... (hex, upper case)
  #   NotBefore              => <cert validity> Format: YYYYDDMMHHMMSS
  #   NotAfter               => <cert validity> Format: YYYYDDMMHHMMSS
  #   CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex,cupper case)
  #   Modulus                => <cert >
  #   PublicKey              => <cert public key> Format: Base64 encoded (PEM)
  #   Certificate            => <certifcate> Format: Base64 encoded (PEM)
  #   BasicConstraints       => <cert basic constraints> Text (free style)
  #   KeyUsage               => <cert key usage> Format: Text (free style)
  #
  # optional (if present in certificate):
  #   SubjectAlternativeName => <cert alternative name>
  #   IssuerAlternativeName  => <issuer alternative name>
  #   SubjectKeyIdentifier   => <X509v3 Subject Key Identifier>
  #   AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>
  #   CRLDistributionPoints  => <X509v3 CRL Distribution Points>
  #
  my $self    = (shift)->getInstance();
  my $command = shift;
  my $params  = shift;
  my %args    = (@_);

  my $rc = 0;
  my $info;
  # build commandstring
  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)){
    my @cmd = (qq("$openssl"), $command);
    push(@cmd, ('-in', qq("$args{CERTFILE}")))       if (defined $args{CERTFILE});
    push(@cmd, ('-inform', qq("$args{CERTFORMAT}"))) if (defined $args{CERTFORMAT});
    foreach (@$params) {
      push(@cmd, -$_);
    }
    my $outfile = CertNanny::Util->getTmpFile();
    push(@cmd, ('>', qq("$outfile")));

    # export certificate to tempfile
    CertNanny::Logging->debug("Execute: " . join(" ", @cmd));

    my $fh;
    if (!open $fh, "| " . join(" ", @cmd)) {
      $rc = CertNanny::Logging->error("callOpenSSL(): open error");
      unlink $outfile;
    }

    if (!$rc) {
      binmode $fh;
      print $fh $args{CERTDATA} if (defined $args{CERTDATA});
      close $fh;

      if ($? != 0) {
        $rc = CertNanny::Logging->error("callOpenSSL(): Error ASN.1 decoding certificate");
        unlink $outfile;
      }

      if (!$rc) {
        # read certificate
        open $fh, '<', $outfile;
        if (!$fh) {
          $rc = CertNanny::Logging->error("callOpenSSL(): Error analysing ASN.1 decoded certificate");
          unlink $outfile;
        }
      }
    }

    if (!$rc) {
      $info = CertNanny::Util->parseCertData(\$fh);
      close $fh;
      unlink $outfile;
    }
  }
  
  return $info;
} ## end sub callOpenSSL


sub _sanityCheckIn {
  ###########################################################################
  # Checks whether either CERTDATA or CERTFILE but at least one of them is
  # given
  #
  my $self = (shift)->getInstance();

  my $proc = shift;
  my %args = (@_);    # argument pair list

  my $rc = 0;
  # eather CERTFILE or CERTDATA must be provided
  if (!(defined $args{CERTFILE} or defined $args{CERTDATA})) {
    CertNanny::Logging->error($proc . "(): No input data specified");
  } elsif ((defined $args{CERTFILE} and defined $args{CERTDATA})) {
    CertNanny::Logging->error($proc . "(): Ambigous input data specified");
  } elsif (defined $args{CERTFILE}) {
    $rc = 'CERTFILE';
  } elsif (defined $args{CERTDATA}) {
    $rc = 'CERTDATA';
  }
  
  return $rc;
}


sub _sha1_base64 {
  my $self = (shift)->getInstance();
  my $data = shift;

  my $sha;
  my $tmpfile = CertNanny::Util->getTmpFile();
  if (CertNanny::Util->writeFile(DSTFILE    => $tmpfile,
                                 SRCCONTENT => $data)) {
    my $openssl =$self->{CONFIG}->get('cmd.openssl', 'CMD');
    if (defined($openssl)) {
      my @cmd = (qq("$openssl"), 'dgst', '-sha', qq("$tmpfile"));
      chomp($sha = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1));
      if ($sha =~ /^.*\)= (.*)$/) {
        $sha = $1;
      }
    }
    unlink($tmpfile);
  }

  return $sha;
}


sub getCertSHA1 {
  ###########################################################################
  #
  # Create DER SHA1 of a certificate
  # 
  # Input: caller must provide a hash ref:
  #   either  CERTDATA   => mandatory: directly contains certificate data
  #   or      CERTFILE   => mandatory: cert file to parse
  #           CERTFORMAT => optional: PEM|DER (default: PEM)
  #
  # exacly one of CERTDATA or CERFILE mut be provided
  #
  # Output: caller gets a hash ref:
  #           CERTSHA1   => String with SHA1 Hash of DER Certificate
  #
  # Convert - if neccesary - to DER
  # Base64 Konvertierung
  # calculate Digest::SHA1
  #
  my $self = (shift)->getInstance();
  
  my %args = (CERTFORMAT => 'PEM',
              OUTFORMAT  => 'DER',
              @_);                   # argument pair list
              
  my $rc = undef;
             
  my ($certType, $cert, $base64, $sha);
  
  if ($certType = $self->_sanityCheckIn('getCertSHA1', %args)) {
    if (defined($self->{getCertSHA1}->{$args{$certType}})) {
      $rc = {CERTSHA1 => $self->{getCertSHA1}->{$args{$certType}}};
    } else {
      if ($cert = CertNanny::Util->convertCert(%args)) {
        if ($sha = $self->_sha1_base64($$cert{CERTDATA})) {
          $rc = {CERTSHA1 => $sha};
          $self->{getCertSHA1}->{$args{$certType}} = $sha;
        }
      }
    }
  }
  if (defined($rc)) {
    CertNanny::Logging->debug("SHA1 calculated as <$rc->{CERTSHA1}>\n");
  } else {
    CertNanny::Logging->debug("No SHA1 calculated\n");
  } 
  

  return $rc;
} ## end sub getCertSHA1


sub getCertInfoHash {
  # parse DER encoded X.509v3 certificate and return certificate information
  # in a hash ref
  # Prerequisites: requires external openssl executable
  #
  # Input: Hash with
  #   either   CERTDATA   => directly contains certificate data
  #   or       CERTFILE   => cert file to parse
  #   optional CERTFORMAT => PEM|DER (default: DER)
  #
  # exacly one of CERTDATA or CERFILE mut be provided
  #
  # Output: Hash with certificate information
  # always:
  #   Version                => <cert version, optional> Values: 2, 3
  #   SubjectName            => <cert subject common name>
  #   IssuerName             => <cert issuer common name>
  #   SerialNumber           => <cert serial number> Format: xx:xx:xx... (hex, upper case)
  #   NotBefore              => <cert validity> Format: YYYYDDMMHHMMSS
  #   NotAfter               => <cert validity> Format: YYYYDDMMHHMMSS
  #   CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex,cupper case)
  #   Modulus                => <cert >
  #   PublicKey              => <cert public key> Format: Base64 encoded (PEM)
  #   Certificate            => <certifcate> Format: Base64 encoded (PEM)
  #   BasicConstraints       => <cert basic constraints> Text (free style)
  #   KeyUsage               => <cert key usage> Format: Text (free style)
  #
  # optional (if present in certificate):
  #   SubjectAlternativeName => <cert alternative name>
  #   IssuerAlternativeName  => <issuer alternative name>
  #   SubjectKeyIdentifier   => <X509v3 Subject Key Identifier>
  #   AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>
  #   CRLDistributionPoints  => <X509v3 CRL Distribution Points>
  #
  my $self = (shift)->getInstance();
  
  my %args = (CERTFORMAT => 'DER',
              @_);    # argument pair list

  # sanity checks
  return undef if (!$self->_sanityCheckIn('getCertInfoHash', %args));

  my %month = (Jan => 1,  Feb => 2,  Mar => 3,  Apr => 4,
               May => 5,  Jun => 6,  Jul => 7,  Aug => 8,
               Sep => 9,  Oct => 10, Nov => 11, Dec => 12);

  my $command = 'x509';
  my @params  = ('text', 'subject', 'issuer', 'serial', 'email', 
                 'startdate', 'enddate', 
                 'modulus', 'fingerprint', 'sha1', 'pubkey', 
                 'purpose');

  my $info  = CertNanny::Util->callOpenSSL($command, \@params, %args);
  
  ####
  # rewrite dates from human readable to ISO notation
  foreach my $var (qw(NotBefore NotAfter)) {
    my ($mon, $day, $hh, $mm, $ss, $year, $tz) = $info->{$var} =~ /(\S+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)\s*(\S*)/;
    my $dmon = $month{$mon};
    if (!defined $dmon) {
      CertNanny::Logging->error("getCertInfoHash(): could not parse month '$mon' in date '$info->{$var}' returned by OpenSSL");
      return undef;
    }

    $info->{$var} = sprintf("%04d%02d%02d%02d%02d%02d", $year, $dmon, $day, $hh, $mm, $ss);
  } ## end foreach my $var (qw(NotBefore NotAfter))

  # sanity checks
  foreach my $var (qw(Version SerialNumber SubjectName IssuerName NotBefore NotAfter CertificateFingerprint Modulus)) {
    if (!exists $info->{$var}) {
      CertNanny::Logging->error("getCertInfoHash(): Could not determine field '$var' from X.509 certificate");
      return undef;
    }
  }

  return $info;
} ## end sub getCertInfoHash


sub getCSRInfoHash {
  # parse PEM encoded X.509v3 certificate and return certificate information
  # in a hash ref
  # Prerequisites: requires external openssl executable
  #
  # Input: Hash with
  #   CERTDATA   => directly contains certificate data
  #   CERTFILE   => cert file to parse
  #   CERTFORMAT => PEM|DER (optional, default: PEM)
  #
  # exacly one of CERTDATA or CERFILE mut be provided
  #
  # Output: Hash with certificate information
  # always:
  #   Version                => <cert version, optional> Values: 2, 3
  #   SubjectName            => <cert subject common name>
  #   Modulus  e             => <cert modulus>
  #
  my $self = (shift)->getInstance();

  my %args = (CERTFORMAT => 'PEM',
              @_);    # argument pair list

  # sanity checks
  return undef if (!$self->_sanityCheckIn('getCSRInfoHash', %args));

  my $command   = 'req';
  my @arguments = ('text', 'subject', 'modulus');

  my $info  = CertNanny::Util->callOpenSSL($command, \@arguments, %args);
  
  # sanity checks
  foreach my $var (qw(Version SubjectName Modulus)) {
    if (!exists $info->{$var}) {
      CertNanny::Logging->error("getCSRInfoHash(): Could not determine field '$var' from certificate signing request.");
      return undef;
    }
  }

  return $info;
} ## end sub getCSRInfoHash


sub parseCertData {
  my $self = (shift)->getInstance();
  my $fh   = ${shift @_};

  my $certinfo = {};
  my $state    = "";
  my @purposes;

  my %mapping = ('serial'                 => 'SerialNumber',
                 'subject'                => 'SubjectName',
                 'issuer'                 => 'IssuerName',
                 'notBefore'              => 'NotBefore',
                 'notAfter'               => 'NotAfter',
                 'SHA1 Fingerprint'       => 'CertificateFingerprint',
                 'PUBLIC KEY'             => 'PublicKey',
                 'CERTIFICATE'            => 'Certificate',
                 'ISSUERALTNAME'          => 'IssuerAlternativeName',
                 'SUBJECTALTNAME'         => 'SubjectAlternativeName',
                 'BASICCONSTRAINTS'       => 'BasicConstraints',
                 'SUBJECTKEYIDENTIFIER'   => 'SubjectKeyIdentifier',
                 'AUTHORITYKEYIDENTIFIER' => 'AuthorityKeyIdentifier',
                 'CRLDISTRIBUTIONPOINTS'  => 'CRLDistributionPoints',
                 'Modulus'                => 'Modulus',);
  while (<$fh>) {
    chomp;
    tr/\r\n//d;

    $state = "PURPOSE"                if (/^Certificate purposes:/);
    $state = "PUBLIC KEY"             if (/^-----BEGIN PUBLIC KEY-----/);
    $state = "CERTIFICATE"            if (/^-----BEGIN CERTIFICATE-----/);
    $state = "SUBJECTALTNAME"         if (/X509v3 Subject Alternative Name:/);
    $state = "ISSUERALTNAME"          if (/X509v3 Issuer Alternative Name:/);
    $state = "BASICCONSTRAINTS"       if (/X509v3 Basic Constraints:/);
    $state = "SUBJECTKEYIDENTIFIER"   if (/X509v3 Subject Key Identifier:/);
    $state = "AUTHORITYKEYIDENTIFIER" if (/X509v3 Authority Key Identifier:/);
    $state = "CRLDISTRIBUTIONPOINTS"  if (/X509v3 CRL Distribution Points:/);

    if ($state eq "PURPOSE") {
      my ($purpose, $bool) = (/(.*?)\s*:\s*(Yes|No)/);
      next unless defined $purpose;
      push(@purposes, $purpose) if ($bool eq "Yes");

      # NOTE: state machine will leave PURPOSE state on the assumption
      # that 'OCSP helper CA' is the last cert purpose printed out
      # by OpenCA. It would be best to have OpenSSL print out
      # purpose information, just to be sure.
      $state = "" if (/^OCSP helper CA :/);
      next;
    } ## end if ($state eq "PURPOSE")

    # Base64 encoded sections
    if ($state =~ /^(PUBLIC KEY|CERTIFICATE)$/) {
      my $key = $state;
      $key = $mapping{$key} if (exists $mapping{$key});

      $certinfo->{$key} .= "\n" if (exists $certinfo->{$key});
      $certinfo->{$key} .= $_ unless (/^-----/);

      $state = "" if (/^-----END $state-----/);
      next;
    } ## end if ($state =~ /^(PUBLIC KEY|CERTIFICATE)$/)

    # X.509v3 extension one-liners
    if ($state =~ /^(SUBJECTALTNAME|ISSUERALTNAME|BASICCONSTRAINTS|SUBJECTKEYIDENTIFIER|AUTHORITYKEYIDENTIFIER|CRLDISTRIBUTIONPOINTS)$/) {
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
    } ## end if ($state =~ /^(SUBJECTALTNAME|ISSUERALTNAME|BASICCONSTRAINTS|SUBJECTKEYIDENTIFIER|AUTHORITYKEYIDENTIFIER|CRLDISTRIBUTIONPOINTS)$/)

    if (/(Version:|subject=|issuer=|serial=|notBefore=|notAfter=|SHA1 Fingerprint=|Modulus=)\s*(.*)/) {
      my $key   = $1;
      my $value = $2;

      # remove trailing garbage
      $key =~ s/[ :=]+$//;

      # apply key mapping
      $key = $mapping{$key} if (exists $mapping{$key});

      # store value
      $certinfo->{$key} = $value;
    } ## end if (/(Version:|subject=|issuer=|serial=|notBefore=|notAfter=|SHA1 Fingerprint=|Modulus=)\s*(.*)/)
  } ## end while (<$fh>)

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
  if (length($certinfo->{SerialNumber}) % 2) {
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
  foreach my $var (qw(SubjectName IssuerName)) {
    $certinfo->{$var} =
      join(", ", reverse split(/[\/,]\s*/, $certinfo->{$var}));

    # remove trailing garbage
    $certinfo->{$var} =~ s/[, ]+$//;
  }

  return $certinfo;
} ## end sub parseCertData


sub convertCert {
  # convert certificate to other formats
  # input: hash
  # CERTDATA => string containing certificate data OR
  # CERTFILE => file containing certificate data
  # CERTFORMAT => certificate encoding format (PEM or DER), default: DER
  # OUTFORMAT => desired output certificate format (PEM or DER), default: DER
  #
  # return: hash ref
  # CERTDATA => string containing certificate data
  # CERTFORMAT => certificate encoding format (PEM or DER)
  # or undef on error
  my $self = (shift)->getInstance();

  my %args = (CERTFORMAT => 'DER',
              OUTFORMAT  => 'DER',
              @_);                 # argument pair list
                 
  # sanity checks
  foreach my $key (qw( CERTFORMAT OUTFORMAT )) {
    if ($args{$key} !~ m{ \A (?: DER | PEM ) \z }xms) {
      CertNanny::Logging->error("convertCert(): Incorrect $key: $args{$key}");
      return undef;
    }
  }

  my ($infile, $output);

  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)) {
    my @cmd     = (qq("$openssl"), 'x509', '-in',);

    if (exists $args{CERTDATA}) {
      $infile = CertNanny::Util->getTmpFile();
      if (!CertNanny::Util->writeFile(DSTFILE    => $infile,
                                      SRCCONTENT => $args{CERTDATA})) {
        CertNanny::Logging->error("convertCert(): Could not write temporary file: $infile");
        return undef;
      }
      push(@cmd, qq("$infile"));
    } else {
      push(@cmd, qq("$args{CERTFILE}"));
    }

    push(@cmd, ('-inform',  $args{CERTFORMAT}));
    push(@cmd, ('-outform', $args{OUTFORMAT}));

    $output->{CERTFORMAT} = $args{OUTFORMAT};
    $output->{CERTDATA} = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1);
    unlink $infile if defined $infile;

    if ($? != 0) {
      CertNanny::Logging->error("convertCert(): Could not convert certificate");
      return undef;
    }
  }

  return $output;
} ## end sub convertCert


sub getTmpFile {
  # NOTE: this is UNSAFE (beware of race conditions). We cannot use a file
  # handle here because we are calling external programs to use these
  # temporary files.
  #CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get a tmp file");
  my $self = (shift)->getInstance();
  
  my $tmpdir = $self->{CONFIG}->get('path.tmpdir', 'FILE');

  #if (! defined $tmpdir);
  my $template = File::Spec->catfile($tmpdir, "cbXXXXXX");

  my $tmpfile = mktemp($template);

  push(@{$self->{TMPFILE}}, $tmpfile);
  # CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get a tmp file");
  return $tmpfile;
} ## end sub getTmpFile


sub staticEngine {
  my $self      = (shift)->getInstance();
  my $engine_id = shift;

  unless (defined $engine_id) {
    CertNanny::Logging->error("No engine_id passed to staticEngine() as first argument!");
    die;
  }

  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)) {
    my @cmd = (qq("$openssl"));
    push(@cmd, 'engine');
    $engine_id =~ s/[^A-Za-z0-9]*//g;
    push(@cmd, $engine_id);
    push(@cmd, '-t');

    CertNanny::Logging->debug("Execute: " . join(' ', @cmd));
    my $output = "";
    open FH, join(' ', @cmd) . " |" or die "Couldn't execute " . join(' ', @cmd) . ": $!\n";
    while (defined(my $line = <FH>)) {
      chomp($line);
      $output .= $line;
    }
    close FH;
    CertNanny::Logging->debug("Output is $output\n");
    return $output =~ m/\(cs\).*\[ available \]/s;
  }
  return undef;
} ## end sub staticEngine


sub encodeBMPString {
  my $self           = (shift)->getInstance();
  my $stringToEncode = shift;

  my $hex = unpack('H*', "$stringToEncode");

  my $len = length($stringToEncode);

  my $result = "1e:";
  $result .= sprintf("%02x", $len * 2);

  for (my $i = 0; $i < length $hex; $i += 2) {

    $result .= sprintf(":00:%s", substr($hex, $i, 2));
  }

  #print "Util::BMP String:" .$result;
  return $result;

} ## end sub encodeBMPString


sub writeOpenSSLConfig {
  my $self            = (shift)->getInstance();
  my $config_hash     = shift;
  my $config_filename = shift || CertNanny::Util->getTmpFile();

  open(my $configfile, ">", $config_filename)
    or die "Cannot write $config_filename";

  if (defined $config_hash->{openssl_conf}) {
    print $configfile "openssl_conf=$config_hash->{openssl_conf}\n";
    delete $config_hash->{openssl_conf};
  }

  foreach my $section (keys %{$config_hash}) {
    print $configfile "[$section]\n";
    foreach my $entry_hash (@{$config_hash->{$section}}) {
      foreach my $key (keys(%{$entry_hash})) {
        my $value = $entry_hash->{$key};
        if (-e $value and $^O eq "MSWin32") {

          #on Windows paths have a backslash, so in the string it is \\.
          #In the config it must keep the doubled backslash so the actual
          #string would contain \\\\. Yes this is ridiculous...
          $value =~ s#/#\\#g;
          $value =~ s/\\/\\\\/g;
        }
        print $configfile "$key=$value\n";
      } ## end foreach my $key (keys(%{$entry_hash...}))
    } ## end foreach my $entry_hash (@{$config_hash...})
  } ## end foreach my $section (keys %...)

  close $configfile;
  return $config_filename;
} ## end sub writeOpenSSLConfig


sub getDefaultOpenSSLConfig {
  my $self = (shift)->getInstance();

  my $default_config = {openssl_conf   => "openssl_def",
                        openssl_def    => [{engines => "engine_section"},],
                        engine_section => []};

  return $default_config;
} ## end sub getDefaultOpenSSLConfig


sub backoffTime {
  my $self   = (shift)->getInstance();
  my $config = shift;

  CertNanny::Logging->debug("CertNanny::Util::backoffTime");

  if (exists $config->{CONFIG}->{conditionalwait}->{time}) {
    CertNanny::Logging->debug("Conditional delay between 0 and " . $config->{CONFIG}->{conditionalwait}->{time} . " seconds");

    my $date = $self->epochToIsoDate(time(), 1);
    my $currentDate = substr($date, 0, 8);
    my $now = time();

    CertNanny::Logging->debug("$now currentDate:  $date");
    my $startTime = CertNanny::Util->isoDateToEpoch($currentDate . $config->{CONFIG}->{conditionalwait}->{start}, 1);
    my $endTime   = CertNanny::Util->isoDateToEpoch($currentDate . $config->{CONFIG}->{conditionalwait}->{end},   1);
    CertNanny::Logging->debug("$startTime startISO: " . $currentDate . $config->{CONFIG}->{conditionalwait}->{start});
    CertNanny::Logging->debug("$endTime endISO: " . $currentDate . $config->{CONFIG}->{conditionalwait}->{end});

    if ($startTime > $endTime) {

      #if the end time is greater then the end time we assume the start time started the day before.
      $startTime -= 24 * 60 * 60;
      CertNanny::Logging->debug("new starttime $startTime in ISO" . CertNanny::Util::epochToIsoDate($startTime, 1));
    }

    if ($now > $startTime and $now < $endTime) {
      my $rndwaittime =
        int(rand($config->{CONFIG}->{conditionalwait}->{time}));
      CertNanny::Logging->debug("Inside the conditional time frame, start extended backoff time of $rndwaittime seconds");
      sleep $rndwaittime;
    } else {
      CertNanny::Logging->debug("Outside the conditional time, no backoff");
      if (exists $config->{CONFIG}->{randomwait}) {
        CertNanny::Logging->debug("Random delay between 0 and " . $config->{CONFIG}->{randomwait} . " seconds");
        my $rndwaittime = int(rand($config->{CONFIG}->{randomwait}));
        CertNanny::Logging->info("Scheduling renewal but randomly waiting $rndwaittime seconds to reduce load on the PKI");
        sleep $rndwaittime;
      }
    }
  } else {
    if (exists $config->{CONFIG}->{randomwait}) {
      CertNanny::Logging->debug("Random delay between 0 and " . $config->{CONFIG}->{randomwait} . " seconds");
      my $rndwaittime = int(rand($config->{CONFIG}->{randomwait}));
      CertNanny::Logging->info("Scheduling renewal but randomly waiting $rndwaittime seconds to reduce load on the PKI");
      sleep $rndwaittime;
    }
  }

  return 1;
} ## end sub backoffTime


sub getMacAddresses {
  # Find all ethernet MAC addresses on the system
  # and print them to stdout
  #
  # Author: Andreas Leibl
  #         andreas@leibl.co.uk
  # 2013-01-30 Martin Bartosch: minor changes
  #
  my $self = (shift)->getInstance();
  my $rc = 0;
  
  my $command;
  my $s = ':';    # the separator: ":" for Unix, "-" for Win
  if ($^O eq 'MSWin32') {
    $command = 'ipconfig /all';
    $s       = "-";
  } elsif ($^O eq 'aix') {
    $command = "lsdev | egrep -w 'ent[0-9]+' | cut -d ' ' -f 1 | while read adapter; do entstat -d \$adapter | grep 'Hardware Address:'; done";
  } else {
    my $ifconfig = $self->{CONFIG}->get('cmd.ifconfig', 'CMD');
    if (defined($ifconfig)) {
      if ($ifconfig and $ifconfig ne '') {
        $command = "$ifconfig -a";
      } else {
        $command = "ifconfig -a";
      }
    }
  }

  #print "DEBUG: OS is $^O\n";

  local $/;       # slurp
  
  open(my $cmd, '-|', $command) or $rc=1 ;
  my $ifconfigout = <$cmd>;
  close $cmd;

  #print "DEBUG: full command output:\n$ifconfigout DEBUG: end of full output\n\n\nDEBUG: found MAC addresses:\n";
  my @result;
  if ($rc == 0) {
    while ($ifconfigout =~ s/\b([\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2})\b//i) {
      my $mac = $1;
      $mac =~ s/-/:/g;    # in case we have windows output, harmonise it
      push @result, $mac;
    }
  } else {
    CertNanny::Logging->info(" unable to determine MAC addresses - ifconfig not available ? ");
  }

  return @result ;
} ## end sub getMacAddresses


sub fetchFileList {
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "fetch a file list");
  my $self   = (shift)->getInstance();
  my $myGlob = shift;
  
  my (@myList, @tmpList);
  # Test if $configfileglob contains regular files
  @myList = glob ("'$myGlob'") ;
  foreach my $item (@myList) {
    $item =~ s/^["']*|["']*$//g;
    $item = File::Spec->canonpath($item);
    CertNanny::Logging->debug("cannonpath file: $item");
    if (-f $item) {
      CertNanny::Logging->debug("Found file: $item");
      push(@tmpList, $item);
    } else {
      if (-d $item) {
       CertNanny::Logging->debug("Found directory: $item");
        if (opendir(DIR, $item)) {
          while (defined(my $file = readdir(DIR))) {
            my $osFileName = File::Spec->catfile($item, $file);
            if (-f $osFileName) {
              CertNanny::Logging->debug("Found file: $osFileName");
              push(@tmpList, $osFileName);
            } else {
              CertNanny::Logging->debug("Found non-file: $osFileName");
            }
          }
          closedir(DIR);
        }
      } else {
        CertNanny::Logging->debug("Item is empty, does not exist or is binary (possible misconfiguration): $item");
      }
    }
  } ## end foreach my $item (@myList)
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "fetch a file list");
  return \@tmpList;
} ## end sub fetchFileList


1;

=head1 NAME

CertNanny::Util - Utility functions for CertNanny.

=head1 SYNOPSIS

    CertNanny::Util->getCertInfoHash();
    CertNanny::Util->writeFile();
    ...

=head1 DESCRIPTION

Provides utility functions for CertNanny. Some functions should be called without any object/instance, some are called via class or instance. On functions that are called via class/instance it does not matter which is used, there is always a singleton instance which will be used.

=head1 FUNCTIONS

=head2 Function List

=over 4

C<new()>

C<getInstance()>

C<runCommand()>

C<timeStamp()>

C<isoDateToEpoch()>

C<expandDate()>

C<printableIsoDate()>

C<readFile()>

C<writeFile()>

C<getCertInfoHash()>

C<getCSRInfoHash()>

C<parseCertData()>

C<getTmpFile()>

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

=item runCommand($command)

Called globally, do not call it via class or instance. Runs a command  and returns its exit code. Prints the output to STDOUT (in CertNanny context this is most likely the logfile).

=over 4

=item $command

The command to execute

=back

=item timeStamp()

Returns the current time in ISO (UTC) timestamp format. Called globally.

=item isoDateToEpoch($time)

Convert an ISO date to a Unix timestamp (seconds since the Epoch). Returns Unix timestamp.

=over 4

=item $time

Time in ISO format (YYYYMMDDHHMMSS)

=back

=item expandDate($time)

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

=item printableIsoDate($isodate)

Return a printable represantation of a compacted ISO date.

=over 4

=item $isodate

ISO Date, format YYYYMMDDHHMMSS

=back

=item readFile($filename)
Read (slurp) file from disk.

=over 4

=item $filename

The filename to read.

=back

=item writeFile(%args)

Write file to disk. Returns false if file already existss unless $args{FORCE} is set. In this case the method will overwrite the specified file.

=over 4

=item $args{FILENAME}

The name of the file to write.

=item $args{CONTENT}

The data to write.

=item $args{FORCE}

If set, will overwrite existing file.

=back

=item getCertInfoHash(%args)

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

=item getCSRInfoHash()

Format is the same a with C<getCertInfoHash()> but does not provide all the information since values like NotAfter are not set until issuance.

=item parseCertData($fh)

Internal function that uses openssl output to retrieve csr/cert information. Can be used externally, but is not intended for use and only works with specific params.

=over 4

=item $fh

Filehandle to the output that should be parsed. See C<getCertInfoHash> and C<getCSRInfoHash> for usage exmaples.

=back

=item getTmpFile()

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

Configuration hash reference. This hash reference requires a special structure: The keys of this hash reference are the names of the sections for an OpenSSL configuration file. Inside such a section then is an array reference which is sorted in the way the options should be entered into the configuration file. Each array entry contains a hash reference with a single key => value pair that contains the parameter name as key and the parameter's value as the value of the hash reference.
For example, you pass:
 
{section_name}->[0]->{key_name}=value
 
This will lead to:

[section_name]
    
key_name=value


=item $config_filename

Optional string that contains the desired filename. If none is passed then a temporary one is created. The filename is always returned, regardless of this setting. 

=back

=item getDefaultOpenSSLConfig()

Returns an OpenSSL default configuration hash. For the of the hash syntax see C<writeOpenSSLConfig()>. It contains an out-of-section default value openssl_conf=openssl_def denoting the OpenSSL section used as a starting point and contains a default engines=engine_section inside it.
