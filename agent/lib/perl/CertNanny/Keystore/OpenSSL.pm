#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::OpenSSL;

use base qw(Exporter CertNanny::Keystore);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

use IO::File;
use File::Spec;
use File::Path;
use File::Copy;
use File::Basename;
use Data::Dumper;

use CertNanny::Util;

# keyspecific needed modules
use Net::Domain;

$VERSION = 0.10;

################################################################################


sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my %args = (@_);    # argument pair list

  my $self = {};
  bless $self, $class;

  $self->{OPTIONS} = \%args;

  # GET VALUES AND SET DEFAULTS
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  # propagate PIN to class options
  $self->{PIN} = $entry->{key}->{pin};
 
  if ($entry->{location} eq 'rootonly') {
    CertNanny::Logging->debug("Instantiate root only keystore skip sanity checks");
    if (!defined $entry->{rootcaupdate}->{enable}) {
      CertNanny::Logging->debug("Rootonly keystored only make sense if rootca update is enabled");
    }
    
    if (!defined $entry->{rootcaupdate}->{quarantinedir}) {
      CertNanny::Logging->debug("Rootonly missing quarantinedir");
    }
      
    if (!defined $entry->{TrustedRootCA}->{AUTHORITATIVE}->{Directory}) {
      CertNanny::Logging->debug("Rootonly missing TrustedRootCA AUTHORITATIVE Directory");
    }
  } else {
    if (defined $entry->{INITIALENROLLEMNT} and $entry->{INITIALENROLLEMNT} eq 'yes' ) {
      CertNanny::Logging->info("Initial enrollment mode, skip check for key and cert file");
    } else {
      #If not an initial enrollment set default to no 
      $entry->{INITIALENROLLEMNT} =  'no'; 
   
      # If it's not an Initial Enrollment, we need at least
      #   - keyfile
      #   - location
      if (!defined $entry->{key}->{file} || (!-r $entry->{key}->{file}) && !defined $entry->{hsm}) {
        croak("keystore.key.file $entry->{key}->{file} not defined, does not exist or unreadable");
        return undef;
      }
 
      if (!defined $entry->{location} || (!-r $entry->{location})) {
        croak("keystore.location $entry->{location} not defined, does not exist or unreadable");
        return undef;
      }
    } ## end else [ if (defined $config->...)] 
  
    # desired target formats valid is PEM or DER
    foreach my $format (qw(FORMAT KEYFORMAT CACERTFORMAT ROOTCACERTFORMAT)) {
      # assign format if explicitly defined in config
      if (defined $entry->{lc($format)}) {
        $self->{$format} = $entry->{lc($format)};
      }

      # assign default PEM otherwise
      if (!defined $self->{$format}) {
        $self->{$format} = $format eq 'FORMAT'
                           ? 'PEM'            # default for .format
                           : $self->{FORMAT}; # default for the rest
      }

      if ($self->{$format} !~ m{ \A (?: DER | PEM ) \z }xms) {
        croak("Incorrect ." . lc($format) . " specification '" . $self->{$format} . "'");
        return undef;
      }
    } ## end foreach my $format (qw(FORMAT KEYFORMAT CACERTFORMAT ROOTCACERTFORMAT))

    # Keytype defaults to OpenSSL; valid is OpenSSL or PKCS8
    
    $self->{KEYTYPE} = $entry->{key}->{type} || 'OpenSSL';
    

    
    if ($self->{KEYTYPE} !~ m{ \A (?: OpenSSL | PKCS8 ) \z }xms) {
      croak("Incorrect keystore type $self->{KEYTYPE}");
      return undef;
    }
    $self->{KEYFORMAT} = $entry->{key}->{format} || 'PEM';
    # SANITY CHECKS
    # sanity check: DER encoded OpenSSL keys cannot be encrypted
    if (defined $self->{PIN} && ($self->{PIN} ne "") &&
                                ($self->{KEYTYPE} eq 'OpenSSL') &&
                                ($self->{KEYFORMAT} eq 'DER')) {
      croak("DER encoded OpenSSL keystores cannot be encrypted");
      return undef;
    }

    # sanity check: Root CA bundle in DER format does not make sense
    if (($self->{ROOTCACERTFORMAT} eq 'DER') && defined $entry->{rootcacertbundle}) {
      croak("DER encoded Root CA bundles are not supported. Fix .format and/or .rootcacertformat and/or .rootcabundle config settings");
      return undef;
    }

    # if we want to use an HSM
    if ($entry->{hsm}->{type}) {
      my $hsmtype = $entry->{hsm}->{type};
      CertNanny::Logging->debug("Using HSM $hsmtype");
      eval "use CertNanny::HSM::$hsmtype";
      if ($@) {
        print STDERR $@;
        return undef;
      }
      eval "\$self->{HSM} = CertNanny::HSM::$hsmtype->new(\$entry, \$config, \$entryname)";
      if ($@ or not $self->{HSM}) {
        CertNanny::Logging->error("Could not instantiate HSM: " . $@);
        return undef;
      }

      my $hsm = $self->{HSM};
      unless ($hsm->can('createRequest') and $hsm->can('genkey')) {
        unless ($hsm->can('engineid')) {
          croak("HSM does not provide function engineid(), can not continue.");
        }

        unless ($hsm->can('keyform')) {
          croak("HSM does not provide function keyform(), can not continue.");
        }
      }
    } ## end if ($entry->{hsm}->{type})
    
    my $chainfile = $config->get("keystore.$entryname.CAChain.GENERATED.File",      'FILE');
    unless (-e $chainfile){
     CertNanny::Logging->debug("Cert chain file defined but doesn not exist $chainfile , force generation");
      $self->k_getCaCerts();
      $self->installCertChain();
    }
    

    # RETRIEVE AND STORE STATE
    # get previous renewal status
    $self->k_retrieveState() || return undef;

    # check if we can write to the file
    $self->k_storeState()    || croak "Could not write state file $self->{STATE}->{FILE}";
  } #location root only 
  # return new keystore object
  return $self;
} ## end sub new


sub DESTROY {
  my $self = shift;

  # call parent destructor
  $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}


sub getCert {
  ###########################################################################
  #
  # get main certificate from keystore
  #
  # Input: caller must provide a hash ref:
  #           CERTFILE   => file containing the cert OR
  #        or CERTDATA   => string containing the cert
  #        if neither CERTFILE nor CERTDATA ist provided, default is
  #        CERTFILE => $self->{OPTIONS}->{ENTRY}->{location}
  #
  # Input: caller must provide the file location.
  #        if no file location is provided default is
  #        $self->{OPTIONS}->{ENTRY}->{location}
  #
  # Output: caller gets a hash ref:
  #           CERTDATA   => string containg the cert data
  #           CERTFORMAT => 'PEM' or 'DER'
  #           CERTREST   => string containing the rest of the input when the 
  #                         first cert is extracted
  #         or undef on error
  #
  # Gets the first certificate found either in CERTDATA or in CERTFILE and 
  # returns it in CERTDATA. 
  # If there is a rest in the input, it is returned in CERTREST
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
  my $self = shift;
  my %args = (@_);    # argument pair list
 
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $rc = undef;
  
  if (!defined $args{CERTFILE} && !defined $args{CERTDATA}) {
    $args{CERTFILE} = $entry->{location}
  }
  
  if (defined $args{CERTFILE} && defined $args{CERTDATA}) {
    $rc = CertNanny::Logging->error("getCert(): Either CERTFILE or CERTDATA may be defined.");
  }

  if (!$rc) {
    my ($certData, $certFormat, $certRest) = ('', '', '');
    if (defined $args{CERTFILE}) {
      $certData = CertNanny::Util->readFile($args{CERTFILE});
      if (!defined $certData) {
        $rc = CertNanny::Logging->error("getCert(): Could not read instance certificate file $args{CERTFILE}");
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
      }
    } else {
      $certData = $args{CERTDATA};
    }
  
    if (!$rc) {
      local $/ = undef;
      if ($certData =~ m/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)(.*?)[\n\r]*$/s) {
        chomp($certData = $1);
        chomp($certRest = $2);
        $certFormat = 'PEM';
      } else {
        # $cerFormat = CertNanny::Util->getCertFormat($certData);
        $certFormat = 'DER';
      }
      $rc = {CERTDATA   => $certData,
             CERTFORMAT => $certFormat,
             CERTREST   => $certRest};
    } else {
      $rc = undef;
    }
  } else {
    $rc = undef;
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
  return $rc;
} ## end sub getCert


sub installCert {
  ###########################################################################
  #
  # installs a new main certificate from the SCEPT server in the keystore
  #
  # Input: caller must provide a hash ref:
  #           CERTFILE  => file containing the cert OR
  #           TARGETDIR => directory, where the new certificate should be installed to
  #
  # Output: true: success false: failure
  #
  # This method is called once the new certificate has been received from
  # the SCEP server. Its responsibility is to create a new keystore containing
  # the new key, certificate, CA certificate keychain and collection of Root
  # certificates configured for CertNanny.
  # A true return code indicates that the keystore was installed properly.
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
  my $self = shift;
  my %args = (@_);    # argument pair list

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  # Todo pgk: {KEYFILE} or {key}->{file} ?
  my $keyfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
  my $pin = $self->{PIN} || $entry->{key}->{pin} || "";

  # data structure representing the new keystore (containing all
  # new file contents to write)
  my @newkeystore = ();

  ######################################################################
  ### private key...
  my $newkey;
  unless ($self->_hasEngine() and $self->{HSM}->keyform() ne "file") {
    unless ($self->_hasEngine()) {
      $newkey = $self->k_convertKey(KEYFILE   => $keyfile,
                                    KEYFORMAT => 'PEM',
                                    KEYTYPE   => 'OpenSSL',
                                    KEYPASS   => $pin,
                                    OUTFORMAT => $self->{KEYFORMAT},
                                    OUTTYPE   => $self->{KEYTYPE},
                                    OUTPASS   => $pin,);
    } else {
      my $keydata = CertNanny::Util->readFile($keyfile);
      $newkey->{KEYDATA} = $keydata;

      # the following data is probably not necessary, but we emulate k_convertKey here
      $newkey->{KEYFORMAT} = $self->{KEYFORMAT};
      $newkey->{KEYTYPE}   = $self->{KEYTYPE};
      $newkey->{KEYPASS}   = $pin;
    }

    if (!defined $newkey) {
      CertNanny::Logging->error("Could not read/convert new key");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
      return undef;
    }

    push(@newkeystore, {DESCRIPTION => "End entity private key",
                        DSTFILE     => $entry->{key}->{file},
                        SRCCONTENT  => $newkey->{KEYDATA}});
  } ## end unless ($self->_hasEngine()...)

  ######################################################################
  ### certificate...
  my $newcert = CertNanny::Util->convertCert(CERTFILE   => $args{CERTFILE},
                                             CERTFORMAT => 'PEM',
                                             OUTFORMAT  => $self->{FORMAT});

  if (!defined $newcert) {
    CertNanny::Logging->error("Could not read/convert new certificate");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
    return undef;
  }

  push(@newkeystore, {DESCRIPTION => "End entity certificate",
                      DSTFILE     => $entry->{location},
                      SRCCONTENT  => $newcert->{CERTDATA}});

  ######################################################################
  ### CA certificates...
  my $ii = 0;
  if (!exists $entry->{cacert}->{$ii}) {

    # cacert.0 does not exist, start with .1
    $ii = 1;
  }
  while (exists $entry->{cacert}->{$ii}
         && defined $self->{STATE}->{DATA}->{CERTCHAIN}[$ii]) {

    # determine CA certificate for this level
    my $item = $self->{STATE}->{DATA}->{CERTCHAIN}[$ii];
    ### $item

    my $destfile = $entry->{cacert}->{$ii};
    ### $destfile

    my $cacert = CertNanny::Util->convertCert(CERTFILE   => $item->{CERTFILE},
                                              CERTFORMAT => 'PEM',
                                              OUTFORMAT  => $self->{CACERTFORMAT});

    if (defined $cacert) {
      push(@newkeystore, {DESCRIPTION => "CA certificate level $ii",
                          DSTFILE     => $destfile,
                          SRCCONTENT  => $cacert->{CERTDATA}});
    } else {
      CertNanny::Logging->error("Could not convert CA certificate for level $ii");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
      return undef;
    }
    $ii++;
  } ## end while (exists $self->{OPTIONS...})

  ######################################################################
  # try to write root certificates

  if (exists $entry->{rootcacertbundle}) {
    my $fh =
      new IO::File(">" . $entry->{rootcacertbundle});
    if (!$fh) {
      CertNanny::Logging->error("installCert(): Could not create Root CA certificate bundle file");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
      return undef;
    }

    foreach my $item (@{$self->{STATE}->{DATA}->{ROOTCACERTS}}) {
      my $cert = CertNanny::Util->convertCert(OUTFORMAT  => 'PEM',
                                              CERTFILE   => $item->{CERTFILE},
                                              CERTFORMAT => 'PEM');

      if (!defined $cert) {
        CertNanny::Logging->error("installCert(): Could not convert root certificate $item->{CERTFILE}");
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
        return undef;
      }

      my $data = $cert->{CERTDATA};
      chomp $data;
      print $fh $data;
      print $fh "\n";
    } ## end foreach my $item (@{$self->...})

    $fh->close();
  } ## end if (exists $self->{OPTIONS...})

  if (exists $entry->{rootcacertdir}) {

    # write root certs to specified directory, possibly with the
    # template name used here.

    my $path             = $entry->{rootcacertdir};
    my $rootcacertformat = $self->{ROOTCACERTFORMAT};

    # prepare default template
    my ($volume, $dir, $template) = ('', $path, 'root-%i.' . lc($rootcacertformat));

    # overwrite template if explicitly defined
    if (!-d $path) {
      ($volume, $dir, $template) = File::Spec->splitpath($path);
    }

    # reconstruct target directory
    $dir = File::Spec->catpath($volume, $dir);

    # sanity check
    if (!-d $dir || !-w $dir) {
      CertNanny::Logging->error("installCert(): Root CA certificate target directory $dir does not exist or is not writable");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
      return undef;
    }

    my $ii = 1;
    foreach my $item (@{$self->{STATE}->{DATA}->{ROOTCACERTS}}) {
      my $cert = CertNanny::Util->convertCert(CERTFORMAT => 'PEM',
                                              CERTFILE   => $item->{CERTFILE},
                                              OUTFORMAT  => $rootcacertformat);

      if (!defined $cert) {
        CertNanny::Logging->error("installCert(): Could not convert root certificate $item->{CERTFILE}");
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
        return undef;
      }

      my $filename = $template;

      # replace tags
      $filename =~ s{%i}{$ii}xmsg;

      $filename = File::Spec->catfile($dir, $filename);

      if (!CertNanny::Util->writeFile(SRCCONTENT => $cert->{CERTDATA},
                                      DSTFILE    => $filename,
                                      FORCE      => 1)
        ) {
        CertNanny::Logging->error("installCert(): Could not write root certificate $filename");
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
        return undef;
      }

      $ii++;
    } ## end foreach my $item (@{$self->...})
  } ## end if (exists $self->{OPTIONS...})

  ######################################################################
  # try to write the new keystore

  if (!$self->k_saveInstallFile(@newkeystore)) {
    CertNanny::Logging->error("Could not install new keystore");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
    return undef;
  }
  
  $self->installCertChain();

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "installs a new main certificate from the SCEPT server in the keystore");
  return 1;
} ## end sub installCert


sub getKey {
  ###########################################################################
  #
  # get private key for main certificate from keystore
  # 
  # Input: caller must provide a hash ref containing the unencrypted private 
  #        key in OpenSSL format
  # 
  # Output: caller gets a hash ref (as expected by k_convertKey()):
  #           KEYDATA   => string containg the private key OR
  #           KEYTYPE   => format (e. g. 'PKCS8' or 'OpenSSL'
  #           KEYFORMAT => 'PEM' or 'DER'
  #           KEYPASS   => key pass phrase (only if protected by pass phrase)
  #         or undef on error
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get private key for main certificate from keystore");
  my $self     = shift;
  
  my $options  = $self->{OPTIONS};
  my $entry    = $options->{ENTRY};

  my $rc = undef;

  if ($self->_hasEngine()) {
    $rc = ($self->{HSM}->can('getKey')) ? $self->{HSM}->getKey() : $entry->{key}->{file};
  } else {
    my $keydata = CertNanny::Util->readFile($entry->{key}->{file});
    if (!defined $keydata || ($keydata eq "")) {
      CertNanny::Logging->error("getKey(): Could not read private key");
    } else {
      my $pin       = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{key}->{pin};
      my $keyformat = ($keydata =~ m{ -----BEGIN.*KEY----- }xms) ? 'PEM' : 'DER';

      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get private key for main certificate from keystore");
      $rc = {KEYDATA   => $keydata,
             KEYTYPE   => $self->{KEYTYPE},
             KEYFORMAT => $keyformat,
             KEYPASS   => $pin};
      $self->{myKey} = $rc;
    }
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get private key for main certificate from keystore");
  return $rc
} ## end sub getKey


sub getCertLocation {
  ###########################################################################
  #
  # get the key specific locations for certificates
  # 
  # Input: caller must provide a hash ref containing 
  #           TYPE      => TrustedRootCA or CAChain
  #                        Default: TrustedRootCA
  # 
  # Output: caller gets a hash ref:
  #           <locationname in lowercase> => <Location>
  #         or undef on error
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get the key specific locations for certificates");
  my $self = shift;
  my %args = (TYPE => 'TrustedRootCA',
              @_);
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $rc = undef;

  if ($args{TrustedRootCA}) {
    foreach ('Directory', 'File', 'ChainFile') {
      if (my $location = $config->get("keystore.$entryname.TrustedRootCA.GENERATED.$_", 'FILE')) {
        $rc->{lc($_)} = $location;
      }
    }
  }
#  if ($args{CAChain}) {
#    foreach ('Directory', 'File') {
#      if (my $location = $config->get("keystore.$entryname.CAChain.GENERATED.$_", 'FILE')) {
#        $rc->{lc($_)} = $location;
#      }
#    }
#  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get the key specific locations for certificates");
  return $rc
} ## end sub getKey


sub createRequest {
  ###########################################################################
  #
  # generate a certificate request
  # 
  # Input: -
  # 
  # Output: caller gets a hash ref:
  #           KEYFILE     => file containing the key data (will
  #                          only be generated if not initial 
  #                          enrollment)
  #           REQUESTFILE => file containing the CSR
  # 
  # This method should generate a new private key and certificate request.
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key and PKCS#10 request 'outside' of
  # your keystore and import this information later.
  # In this case use the following code:
  # sub createRequest {
  #   my $self = shift;
  #   return $self->SUPER::createRequest(@_) if $self->can("SUPER::createRequest");
  # }
  #
  # If you are able to directly operate on your keystore to generate keys
  # and requests, you might choose to do all this yourself here:
  my $self = shift;
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  CertNanny::Logging->info("Creating request");

  my $result = undef;

  if (defined  $entry->{INITIALENROLLEMNT} and 
 	  $entry->{INITIALENROLLEMNT} eq 'yes' and 
 	  ($entry->{initialenroll}->{auth}->{mode} eq 'password' or $entry->{initialenroll}->{auth}->{mode} eq 'anonymous')) {
    $result = {KEYFILE => File::Spec->catfile($entry->{statedir}, $entryname . "-key.pem")};
    CertNanny::Logging->debug("Skip key generation in initialenrollment its already generated for selfsign certificate");
  } else {
    $result = $self->generateKey();
  }

  if (!defined $result) {
    CertNanny::Logging->error("Key generation failed");
    return undef;
  }

  $result->{REQUESTFILE} = File::Spec->catfile($entry->{statedir}, $entryname . ".csr");

  if ($self->_hasEngine() and $self->{HSM}->can('createRequest')) {
    CertNanny::Logging->debug("Creating new CSR with HSM.");
    $result = $self->{HSM}->createRequest($result);
  } else {
    my $pin = $self->{PIN} || $entry->{key}->{pin} || "";
    CertNanny::Logging->debug("Creating new CSR with native OpenSSL functionality.");

    my $openssl = $config->get('cmd.openssl', 'FILE');
    if (!defined $openssl) {
      CertNanny::Logging->error("No openssl shell specified");
      return undef;
    }

    my $DN;
    #for inital enrollment we override the DN to use the configured desiered DN rather then the preset enrollment certificates DN
    if ($entry->{INITIALENROLLEMNT} eq 'yes') {
      $DN = $entry->{initialenroll}->{subject};
    } else {
      $DN = $self->{CERT}->{CERTINFO}->{SubjectName};
    }
    CertNanny::Logging->debug("DN: $DN");

    # split DN into individual RDNs. This regex splits at the ','
    # character if it is not escaped with a \ (negative look-behind)
    my @RDN = split(/(?<!\\),\s*/, $DN);
    my %RDN_Count;
    foreach (@RDN) {
      my ($key, $value) = (/(.*?)=(.*)/);
      $RDN_Count{$key}++;
    }

    # delete all entries that only showed up once
    # all other keys now indicate the total number of appearance
    map {delete $RDN_Count{$_} if ($RDN_Count{$_} == 1);} keys %RDN_Count;

    # create OpenSSL config file
    my $config_options = CertNanny::Util->getDefaultOpenSSLConfig();
    $config_options->{req} = [];
    push(@{$config_options->{req}}, {prompt             => "no"});
    push(@{$config_options->{req}}, {distinguished_name => "req_distinguished_name"});

    # handle subject alt names from inital configuration information
    my $newsans = '';
    if ($entry->{INITIALENROLLEMNT} eq 'yes') {
      CertNanny::Logging->debug("Add SANs for initial enrollment");
      if (exists $entry->{initialenroll}->{san}) {
        push(@{$config_options->{req}}, {req_extensions => "v3_ext"});
      SANS:
        foreach my $key (keys %{$entry->{initialenroll}->{san}}) {
          next SANS if ($key eq 'INHERIT');
          $newsans .=
            $entry->{initialenroll}->{san}->{$key} . ',';
        }
        ##write inittal enrollment SANs into the cert information without last ','
        $self->{CERT}->{CERTINFO}->{SubjectAlternativeName} = substr($newsans, 0, -1);
      } ## end if (exists $self->{OPTIONS...})

    } else {
      if (exists $self->{CERT}->{CERTINFO}->{SubjectAlternativeName}) {
        push(@{$config_options->{req}}, {req_extensions => "v3_ext"});
      }
    }

    $config_options->{req_distinguished_name} = [];
    foreach (reverse @RDN) {
      my $rdnstr = "";
      my ($key, $value) = (/(.*?)=(.*)/);
      if (exists $RDN_Count{$key}) {
        $rdnstr = $RDN_Count{$key} . ".";
        $RDN_Count{$key}--;
      }

      $rdnstr .= $key;
      push(@{$config_options->{req_distinguished_name}}, {$rdnstr => $value});
    } ## end foreach (reverse @RDN)

    if (exists $self->{CERT}->{CERTINFO}->{SubjectAlternativeName}) {
      my $san = $self->{CERT}->{CERTINFO}->{SubjectAlternativeName};
      $san =~ s{ IP\ Address: }{IP:}xmsg;
      $config_options->{v3_ext} = [];
      push(@{$config_options->{v3_ext}}, {subjectAltName => $san});
    }

    if ($entry->{INITIALENROLLEMNT} eq 'yes') {
      CertNanny::Logging->debug("Enter initial enrollment section");

      if (exists $entry->{initialenroll}->{profile} && $entry->{initialenroll}->{profile} ne '') {
        CertNanny::Logging->debug("Found initial enroll profile: " . $entry->{initialenroll}->{profile});
        push(@{$config_options->{v3_ext}}, {'1.3.6.1.4.1.311.20.2' => 'DER:' . CertNanny::Util->encodeBMPString($entry->{initialenroll}->{profile})});
      }

      if (exists $entry->{initialenroll}->{auth}->{challengepassword} && $entry->{initialenroll}->{auth}->{challengepassword} ne '') {
        CertNanny::Logging->debug("Add challenge Password to CSR");
        push(@{$config_options->{req}},            {attributes          => "req_attributes"});
        push(@{$config_options->{req_attributes}}, {'challengePassword' => $entry->{initialenroll}->{auth}->{challengepassword}});
      }

    } ## end if ($entry->{INITIALENROLLEMNT...})

    my @engine_cmd;
    if ($self->_hasEngine()) {
      my $hsm = $self->{HSM};
      CertNanny::Logging->debug("Setting required engine parameters for HSM.");
      my $engine_id = $hsm->engineid();
      push(@engine_cmd, '-engine', $engine_id);

      if ($hsm->keyform()) {
        push(@engine_cmd, '-keyform', $hsm->keyform());
      }

      my $engine_config = $self->{HSM}->getEngineConfiguration();
      if ($engine_config) {
        my $engine_section = "${engine_id}_section";
        $config_options->{engine_section} = [];
        push(@{$config_options->{engine_section}}, {$engine_id => "${engine_id}_section"});
        $config_options->{$engine_section} = $engine_config;
      }
    } ## end if ($self->k_hasEngine)
    CertNanny::Logging->debug("config_options ");
    my $tmpconfigfile = CertNanny::Util->writeOpenSSLConfig($config_options);

    #CertNanny::Logging->debug("The following configuration was written to $tmpconfigfile:\n" . CertNanny::Util->readFile($tmpconfigfile));

    # generate request
    # Todo pgk: Testen runCommand
    my @cmd = (qq("$openssl"), 'req', '-config', qq("$tmpconfigfile"), '-new', '-sha1', '-out', qq("$result->{REQUESTFILE}"), '-key', qq("$result->{KEYFILE}"),);
    push(@cmd, ('-passin', 'env:PIN')) unless $pin eq "";
    push(@cmd, @engine_cmd);
    $ENV{PIN} = $pin;
    if (CertNanny::Util->runCommand(\@cmd) != 0) {
      CertNanny::Logging->error("Request creation failed");
      delete $ENV{PIN};
      unlink $tmpconfigfile;
      return undef;
    }
    delete $ENV{PIN};
    unlink $tmpconfigfile;
  } ## end else [ if ($self->k_hasEngine()...)]

  return $result;
} ## end sub createRequest


sub selfSign {
  ###########################################################################
  #
  # sign the ceritifate
  # 
  # Input: -
  # 
  # Output: caller gets a hash ref:
  #           CERT => file containing the signed certificate
  # 
  # This signs the current certifiate
  # This method should selfsign the current certificate.
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub selfSign {
  #   my $self = shift;
  #   return $self->SUPER::selfSign(@_) if $self->can("SUPER::selfSign");
  # }
  #
  # If you are able to directly operate on your keystore to generate keys
  # and requests, you might choose to do all this yourself here:
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $openssl      = $config->get('cmd.openssl', 'FILE');
  my $selfsigncert = $entryname . "-selfcert.pem";
  my $outfile      = File::Spec->catfile($entry->{statedir}, $selfsigncert);
  my $pin          = $self->{PIN} || $entry->{key}->{pin} || "";

  ######prepere openssl config file##########

  my $DN;
  #for inital enrollment we override the DN to use the configured desiered DN rather then the preset enrollment certificates DN
  if ($entry->{INITIALENROLLEMNT} eq 'yes') {
    $DN = $entry->{initialenroll}->{subject};
  } else {
    $DN = Net::Domain::hostfqdn();
  }
  CertNanny::Logging->debug("DN: $DN");

  # split DN into individual RDNs. This regex splits at the ','
  # character if it is not escaped with a \ (negative look-behind)
  my @RDN = split(/(?<!\\),\s*/, $DN);

  my %RDN_Count;
  foreach (@RDN) {
    my ($key, $value) = (/(.*?)=(.*)/);
    $RDN_Count{$key}++;
  }

  # delete all entries that only showed up once
  # all other keys now indicate the total number of appearance
  map {delete $RDN_Count{$_} if ($RDN_Count{$_} == 1);} keys %RDN_Count;

  my $config_options = CertNanny::Util->getDefaultOpenSSLConfig();
  $config_options->{req} = [];
  push(@{$config_options->{req}}, {prompt             => "no"});
  push(@{$config_options->{req}}, {distinguished_name => "req_distinguished_name"});

  $config_options->{req_distinguished_name} = [];
  foreach (reverse @RDN) {
    my $rdnstr        = "";
    my ($key, $value) = (/(.*?)=(.*)/);
    if (exists $RDN_Count{$key}) {
      $rdnstr = $RDN_Count{$key} . ".";
      $RDN_Count{$key}--;
    }

    $rdnstr .= $key;
    push(@{$config_options->{req_distinguished_name}}, {$rdnstr => $value});
  } ## end foreach (reverse @RDN)

  my $tmpconfigfile = CertNanny::Util->writeOpenSSLConfig($config_options);
  CertNanny::Logging->debug("The following configuration was written to $tmpconfigfile:\n" . CertNanny::Util->readFile($tmpconfigfile));

  # generate request
  my @cmd = (qq("$openssl"), 'req', '-config', qq("$tmpconfigfile"), '-x509', '-new', '-sha1', '-out', qq("$outfile"), '-key', qq("$entry->{key}->{file}"),);

  push(@cmd, ('-passin', 'env:PIN')) unless $pin eq "";
  $ENV{PIN} = $pin;
  if (CertNanny::Util->runCommand(\@cmd) != 0) {
    CertNanny::Logging->error("Selfsign certifcate creation failed!");
    delete $ENV{PIN};
  }

  #    openssl req -x509 -days 365 -new -out self-signed-certificate.pem
  #	-key pub-sec-key.pem

  return {CERT => $outfile};
} ## end sub selfSign


sub _hasEngine {
  my $self = shift;
 
  return defined $self->{HSM};
}


sub generateKey {
  ###########################################################################
  #
  # generate a new keypair
  # 
  # Input: -
  # 
  # Output: caller gets a hash ref:
  #           KEYFILE     => mandatory: file containing the key data (will
  #                          only be generated if not initial 
  #                          enrollment)
  #           REQUESTFILE => optional: file containing the CSR
  # 
  # This method should generate a new private key.
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub generateKey {
  #   my $self = shift;
  #   return $self->SUPER::generateKey(@_) if $self->can("SUPER::generateKey");
  # }
  #
  # If you are able to directly operate on your keystore to generate keys,
  # you might choose to do all this yourself here:
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "generateKey");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = undef;
  my $outfile;
  
#  if ($entry->{type} ne 'OpenSSL' && $entry->{type} ne 'PKCS12') {
    # Only valid for OpenSSL Key all others should implement by themselfs or they get an error
#    CertNanny::Logging->error("WRONG GENERATE KEY! ");
#  } else {
    my $keyfile = $entryname . "-key.pem";
    $outfile = File::Spec->catfile($entry->{statedir}, $keyfile);

    # Todo Arkadius: Ist $self und $entry hier nicht dasselbe -> Groß-/Kleinschreibung der elemente ?!?
    my $pin        = $self->{PIN}        || $entry->{key}->{pin} || "";
    my $bits       = $self->{SIZE}       || $entry->{size}       || '2048';
    my $engine     = $self->{ENGINE}     || $entry->{engine}     || 'no';
    my $enginetype = $self->{ENGINETYPE} || $entry->{enginetype} || 'none';
    my $enginename = $self->{ENGINENAME} || $entry->{enginename} || 'none';

    #TODO sub generateKey Doku!
    if ($self->_hasEngine() and $self->{HSM}->can('genkey')) {
      CertNanny::Logging->debug("Generating a new key using the configured HSM.");
      my $hsm = $self->{HSM};
      $outfile = $hsm->genkey();
      unless ($outfile) {
        $rc = CertNanny::Logging->error("HSM could not generate new key.");
      }
    } else {
      CertNanny::Logging->debug("Generating a new key using native OpenSSL functionality.");
      # Todo pgk: Testen $config->get
      my $openssl = $config->get('cmd.openssl', 'FILE');
      if (!defined $openssl) {
        $rc = CertNanny::Logging->error("No openssl shell specified");
      }

      if (!$rc) {
        my @passout = ();
        if (defined $pin and $pin ne "") {
          @passout = ('-des3', '-passout', 'env:PIN');
        }

        my @engine_cmd;
        if ($self->_hasEngine()) {
          CertNanny::Logging->debug("Since an engine is used, setting required command line parameters.");
          my $hsm = $self->{HSM};
          push(@engine_cmd, '-engine', $hsm->engineid());
          push(@engine_cmd, '-keyform', $hsm->keyform()) if $hsm->keyform();
        }

        # generate key
        my @cmd = (qq("$openssl"), 'genrsa', '-out', qq("$outfile"), @passout, @engine_cmd, $bits);
        $ENV{PIN} = $pin;
        if (CertNanny::Util->runCommand(\@cmd) != 0) {
          delete $ENV{PIN};
          $rc = CertNanny::Logging->error("RSA key generation failed");
        }
      }
    } ## end else [ if ($self->k_hasEngine()...)]
    
    if (!$rc) {
      chmod 0600, $outfile;
      delete $ENV{PIN};
      $rc = {KEYFILE => $outfile};
    }
 # }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "generateKey");
  return $rc;
  # return ({KEYFILE => $outfile});
} ## end sub generateKey


sub createPKCS12 {
  ###########################################################################
  #
  # create pkcs12 file
  # 
  # Input: caller must provide a hash ref:
  #           FILENAME     => mandatory: pkcs12 file to create
  #           FRIENDLYNAME => optional: cert label to be used in pkcs#12 structure
  #           EXPORTPIN    => mandatory: PIN to be set for pkcs#12 structure
  #           CERTFILE     => mandatory: certificate to include in the pkcs#12 file, instance certificate
  #                           if not specified
  #           CERTFORMAT   => mandatory: PEM|DER, instance cert format if not specified
  #           KEYFILE      => mandatory: keyfile, instance key if not specified
  #           PIN          => optional: keyfile pin
  #           CACHAIN      => optional: arrayref containing the certificate info structure of
  #                           CA certificate files to be included in the PKCS#12
  #                           Required keys for entries: CERTFILE, CERTFORMAT, CERTINFO
  # 
  # Output: caller gets a hash ref:
  #           FILENAME    => created pkcs12 file to create
  # 
  # This method should generate a new pkcs12 file 
  # with all the items that are given
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub createPKCS12 {
  #   my $self = shift;
  #   return $self->SUPER::createPKCS12(@_) if $self->can("SUPER::createPKCS12");
  # }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "create pkcs12 file");
  my $self = shift;
  
  my %args = (FILENAME     => undef,
              FRIENDLYNAME => undef,
              EXPORTPIN    => undef,
              CACHAIN      => undef,
              CERTFILE     => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE},
              CERTFORMAT   => 'PEM',
              KEYFILE      => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE},
              PIN          => $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{key}->{pin},
              @_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = undef;
  
  my $certfile = $args{CERTFILE};

  # if ($entry->{type} ne 'OpenSSL' && $entry->{type} ne 'PKCS12') {
    # Only valid for OpenSSL Key all others should implement by themselfs or they get an error
  #  CertNanny::Logging->error("WRONG GENERATE KEY! ");
  #  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "create pkcs12 file");
  # return undef;
  #}
  
  my $openssl = $config->get('cmd.openssl', 'FILE');
  if (!defined $openssl)                 {$rc = CertNanny::Logging->error("No openssl shell specified")}
  if (!$rc && !defined $args{FILENAME})  {$rc = CertNanny::Logging->error("createpks12(): No output file name specified")}
  if (!$rc && !defined $args{CERTFILE})  {$rc = CertNanny::Logging->error("createpks12(): No certificate file specified")}
  if (!$rc && !defined $args{KEYFILE})   {$rc = CertNanny::Logging->error("createpks12(): No key file specified")}
  if (!$rc && !defined $args{EXPORTPIN}) {$rc = CertNanny::Logging->error("createpks12(): No export PIN specified")}

  CertNanny::Logging->debug("Certformat: $args{CERTFORMAT}");

  if (!$rc && (!defined $args{CERTFORMAT} or $args{CERTFORMAT} !~ /^(PEM|DER)$/)) {
    $rc = CertNanny::Logging->error("createpks12(): Illegal certificate format specified")
  }

  if (!$rc) {
    my @cmd;

    # openssl pkcs12 command does not support DER input format, so
    # convert it to PEM first
    # FIXME: use SUPER::k_convertCert?
    if ($args{CERTFORMAT} eq "DER") {
      $certfile = CertNanny::Util->getTmpFile();

      # Todo pgk: Testen runCommand
      @cmd = (qq("$openssl"), 'x509', '-in', qq("$args{CERTFILE}"), '-inform', qq("$args{CERTFORMAT}"), '-out', qq("$certfile"), '-outform', 'PEM',);
      if (CertNanny::Util->runCommand(\@cmd) != 0) {
        $rc = CertNanny::Logging->error("Certificate format conversion failed")
      }
    } ## end if ($args{CERTFORMAT} ...)

    if (!$rc) {
      my @passin = ();
      if (defined $args{PIN} ) {
        @passin = ('-passin', 'env:PIN');
        $ENV{PIN} = $args{PIN};
        CertNanny::Logging->debug("passin set ");
      }
      

      my @passout = ();
      if (defined $args{EXPORTPIN} and $args{EXPORTPIN} ne "") {
        @passout = ('-password', 'env:EXPORTPIN');
        $ENV{EXPORTPIN} = $args{EXPORTPIN};
        CertNanny::Logging->debug("passout set");
      }

      my @name = ();
      if (defined $args{FRIENDLYNAME} and $args{FRIENDLYNAME} ne "") {
        @name = ('-name', qq("$args{FRIENDLYNAME}"));
      }

      my $cachainfile;
      my @cachain = ();
      if (defined $args{CACHAIN} and ref $args{CACHAIN} eq "ARRAY") {
        $cachainfile = CertNanny::Util->getTmpFile;

        # add this temp file
        push(@cachain, '-certfile');
        push(@cachain, qq("$cachainfile"));

        foreach my $entry (@{$args{CACHAIN}}) {
          #my $file = $entry->{CERTFILE};
          my @RDN  = split(/(?<!\\),\s*/, $entry->{CERTINFO}->{SubjectName});
          my $CN   = $RDN[0];
          $CN =~ s/^CN=//;
          CertNanny::Logging->debug("Adding CA certificate '$CN' in $cachainfile");
          my $pemCACert = "-----BEGIN CERTIFICATE-----\n" . $entry->{'CERTINFO'}->{'Certificate'} ."-----END CERTIFICATE-----\n";
              
          if (!CertNanny::Util->writeFile(DSTFILE    => $cachainfile,
	  			  				                      SRCCONTENT => $pemCACert,
		  			  			                      APPEND     => 1)) {
    	      CertNanny::Logging->error("Could not append Root CA into chainfile");        
          } else {
      	    push(@cachain, '-caname');
          	push(@cachain, qq("$CN"));
          }
        } ## end foreach my $entry (@{$args{...}})
      } ## end if (defined $args{CACHAIN...})

      @cmd = (qq("$openssl"), 'pkcs12', '-export', '-out', qq("$args{FILENAME}"), @passout, '-in', qq("$certfile"), '-inkey', qq("$args{KEYFILE}"), @passin, @name, @cachain,);
      if (CertNanny::Util->runCommand(\@cmd) != 0) {
        CertNanny::Logging->error("PKCS#12 export failed");
      } else {
        $rc = {FILENAME => $args{FILENAME}};
      }
      delete $ENV{PIN};
      delete $ENV{EXPORTPIN};
      unlink $certfile if ($args{CERTFORMAT} eq "DER");
      unlink $cachainfile if (defined $cachainfile);
    } else {$rc = undef}
  } else {$rc = undef}

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "create pkcs12 file");
  return $rc;
} ## end sub createPKCS12


sub importP12 {
  ###########################################################################
  #
  # import pkcs12 file
  # 
  # Input: caller must provide a hash ref:
  #           FILE         => mandatory: 'path/file.p12'
  #           PIN          => mandatory: 'file pin'
  #           ENTRYNAME    => optional:  'capi'
  #           CONF         => optional:  Certnanny Configurationhashref
  # 
  # Output: caller gets a hash ref:
  #           FILENAME    => created pkcs12 file to create
  # 
  # examples:
  # $self->importP12({FILE => 'foo.p12', PIN => 'secretpin'});
  # 
  # Import a p12 with private key and certificate into target keystore
  # also adding the certificate chain if required / included.
  # Is used with inital enrollemnt
  # IMPORTANT NOTICE: THIS METHOD MUST BE CALLED IN STATIC CONTEXT, NEVER AS A CLASS METHOD
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub importP12 {
  #   my $self = shift;
  #   return $self->SUPER::importP12(@_) if $self->can("SUPER::importP12");
  # }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "import pkcs12 file");
  my $self = shift;
  my %args = (@_);    # argument pair list

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (!CertNanny::Util->writeFile(DSTFILE    => $entry->{location},
                                  SRCCONTENT => CertNanny::Util->readFile($args{FILE}),
                                  FORCE      => 0)) {
    CertNanny::Logging->error("Could not write new p12 Keystore, file already exists ?!");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "import pkcs12 file");
    return undef;
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "import pkcs12 file");
  return 1;
} ## end sub importP12


sub getInstalledCAs {
  ###########################################################################
  #
  # get all installed root certificates
  #
  # Input:  caller must provide a hash ref:
  #           TARGET      => optional : where should the procedure search for installed
  #                          root certificates (DIRECTORY|FILE|CHAINFILE|LOCATION)
  #                          default: all
  # 
  # Output: caller gets a hash ref:
  #           Hashkey is the SHA1 of the certificate
  #           Hashcontent ist the parsed certificate
  #             - CERTDATA      mandatory: certificate data
  #             - CERTINFO      mandatory: parsed certificat info
  #             - CERTFILE       optional (not present): certificate file
  #             - CERTALIAS      optional (present): certificate alias name
  #             - CERTCREATEDATE optional (present): certificate creation date
  #             - CERTTYPE       optional (present): certificate type
  #
  # Reads the config Parameters
  #   keystore.<name>.TrustedRootCA.GENERATED.Directory
  #   keystore.<name>.TrustedRootCA.GENERATED.File
  #   keystore.<name>.TrustedRootCA.GENERATED.ChainFile
  # and look for Trusted Root Certificates. All found certificates are
  # returned in a Hash
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub getInstalledCAs {
  #   my $self = shift;
  #   return $self->SUPER::getInstalledCAs(@_) if $self->can("SUPER::getInstalledCAs");
  # }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get all installed root certificates");
  my $self = shift;
  my %args = (@_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  #if no root ca location defined return only an empty hash
  my $rc = {};
  
  my %locSearch = ('directory' => $config->get("keystore.$entryname.TrustedRootCA.GENERATED.Directory", 'FILE'),
                   'file'      => $config->get("keystore.$entryname.TrustedRootCA.GENERATED.File",      'FILE'),
                   'chainfile' => $config->get("keystore.$entryname.TrustedRootCA.GENERATED.ChainFile", 'FILE'));

                
  my ($certRef, $certData, $certSha1);
  $self->{installedRootCAs} = {};

  foreach my $locName (keys %locSearch) {  
    # Look for root certificates in keystore.openssl.TrustedRootCA.GENERATED.Directory / File / ChainFile
    if (!defined($args{TARGET}) or (uc($locName) =~ m/^$args{TARGET}/)) {
      if (defined($locSearch{$locName})) {
        CertNanny::Logging->debug("Searching trusted root certificates in $locName <$locSearch{$locName}>.");
        my @certFileList = @{CertNanny::Util->fetchFileList($locSearch{$locName})};
        foreach my $certFile (@certFileList) {
          $certRef = $self->getCert(CERTFILE => $certFile);
          while ($certRef and ($certData = $certRef->{CERTDATA})) {
            my $certInfo = CertNanny::Util->getCertInfoHash(CERTDATA   => $certData,
                                                            CERTFORMAT => 'PEM');
            if (defined($certInfo)) {
              if (my $certTyp = $self->k_getCertType(CERTINFO => $certInfo)) {
                $certSha1 = CertNanny::Util->getCertSHA1(%{$certRef});
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTFILE} = $certFile;
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTDATA} = $certData;
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTINFO} = $certInfo;
                if ($certTyp eq 'installedRootCAs') {
                  $rc->{$certSha1->{CERTSHA1}} = $self->{$certTyp}->{$certSha1->{CERTSHA1}}
                }
              }
            }
            $certRef  = $self->getCert(CERTDATA => $certRef->{CERTREST});
          }
        }
      }
    }
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get all installed root certificates");
  return $rc;
} ## end sub getInstalledCAs


sub installRoots {
  # ToDo pgk Testen: sub installRoots Postinstall Hooks
  ###########################################################################
  #
  # install all available root certificates
  #
  # Input:  caller must provide a hash ref:
  #           TARGET      => optional : where should the procedure install
  #                          root certificates (DIRECTORY|FILE|CHAINFILE|LOCATION)
  #                          default: all three
  # 
  # Output: 1 : failure  0 : success 
  #
  # this function gets a hash of parsed root certificates
  # installs all roots into the keystore depending on keystore type
  # (write files, rebuild kestore, etc.)
  # execute install-root-hook for all certificates that will be new installed
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub installRoots {
  #   my $self = shift;
  #   return $self->SUPER::installRoots(@_) if $self->can("SUPER::installRoots");
  # }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Install all available root certificates");
  my $self = shift;
  my %args = (@_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my %locInstall = ('directory' => $config->get("keystore.$entryname.TrustedRootCA.GENERATED.Directory", 'FILE'),
                    'file'      => $config->get("keystore.$entryname.TrustedRootCA.GENERATED.File",      'FILE'),
                    'chainfile' => $config->get("keystore.$entryname.TrustedRootCA.GENERATED.ChainFile", 'FILE'));

  my $rc = 0;

  my $doSearch = (!defined($args{TARGET}) or defined($locInstall{lc($args{TARGET})}));
  if ($doSearch) {
    my $rootCertHash = $self->k_getAvailableRootCAs();
    if (!defined($rootCertHash)) {
      $rc = CertNanny::Logging->error("No root certificates found in " . $config-get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.Directory", 'FILE'));
    } else {
      # write for TARGET DIRECTORY links: Links every certificate to the target directory
      if (defined($locInstall{'directory'}) && (!defined($args{TARGET}) or ('DIRECTORY' =~ m/^$args{TARGET}/))) {
	      # First clean up the Target directory and get rid of all old certs
        $self->_createLocalCerts(TARGET  => $locInstall{directory},
                                 CLEANUP => 1);

        # For each cert install in target and execute postinstall Hook
        foreach my $item (keys %{$rootCertHash}) {
          $self->_createLocalCerts(SOURCE  => $rootCertHash->{$item}->{CERTFILE},
                                   TARGET  => $locInstall{directory},
                                   CLEANUP => 0);

          $self->{hook}->{Type}   .= 'DIRECTORY' . ','                                                  if (defined($self->{hook}->{Type})   && ($self->{hook}->{Type}   !~ m/DIRECTORY/s));
          $self->{hook}->{File}   .= $rootCertHash->{$item}->{CERTFILE} . ','                           if (defined($self->{hook}->{File})   && ($self->{hook}->{File}   !~ m/$rootCertHash->{$item}->{CERTFILE}/s));
          $self->{hook}->{FP}     .= $rootCertHash->{$item}->{CERTINFO}->{CertificateFingerprint} . ',' if (defined($self->{hook}->{FP})     && ($self->{hook}->{FP}     !~ m/$rootCertHash->{$item}->{CERTINFO}->{CertificateFingerprint}/s));
          $self->{hook}->{Target} .= $locInstall{directory} . ','                                       if (defined($self->{hook}->{Target}) && ($self->{hook}->{Target} !~ m/$locInstall{directory}/s));
        }  
      }  

      if (!defined($args{TARGET}) or ('FILE' =~ m/^$args{TARGET}/) or ('CHAINFILE' =~ m/^$args{TARGET}/)) {
        # write file: Writes all certificates in one PEM file / Chainfile
        if (defined($locInstall{'file'}) or defined($locInstall{'chainfile'})) {
        # write in an tmp-file first just in case ...
          my $tmpFile = CertNanny::Util->getTmpFile();
          foreach my $item (keys %{$rootCertHash}) {
            CertNanny::Util->writeFile(SRCFILE => $rootCertHash->{$item}->{CERTFILE}, 
                                       DSTFILE => $tmpFile,
                                       APPEND  => 1);

            if (defined($locInstall{'file'}) and (!defined($args{TARGET}) or ('FILE' =~ m/^$args{TARGET}/))) {
              $self->{hook}->{Type}   .= 'FILE' . ','                                                       if (defined($self->{hook}->{Type})   && ($self->{hook}->{Type}   !~ m/FILE/s));
              $self->{hook}->{File}   .= $rootCertHash->{$item}->{CERTFILE} . ','                           if (defined($self->{hook}->{File})   && ($self->{hook}->{File}   !~ m/$rootCertHash->{$item}->{CERTFILE}/s));
              $self->{hook}->{FP}     .= $rootCertHash->{$item}->{CERTINFO}->{CertificateFingerprint} . ',' if (defined($self->{hook}->{FP})     && ($self->{hook}->{FP}     !~ m/$rootCertHash->{$item}->{CERTINFO}->{CertificateFingerprint}/s));
              $self->{hook}->{Target} .= $locInstall{file} . ','                                            if (defined($self->{hook}->{Target}) && ($self->{hook}->{Target} !~ m/$locInstall{file}/s));
            }

            if (defined($locInstall{'chainfile'}) and (!defined($args{TARGET}) or ('CHAINFILE' =~ m/^$args{TARGET}/))) {
              $self->{hook}->{Type}   .= 'CHAINFILE' . ','                                                  if (defined($self->{hook}->{Type})   && ($self->{hook}->{Type}   !~ m/CHAINFILE/s));
              $self->{hook}->{File}   .= $rootCertHash->{$item}->{CERTFILE} . ','                           if (defined($self->{hook}->{File})   && ($self->{hook}->{File}   !~ m/$rootCertHash->{$item}->{CERTFILE}/s));
              $self->{hook}->{FP}     .= $rootCertHash->{$item}->{CERTINFO}->{CertificateFingerprint} . ',' if (defined($self->{hook}->{FP})     && ($self->{hook}->{FP}     !~ m/$rootCertHash->{$item}->{CERTINFO}->{CertificateFingerprint}/s));
              $self->{hook}->{Target} .= $locInstall{chainfile} . ','                                       if (defined($self->{hook}->{Target}) && ($self->{hook}->{Target} !~ m/$locInstall{chainfile}/s));
            }
          }

          # Target file part is finished. now write Target
          if (defined($locInstall{'file'}) and (!defined($args{TARGET}) or ('FILE' =~ m/^$args{TARGET}/))) {
            # put tmp-file to the right location     
            if (!File::Copy::copy($tmpFile, $locInstall{'file'})) {
              CertNanny::Logging->error("Could not install new TrusteRootCA File to " . $locInstall{'file'} . ".");
            }
          }

          # continue with target chainfile
          if (defined($locInstall{'chainfile'}) and (!defined($args{TARGET}) or ('CHAINFILE' =~ m/^$args{TARGET}/))) {
            # in addition to the Root Certs, the chainfile also keeps the chain
            $self->k_getCaCerts();
            if (my $chainArrRef = $self->k_buildCertificateChain($self->getCert())) {
              # delete root
              #CertNanny::Logging->debug("chainfile: ". Dumper($chainArrRef));
              shift(@$chainArrRef);
              # delete EE
              #pop(@$chainArrRef);
              # all others add to chainfile
              while (my $cert = shift($chainArrRef)) {
                CertNanny::Util->writeFile(DSTFILE => $tmpFile,
                                           SRCFILE => $cert->{CERTFILE}, 
                                           APPEND  => 1);

                $self->{hook}->{Type}   .= 'CHAINFILE' . ','                                 if (defined($self->{hook}->{Type})   &&  $self->{hook}->{Type}   !~ m/CHAINFILE/);
                $self->{hook}->{File}   .= $cert->{CERTFILE} . ','                           if (defined($self->{hook}->{File})   &&  $self->{hook}->{File}   !~ m/$cert->{CERTFILE}/);
                $self->{hook}->{FP}     .= $cert->{CERTINFO}->{CertificateFingerprint} . ',' if (defined($self->{hook}->{FP})     &&  $self->{hook}->{FP}    !~ m/$cert->{CERTINFO}->{CertificateFingerprint}/);
                $self->{hook}->{Target} .= $locInstall{chainfile} . ','                      if (defined($self->{hook}->{Target}) &&  $self->{hook}->{Target} !~ m/$locInstall{chainfile}/);
              }    
              # Target chainfile part is finished. now write Target
              # put tmp-file to the right location     
              if (!File::Copy::copy($tmpFile, $locInstall{'chainfile'})) {
                CertNanny::Logging->error("Could not install new TrusteRootCA ChainFile to " . $locInstall{'file'} . ".");
              }
            }    
          }
          eval {unlink($tmpFile)};
        }  
      }
    }
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Install all available root certificates");
  return $rc;
} ## end sub installRoots


sub installCertChain {
  ###########################################################################
  #
  # install certchain file
  #
  #
  ###########################################################################
  
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Install installCertChain");
  my $self = shift;
  my %args = (@_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = 0;

  my %locInstall = ('file'      => $config->get("keystore.$entryname.CAChain.GENERATED.File",      'FILE'));
          
     # write file: Writes all certificates in one PEM file / Chainfile
    if (defined($locInstall{'file'}) or defined($locInstall{'chainfile'})) {
 
       #delete old chainfile 
       unlink $locInstall{'file'}; 
       CertNanny::Logging->debug("install chain file locInstall{'file'}");
         
       if (my $chainArrRef = $self->k_buildCertificateChain($self->getCert())) {
        
        my @certChain =  @{$chainArrRef};
        my @reversedChain = reverse @certChain ;
             
        foreach my $cert (@reversedChain){
          CertNanny::Logging->debug("cert chain cert: " . $cert->{'CERTINFO'}->{'SubjectName'});
          if( !CertNanny::Util->writeFile(DSTFILE =>  $locInstall{'file'},
                                            SRCFILE => $cert->{CERTFILE}, 
                                            APPEND  => 1)) {                                                     
            $rc = CertNanny::Logging->error("installCertChain(): failed to wire cert chain file");                   
          }       
        }    
       } 
     }
  

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Install installCertChain");
  return $rc;
} ## end sub installRoots




sub _createLocalCerts {
  ###########################################################################
  #
  # create certificate symlinks or copies in the target directory
  #
  # Input: caller must provide a hash ref:
  #           SOURCE  => optional:  certificate directory
  #           TARGET  => mandatory: link or copy directory
  #           COPY    => optional:  copy or link the files (default no)
  #           CLEANUP => optional:  deletes all valid certificates in the 
  #                      link directory before starting to link (default yes)
  #
  # Output: 0: successfull
  #         1: failed
  #
  # scan certificate directory and copy or link the found certificates to the 
  # target directory. If no CERTDIR is given, the procedure only cleans the 
  # target directory (if CLEANUP is not disbled)
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "create certificate symlinks or copies in the target directory");
  my $self         = shift;
  my %args = (CLEANUP   => 1,
              COPY      => 0,
              @_);
  
  my $certSourceGlob = $args{SOURCE};
  my $certTargetDir  = $args{TARGET};
  my $copy           = $args{COPY};
  my $cleanup        = $args{CLEANUP};

  my ($rc, $tryCopy, $cert, @certFileList, $certFile, $certSHA1, %certSHA1Hash, $cmdTemplate, @subject_hashs, $subject_hash, $target);
  $rc = 0;

  if ($cleanup) {
    # Delete every certificate in the target directory, but only if it is a certificate
    @certFileList = @{CertNanny::Util->fetchFileList($certTargetDir)};
    foreach $certFile (@certFileList) {
      $certSHA1 = CertNanny::Util->getCertSHA1(CERTFILE => $certFile);
      if (defined($certSHA1) and defined($certSHA1->{CERTSHA1})) {
        unlink $certFile if defined($certSHA1);
      }
    }
  }
  
  if ($certSourceGlob) {
    # Get all files from certificate source directory
    @certFileList = @{CertNanny::Util->fetchFileList($certSourceGlob)};

    # Test if it's a certificate or just rubbish
    $cmdTemplate = '"' . $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE') . '" x509 -subject_hash -subject_hash_old -noout -in "%s"';

    foreach $certFile (@certFileList) {
      chomp(@subject_hashs = CertNanny::Util->runCommand(sprintf($cmdTemplate, $certFile), WANTOUT => 1));
      if (@subject_hashs) {
        CertNanny::Logging->info("Valid certificate found: $certFile");

        $certSHA1 = CertNanny::Util->getCertSHA1(CERTFILE => $certFile);
        $certSHA1 = $certSHA1->{CERTSHA1} if (defined($certSHA1));
        foreach $subject_hash (@subject_hashs) {
          # find out, whether we already have this file in the linkdirectory
          my $makeTarget  = 1;
          my $counter     = 0;
          foreach my $targetFile (keys %certSHA1Hash) {
            my ($targetName, $dummy, $targetNumber) = fileparse($targetFile, qr{\..*});
            # Find all files in the linkdirectory that match $subject_hash.*
            if ($makeTarget && ($subject_hash eq $targetName)) {
              # compare SHA1 of the file in the linkdirectory with the one to be linked
              if ($certSHA1 eq $certSHA1Hash{$targetFile}) {
                # SHA1 is equal => same file, nothing to do
                $target = File::Spec->catfile($certTargetDir, $subject_hash) . $targetNumber;
                CertNanny::Logging->info("Not linking certificate $certFile: Certificate with identical Fingerprint and SHA1 already exists ($target)");
                $makeTarget = 0;
              } else {
                # SHA1 is not equal => same fingerprint, but different SHA1 => make a link with
                # incremented counter as file extension
                $counter = reverse($targetNumber);
                chop($counter);
                $counter = reverse($counter);
                $counter++;
                CertNanny::Logging->info("Identical Certificate $certFile with different fingerprint found. Setting filecounter to $counter");
              }
            }
          }
        
          if ($makeTarget) {
            # try to link the file, if it fails (e.g. for Windows Systems) try a copy file to desired location
            $certTargetDir = File::Spec->canonpath($certTargetDir);
            eval {File::Path::mkpath($certTargetDir)};
            $target = File::Spec->catfile($certTargetDir, $subject_hash) . '.' . $counter;
            unlink $target if (-e $target);
            $tryCopy = $copy;
            if (!$tryCopy) {
              if (link $certFile, $subject_hash) {
                CertNanny::Logging->info("Certificate $certFile linked to $target");
              } else {
                $tryCopy = 1;
              }
            }

            if ($tryCopy) {
              if (File::Copy::copy($certFile, $target)) {
                CertNanny::Logging->info("Certificate $certFile copied to $target");
              } else {
                CertNanny::Logging->fatal("File creation error: $certFile link/copy to $target");
                $rc = 1;
              }
            }
            $certSHA1Hash{$target} = $certSHA1 if defined($certSHA1);
          }
        }
      } else {
        CertNanny::Logging->info("Not a valid certificate: " . $certFile);
      }
    } ## end foreach my $certFile (@certFileList)
  } ## end if ($certSourceGlob)

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "create certificate symlinks or copies in the target directory");
  return $rc;
} ## end sub _createLocalCerts


sub _writeRootCAFile {
  # Input: filename, where all found RootCA are written to
  #
  # Output: 0: successfull
  #         1: failed
  #
  # fetch all certificates from rootCaDirectory and
  # concatenate all certificates in one PEM file
  my $self         = shift;
  my $certFileGlob = shift;
  my $certLinkDir  = shift;

  # list of trusted root certificates
  my @trustedroots = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};
  ### @trustedroots

  my %rootcertfingerprint;
  foreach my $entry (@trustedroots) {
    my $fingerprint = $entry->{CERTINFO}->{CertificateFingerprint};
    $rootcertfingerprint{$fingerprint}++;
  }
} ## end sub writeRootCAFile


sub _writeCAChainFile {

  # Input: filename
  #        EECert
  #        Order (reverse|forward)
  #
  # Output: 0: successfull
  #         1: failed
  #
  # fetch all certificates from rootCaDirectory and
  # concatenate whole certificates chain in one PEM file
  my $self  = shift;
  my $cert  = shift;
  my $order = shift;


#getCert
#
#  $scepCertChain = $self->k_buildCertificateChain($scepracert);
#
#  foreach my $cert (@{$scepCertChain}) {
#    #CertNanny::Logging->debug("Each ele: $cert " .ref ($cert) . Dumper($cert) );
#    $pemchain .= "-----BEGIN CERTIFICATE-----\n" . $cert->{CERTINFO}->{Certificate} . "-----END CERTIFICATE-----\n"
#
#  }
#
#  if (!CertNanny::Util->write_file(FILENAME => $certchainfile,
#                                   CONTENT  => $pemchain,
#                                   FORCE    => 1,)
#    ) {
#    CertNanny::Logging->error("Could not write certificatechain file");
#    return undef;
#  }
#
#  my $enroller = $self->_getEnroller();
#  my %certs    = $enroller->getNextCA($certchainfile);
#
#  if (%certs) {

  return undef;
} ## end sub writeCAChainFile


1;
