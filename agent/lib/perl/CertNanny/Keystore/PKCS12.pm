#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005 - 2007 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::PKCS12;

use base qw(Exporter CertNanny::Keystore::OpenSSL);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

# use IO::File;
use File::Spec;
use File::Copy;
# use File::Basename;
use Data::Dumper;

use CertNanny::Util;

# keyspecific needed modules
use English;

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

  # plausi check
  if (!$config->get('cmd.openssl', 'FILE')) {
    CertNanny::Logging->error("No openssl shell specified");
    return undef;
  }

  # export the pin to this instance
  $self->{PIN} = $config->get("keystore.$entryname.key.pin");

  # sample sanity checks for configuration settings
  foreach my $parameter (qw(location)) {
    if (!defined $entry->{$parameter} || (!-r $entry->{$parameter})) {
      croak("keystore.$parameter $entry->{$parameter} not defined, does not exist or unreadable");
      return undef;
    }
  }

  # the rest should remain untouched

  # RETRIEVE AND STORE STATE
  # get previous renewal status
  $self->k_retrieveState() || return undef;

  # check if we can write to the file
  $self->k_storeState()    || croak "Could not write state file $self->{STATE}->{FILE}";

  # return new keystore object
  return $self;
} ## end sub new


sub DESTROY {
  # you may add additional destruction code here but be sure to retain
  # the call to the parent destructor
  my $self = shift;

  # check for an overridden destructor...
  $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}


sub getCert {
  ###########################################################################
  #
  # Input: caller must provide a hash ref:
  #           CERTFILE   => file containing the cert OR
  #        or CERTDATA   => string containing the cert
  #        if neither CERTFILE nor CERTDATA ist provided, default is
  #        CERTFILE => $self->{OPTIONS}->{ENTRY}->{location}
  #           CERTTYPE   => optional: CL|CA: CA CA Chain Certs, EE Client Certs
  #
  # Input: caller must provide the file location.
  #        if no file location is provided default is
  #        $self->{OPTIONS}->{ENTRY}->{location}
  #
  # Output: caller gets a hash ref:
  #           CERTDATA   => string containg the cert data
  #           CERTLABEL  => Label of the cert
  #           CERTFORMAT => 'PEM' or 'DER'
  #           CERTREST   => string containing the rest of the input when the 
  #                         first cert is extracted
  #         or undef on error
  #
  # Gets the first certificate found either in CERTDATA or in CERTFILE and 
  # returns it in CERTDATA. 
  # If there is a rest in the input, it is returned in CERTREST
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
  my $self = shift;
  my %args =(CERTTYPE => 'EE',
             @_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = undef;

  if (!defined $args{CERTFILE} && !defined $args{CERTDATA}) {
    $args{CERTFILE} = $config->get("keystore.$entryname.location", 'FILE')
  }
  
  if (defined $args{CERTFILE} && defined $args{CERTDATA}) {
    $rc = CertNanny::Logging->error("getCert(): Either CERTFILE or CERTDATA may be defined.");
  }

  if (!$rc) {
    my ($certHead, $certData, $certFormat, $certLabel, $certRest) = ('', '', '', '', '');
    if (defined $args{CERTFILE}) {
      my @cmd;
      if ($args{CERTTYPE} eq 'CA') {
        @cmd = $self->_buildOpenSSLPKCS12Cmd('-nokeys'  => '-nokeys', 
                                             '-cacerts' => '-cacerts');
      } else {
        @cmd = $self->_buildOpenSSLPKCS12Cmd('-nokeys'  => '-nokeys', 
                                             '-clcerts' => '-clcerts');
      }
      $certData = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1);
      if (!defined($certData)) {
        $rc = CertNanny::Logging->error("getCert(): Could not read instance certificate file $args{CERTFILE}");
      }
    } else {
      $certData = $args{CERTDATA};
    }
  
    if (!$rc) {
      local $/ = undef;
      if ($certData =~ m/(.*?)(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)(.*?)[\n\r]*$/s) {
        chomp($certHead = $1);
        chomp($certData = $2);
        chomp($certRest = $3);
        if ($certHead =~ m{ ^ \s* friendlyName: \s+ (.*?) $ }xms) {$certLabel = $1}
        $certFormat = 'PEM';
      } else {
        # $cerFormat = CertNanny::Util->getCertFormat($certData);
        $certFormat = 'DER';
      }
      $rc = {CERTDATA   => $certData,
             CERTLABEL  => $certLabel,
             CERTFORMAT => $certFormat,
             CERTREST   => $certRest};
    } else {
      $rc = undef;
    }
  } else {
    $rc = undef;
  }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
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
  my $self = shift;
  my %args = (@_);    # argument pair list

  my $data = $self->_getNewPKCS12Data(%args);
  return unless $data;

  my @newkeystore;

  # schedule for installation
  push(@newkeystore, {DESCRIPTION => "PKCS#12 file",
                      FILENAME    => $self->{OPTIONS}->{ENTRY}->{location},
                      CONTENT     => $data});

  if (!$self->k_saveInstallFile(@newkeystore)) {    # if any error happened
    CertNanny::Logging->error("Could not install new keystore");
    return undef;
  }

  # only on success:
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
  #           KEYFORMAT => 'PEM' or 'DER'
  #           KEYTYPE   => format (e. g. 'PKCS8' or 'OpenSSL'
  #           KEYPASS   => key pass phrase (only if protected by pass phrase)
  #         or undef on error
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get private key for main certificate from keystore");
  my $self = shift;

  my $rc = undef;

  my @cmd = $self->_buildOpenSSLPKCS12Cmd('-nocerts' => '-nocerts');
  my $data = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1);
  
  if ($data =~ s{ \A .* (?=-----BEGIN) }{}xms) {
    $rc = {KEYDATA   => $data,
           KEYTYPE   => 'OpenSSL',
           KEYPASS   =>  $self->_getPin(),
           KEYFORMAT => 'PEM'};
    $self->{myKey} = $rc;
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get private key for main certificate from keystore");
  return $rc;
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
  return $self->SUPER::createRequest(@_) if $self->can("SUPER::createRequest");
}


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
  my $self     = shift;
  return $self->SUPER::selfSign(@_) if $self->can("SUPER::selfSign");
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
  my $self = shift;
  return $self->SUPER::generateKey(@_) if $self->can("SUPER::generateKey");
}


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
  my $self = shift;
  return $self->SUPER::createPKCS12(@_) if $self->can("SUPER::createPKCS12");
}


sub importP12 {
  ###########################################################################
  #
  # import pkcs12 file
  # 
  # Input: caller must provide a hash ref:
  #           FILENAME     => mandatory: 'path/file.p12'
  #           PIN          => mandatory: 'file pin'
  #           ENTRYNAME    => optional:  'capi'
  #           CONF         => optional:  Certnanny Configurationhashref
  #			  ENTRY         => optional:  Certnanny ENTRY hashref
  # 
  # Output: caller gets a hash ref:
  #           FILENAME    => created pkcs12 file to create
  # 
  # examples:
  # $self->importP12({FILENAME => 'foo.p12', PIN => 'secretpin'});
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
  #my $self = shift;
  my %args = (@_);    # argument pair list

  my $entry     = $args{ENTRY};
  my $config    =  $args{CONFIG};
  #CertNanny::Logging->debug( "import pkcs12 file entry". Dumper($entry));
 
  my $origin = File::Spec->canonpath($args{FILENAME}); 
  my $dest = File::Spec->canonpath($entry->{initialenroll}->{targetLocation});
  
  if(! copy($origin,$dest)){
  	 CertNanny::Logging->error("Could not write new p12 Keystore, file already exists ?!$entry->{location} to $args{FILENAME} ");
#  if (!CertNanny::Util->writeFile(DSTFILE    => $entry->{initialenroll}->{targetLocation},
#                                 SRCFILE => $args{FILENAME} ,
#                                  FORCE      => 0)) {
#    CertNanny::Logging->error("Could not write new p12 Keystore, file already exists ?!$entry->{location} to $args{FILENAME} ");
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
  
  my $rc = {};
  
  my $certFound = {};
  
  # get FILE, DIRECTORY and CHAINFILE if spezified
  $self->{installedRootCAs} = $self->SUPER::getInstalledCAs(\%args) if $self->can("SUPER::getInstalledCAs");

  # get root certs from LOCATION
  my ($certRef, $certData, $certSha1);
  $certRef = $self->getCert(CERTFILE => $config->get("keystore.$entryname.location", 'FILE'),
                            CERTTYPE => 'CA');
  while ($certRef and ($certData = $certRef->{CERTDATA})) {
    my $certInfo = CertNanny::Util->getCertInfoHash(CERTDATA   => $certData,
                                                    CERTFORMAT => 'PEM');
    if (defined($certInfo)) {
      if (my $certTyp = $self->k_getCertType(CERTINFO => $certInfo)) {
        $certSha1 = CertNanny::Util->getCertSHA1(%{$certRef});
        $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTFILE} = $config->get("keystore.$entryname.location", 'FILE');
        $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTDATA} = $certData;
        $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTINFO} = $certInfo;
        if ($certTyp eq 'installedRootCAs') {
          $rc->{$certSha1->{CERTSHA1}} = $self->{$certTyp}->{$certSha1->{CERTSHA1}}
        }
      }
    }
    $certRef  = $self->getCert(CERTDATA => $certRef->{CERTREST});
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get all installed root certificates");
  return $rc;
} ## end sub getInstalledCAs


sub installRoots {
  ###########################################################################
  #
  # install all available root certificates
  #
  # Input:  caller must provide a hash ref:
  #           TARGET      => optional : where should the procedure install
  #                          root certificates (DIRECTORY|FILE|CHAINFILE|LOCATION)
  #                          default: all three
  #           INSTALLED   => mandatory(used) : hash with already installed roots
  #           AVAILABLE   => mandatory(used) : hash with available roots
  # 
  # Output: 1 : failure  0 : success 
  #
  # this function gets a hash of parsed root certificates
  # install all roots into the keystore depending on keystore type
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
  
  my $rc = undef;
  
  # DIRECTORY, FILE and CHAINFILE is identical to the OpenSSL Key, so we use the installRoots of OpenSSL
  $rc = $self->SUPER::installRoots(@_) if $self->can("SUPER::installRoots");

  # only LOCATION is handled in a different way
  if (!$rc && (!defined($args{TARGET}) || ($args{TARGET} eq 'LOCATION'))) {
    # First get the available Root Certs
    my $installedRootCAs = $self->k_getAvailableRootCAs();

    if (!defined($installedRootCAs)) {
      $rc = CertNanny::Logging->error("No root certificates found in " . $config-get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.Directory", 'FILE'));
    } else {
      # If this is ok, let's get the privat key
      my $myKey = $self->getKey();
      my $EECert;
      if (!defined($myKey)) {
        $rc = CertNanny::Logging->error("No private key found in " . $config-get("keystore.$entryname.location", 'FILE'));
      } else {
        # now let's get the certificate
        $EECert = $self->getCert(CERTTYPE => 'EE');
        if (!defined($EECert)) {
          $rc = CertNanny::Logging->error("No EE cert found in " . $config-get("keystore.$entryname.location", 'FILE'));
        } else {
          $EECert->{CERTINFO} = CertNanny::Util->getCertInfoHash(CERTDATA   => $EECert->{CERTDATA},
                                                                 CERTFORMAT => 'PEM');
          # Collect all Certs to be in the PKCS12 file in a list        
          my %certHash;

          # EE Cert is always in the PKCS12 File
          $certHash{CertNanny::Util->getCertSHA1(%{$EECert})->{CERTSHA1}} = $EECert;
          
          # Chain Certs is only in the PKCS12 File if excludeCAChain is NOT set
          if (!$config->getFlag("keystore.$entryname.key.excludeCAChain")) {
            $self->k_getCaCerts();
            my $certChain = $self->k_buildCertificateChain($EECert);
            foreach (@{$certChain}) {
              $certHash{CertNanny::Util->getCertSHA1(%{$_})->{CERTSHA1}} = $_;
            }
          }

          # Trusted Root Certs are only in the PKCS12 File if excludeCAChain is NOT set and excludeRoot is NOT set
          if (!$config->getFlag("keystore.$entryname.key.excludeCAChain") && !$config->getFlag("keystore.$entryname.key.excludeRoot")) {
            foreach (keys($installedRootCAs)) {
              $certHash{$_} = $installedRootCAs->{$_};
            }
          }  

          # Build the command option and concat all certs to be added in an single file
          my $CAListFile = CertNanny::Util->getTmpFile;
    
          # First argument ist the CAListfile Name
          my @CAList     = ();
          push(@CAList, '-certfile', qq("$CAListFile"));
          
          # then collect the certs
          foreach my $item (keys (%certHash)) {
            (my $CN = (split(/(?<!\\),\s*/, $certHash{$item}->{CERTINFO}->{SubjectName}))[0]) =~ s/^CN=//;
            #$CN =~ s/^CN=//;
            CertNanny::Logging->debug("Adding CA certificate '$CN' in $CAListFile");
            my $pemCACert = "-----BEGIN CERTIFICATE-----\n" . $certHash{$item}->{'CERTINFO'}->{'Certificate'} ."-----END CERTIFICATE-----\n";
              
            # concat the certs in the CAListFile
            if (!CertNanny::Util->writeFile(SRCCONTENT => $pemCACert,
                                            DSTFILE    => $CAListFile,
                                            APPEND     => 1)) {
              $rc = CertNanny::Logging->error("Could not append Root CA into chainfile");        
            } else {
              # and collect the certName in the Argumentlist
              push(@CAList, '-caname', qq("$CN"));
            }
          } ## end foreach my $entry (@{$args{...}})

          if (!$rc) {
            my $tmpKey = CertNanny::Util->getTmpFile();
            $rc = !CertNanny::Util->writeFile(SRCCONTENT => $myKey->{KEYDATA},
                                              DSTFILE    => $tmpKey,
                                              FORCE      => 1);
                                              
            my $tmpCert = CertNanny::Util->getTmpFile();
            $rc = $rc || !CertNanny::Util->writeFile(SRCCONTENT => $EECert->{CERTDATA},
                                                     DSTFILE    => $tmpCert,
                                                     FORCE      => 1);
                                              
            my $tmpP12 = CertNanny::Util->getTmpFile();
            if (!$rc) {
              my @cmd = $self->_buildOpenSSLPKCS12Cmd('-export' => '-export', 
                                                      '-in'     => $tmpCert,     
                                                      '-out'    => $tmpP12,
                                                      '-inkey'  => $tmpKey,
                                                      '-name'   => $config->get("keystore.$entryname.label") || 'cert1',
                                                      'ARGS'    => \@CAList);
              $rc = CertNanny::Util->runCommand(\@cmd);

              if (!$rc) {
                $rc = !CertNanny::Util->writeFile(SRCFILE => $tmpP12,
                                                  DSTFILE => $config->get("keystore.$entryname.location") . ".new",
                                                  FORCE   => 1);
              }
            }
            # cleanup 
            eval {unlink($tmpKey)};
            eval {unlink($tmpCert)};
            eval {unlink($tmpP12)};
          }
          # cleanup 
          eval {unlink($CAListFile)};
        }
      }
    }
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Install all available root certificates");
  return $rc;
} ## end sub installRoots


sub syncRootCAs {
  ###########################################################################
  #
  # synchronize the unstalled root certificates with the avaiable ones
  #
  # Input: -
  # 
  # Output: 1 : failure  0 : success 
  #
  # this function synchronizes installed roots with local trusted root CAs.
  # The installed root CAs are fetched via getInstalledCAs. The available
  # trusted root CAs are fetched via k_getRootCerts.
  # Alle available root CAs are installed in a new temp. keystore. The 
  # installed root CAs are replaced with the new keytore. So all installed
  # roots CAs that are no longer available are deleted 
  # after all the post-install-hook is executed.
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub syncRootCAs {
  #   my $self = shift;
  #   return $self->SUPER::syncRootCAs(@_) if $self->can("SUPER::syncRootCAs");
  # }
  my $self = shift;
  return $self->SUPER::syncRootCAs(@_) if $self->can("SUPER::syncRootCAs");
}



sub _buildOpenSSLPKCS12Cmd {
  # build a OpenSSL command (as an array) containing all common options.
  # used options combinations:
  #   -nocerts         : to display the encrypted private key
  #   -nokeys -clcerts : to display the client certificate only
  #   -nokeys -cacerts : to display the CA chain certificates only
  my $self     = shift;
  
  my %args = (-in       => undef,
              -password => undef,
              -passout  => undef,
              -passin   => undef,
              @_);
  

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $rc = 0;
  
  my $openssl    = $config->get('cmd.openssl', 'FILE');
  $args{-in}       ||= $config->get("keystore.$entryname.location", 'FILE');
  $ENV{PASSWORD} = $args{-password} || $self->_getPin();
  $ENV{PASSOUT}  = $args{-passout}  || $self->_getPin();
  $ENV{PASSIN}   = $args{-passin}   || $self->_getPin();
  $args{-password} = "env:PASSWORD";
  $args{-passout}  = "env:PASSOUT";
  $args{-passin}   = "env:PASSIN";
  
  my @cmd = (qq("$openssl"), 'pkcs12') if ($openssl);
  foreach (keys (%args)) {
    if (defined($args{$_})) {
      if ($_ eq 'ARGS') {
        push(@cmd, @{$args{ARGS}});
      } else {
        push(@cmd, $_);
        push(@cmd, $args{$_}) if ($args{$_} ne $_);
      }
    }
  }
  # if everything should  work unencrypted uncomment:
  # push(@cmd, -nodes);

  @cmd;
} ## end sub _buildOpenSSLPKCS12Cmd


sub _getNewPKCS12Data {
  ###########################################################################
  #
  # Creating prototype PKCS#12
  #
  # Input: caller must provide a hash ref:
  #           CERTFILE   => ???
  # 
  # Output:  caller gets the content of the new pksc12 file
  #
  # this function gets a hash of parsed root certificates
  # install all roots into the keystore depending on keystore type
  # (write files, rebuild kestore, etc.)
  # execute install-root-hook for all certificates that will be new installed
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Creating prototype PKCS#12");
  my $self = shift;
  my %args = (@_);    # argument pair list

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
 
  # create prototype PKCS#12 file
  my $certfile = $args{CERTFILE};
  my $keyfile  = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
  my $label    = $self->{CERT}->{LABEL};

  CertNanny::Logging->info("certfile $certfile, keyfile $keyfile, label $label");

  my $excludeRoot = $config->getFlag("keystore.$entryname.key.excludeRoot");
  my $excludeCAChain = $config->getFlag("keystore.$entryname.key.excludeCAChain");
  
  my @cachain;
  # if flag keystore.$entryname.key.excludeRoot is set or   
  # flag keystore.$entryname.key.excludeCAChain is set, don't add trusted Root CA certificates...
  if (!$excludeRoot && !$excludeCAChain) { 
    push(@cachain, @{$self->{STATE}->{DATA}->{ROOTCACERTS}});
  }

  # if flag keystore.$entryname.key.excludeCAChain is set, don't add trusted CA key chain...
  # ... plus all certificates from the CA key chain minus its root cert
  if (!$excludeCAChain) { 
    push(@cachain, @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1 .. $#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);
  }

  # pkcs12file must be an absolute filename (see below, gsk6cmd bug)
  my $pkcs12file = $self->createPKCS12(FILENAME     => CertNanny::Util->getTmpFile(),
                                       FRIENDLYNAME => $label,
                                       EXPORTPIN    => $self->_getPin(),
                                       CACHAIN      => \@cachain,
                                       CERTFILE     => $certfile, 
 									   KEYFILE      => $keyfile, 
  									   PIN          => $self->_getPin() )->{FILENAME} ;

  if (!defined $pkcs12file) {
    CertNanny::Logging->error("Could not create prototype PKCS#12 from received certificate");
    return undef;
  }
  CertNanny::Logging->info("Created prototype PKCS#12 file $pkcs12file");

  my $data = CertNanny::Util->readFile($pkcs12file);
  unlink $pkcs12file;
  if (!defined $data) {
    CertNanny::Logging->error("Could read new keystore file " . $pkcs12file);
    return undef;
  }

  return $data;
} ## end sub get_new_pkcs12_data


sub _getPin {
  my $self = shift;
  return $self->{PIN};
}



1;
