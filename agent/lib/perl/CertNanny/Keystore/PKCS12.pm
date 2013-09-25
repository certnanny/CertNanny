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
# use File::Spec;
# use File::Copy;
# use File::Basename;
# use Data::Dumper;

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

  # SANITY CHECKS
  my $pin = $entry->{key}->{pin};

  # export the pin to this instance
  $self->{PIN} = $entry->{key}->{pin};

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
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  # Todo pgk: Testen {CONFIG}->get
  my $openssl = $config->get('cmd.openssl', 'FILE');
  if (!defined $openssl) {
    CertNanny::Logging->error("No openssl shell specified");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
    return undef;
  }

  my $filename = $self->_getPKCS12File();
  my $pin      = $self->_getPin();

  my @passin = ();
  if (defined $pin) {
    @passin = ('-password', 'env:PIN');
    $ENV{PIN} = $pin;
  }

  my @cmd = (qq("$openssl"), 'pkcs12', '-in', qq("$filename"), '-nokeys', '-clcerts', @passin,);
  CertNanny::Logging->debug("PKCS12:getCert cmd @cmd");

  my $handle;
  if (!open $handle, join(' ', @cmd) . " |") {
    delete $ENV{PIN};
    CertNanny::Logging->error("could not run OpenSSL shell");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
    return undef;
  }

  local $INPUT_RECORD_SEPARATOR;
  my $certdata = <$handle>;
  close $handle;
  delete $ENV{PIN};

  my $label;
  if ($certdata =~ m{ ^ \s* friendlyName: \s+ (.*?) $ }xms) {
    $label = $1;
  }
  $certdata =~ s{ \A .* (?=-----BEGIN\ CERTIFICATE) }{}xms;
  CertNanny::Logging->debug("PKCS12:getCert certdata $certdata");

# Todo Arkadius Frage: getCert: Hash Element LABEL existiert nur bei diesem Key!!
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
  return {LABEL      => $label,
          CERTDATA   => $certdata,
          CERTFORMAT => 'PEM'};
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
  #           KEYFILE   => file containing the key data
  #           KEYFORMAT => 'PEM' or 'DER'
  #           KEYTYPE   => format (e. g. 'PKCS8' or 'OpenSSL'
  #           KEYPASS   => key pass phrase (only if protected by pass phrase)
  #         or undef on error
  my $self = shift;

  # Todo pgk: Testen {CONFIG}->get
  my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
  if (!defined $openssl) {
    CertNanny::Logging->error("No openssl shell specified");
    return undef;
  }

  my $filename = $self->_getPKCS12File();
  my $pin      = $self->_getPin();

  my @passin = ();
  if (defined $pin) {
    @passin = ('-password', 'env:PIN', '-passout', 'env:PIN',);
    $ENV{PIN} = $pin;
  }

  my @cmd = (qq("$openssl"), 'pkcs12', '-in', qq("$filename"), '-nocerts', @passin,);

  my $handle;
  if (!open $handle, join(' ', @cmd) . " |") {
    CertNanny::Logging->error("could not run OpenSSL shell");
    delete $ENV{PIN};
    return undef;
  }

  local $INPUT_RECORD_SEPARATOR;
  my $keydata = <$handle>;
  close $handle;
  delete $ENV{PIN};

  $keydata =~ s{ \A .* (?=-----BEGIN) }{}xms;

  return {KEYDATA   => $keydata,
          KEYTYPE   => 'OpenSSL',
          KEYPASS   => $pin,
          KEYFORMAT => 'PEM'};
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
  my $self = shift;
  return $self->SUPER::importP12(@_) if $self->can("SUPER::importP12");
} ## end sub importP12


sub getInstalledRoots {
  ###########################################################################
  #
  # get all installed root certificates
  #
  # Input: -
  # 
  # Output: caller gets a hash ref:
  #           ROOTCERTS   => Hash containing array of currently installed root 
  #                          certificates
  #                          Hashkey is tha SHA1 of the certificate
  #                          Hashcontent ist the parsed certificate
  #
  # Reads the config Parameters
  #   keystore.<name>.TrustedRootCA.GENERATED.Dir
  #   keystore.<name>.TrustedRootCA.GENERATED.File
  #   keystore.<name>.TrustedRootCA.GENERATED.ChainFile
  # and look for Trusted Root Certificates. All found certificates are
  # returned in a Hash
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub getInstalledRoots {
  #   my $self = shift;
  #   return $self->SUPER::getInstalledRoots(@_) if $self->can("SUPER::getInstalledRoots");
  # }
  my $self = shift;
  return $self->SUPER::getInstalledRoots(@_) if $self->can("SUPER::getInstalledRoots");
} ## end sub getInstalledRoots


sub installRoots {
  ###########################################################################
  #
  # install all available root certificates
  #
  # Input: caller must provide a hash ref:
  #           ROOTCERTS   => Hash containing array of all rootcertificates to 
  #                          be installed (as returned by getInstalledRoots)
  #                          Hashkey is tha SHA1 of the certificate
  #                          Hashcontent ist the parsed certificate
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

  # INFO Sascha:
  #   - nachträgliches Hinzufügen eines Root Certs in einen pkcs12 Keystore ist 
  #     nicht möglich (nur durch entpacken und neu zusammensetzen)
  #
  # Anbei das Script zum Hinzufügen von Zertifikaten zu pkcs12 Containern.
  # 
  # Das Script erwartet folgende Parameter:
  # $1 Pfad zur pkcs12 Datei
  # $2 Pfad zum Zertifikat, das hinzugefügt werden soll
  # $3 Pfad für den neuen pkcs12 Container
  #
  # Beispiel:
  #
  # #!/bin/bash
  # 
  # #$1 path to pkcs12 container
  # #$2 path to keyfile to add
  # #$3 path to new pkcs12 container
  # 
  # #Extract private key
  # openssl pkcs12 -in $1 -nocerts -nodes | openssl rsa > id_rsa
  # 
  # #Extract certificates
  # openssl pkcs12 -in $1 -out keyStore.pem -nodes -nokeys
  # 
  # #convert 
  # openssl x509 -in $2 -out keyStore2.pem
  # 
  # cat keyStore2.pem >> keyStore.pem
  # openssl pkcs12 -export -out $3 -inkey ./id_rsa -in keyStore.pem
  # 
  # rm id_rsa
  # rm keyStore.pem
  # rm keyStore2.pem
  

  my $self = shift;
  return $self->SUPER::installRoots(@_) if $self->can("SUPER::installRoots");
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
  # The installed root CAs are fetched via getInstalledRoots. The available
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



sub _getNewPKCS12Data {
  my $self = shift;
  my %args = (@_);    # argument pair list

  # create prototype PKCS#12 file
  my $certfile = $args{CERTFILE};
  my $keyfile  = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
  my $label    = $self->{CERT}->{LABEL};

  CertNanny::Logging->info("Creating prototype PKCS#12 from certfile $certfile, keyfile $keyfile, label $label");

  # all trusted Root CA certificates...
  my @cachain = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};

  # ... plus all certificates from the CA key chain minus its root cert
  push(@cachain, @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1 .. $#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);

  # pkcs12file must be an absolute filename (see below, gsk6cmd bug)
  my $pkcs12file = $self->createPKCS12(FILENAME     => CertNanny::Util->getTmpFile(),
                                       FRIENDLYNAME => $label,
                                       EXPORTPIN    => $self->_getPin(),
                                       CACHAIN      => \@cachain)->{FILENAME};

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


sub _getPKCS12File {
  # returns filename with all PKCS#12 data
  my $self = shift;
  return $self->{OPTIONS}->{ENTRY}->{location};
}


sub _getPin {
  my $self = shift;
  return $self->{PIN};
}






1;
