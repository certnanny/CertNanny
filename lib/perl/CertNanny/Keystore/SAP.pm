#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005 - 2007 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::SAP;

use base qw(Exporter CertNanny::Keystore::PKCS12);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

# use IO::File;
# use File::Spec;
use File::Copy;
# use File::Basename;
# use Data::Dumper;

use CertNanny::Util;

# keyspecific needed modules
use English;
use MIME::Base64;

#if ($^O eq "MSWin32") {
#  use File::Copy;
#}


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
  # check that both directories exist
  my ($sap_to_certnanny_dir, $certnanny_to_sap_dir, $p12_xml_file);

  $certnanny_to_sap_dir = $entry->{certnanny_to_sap_dir};
  if (!$certnanny_to_sap_dir or !-d $certnanny_to_sap_dir) {
    CertNanny::Logging->error("keystore.$entryname.certnanny_to_sap_dir is either missing or not a directory, please check.");
    return undef;
  }

  $sap_to_certnanny_dir = $entry->{sap_to_certnanny_dir};
  if (!$sap_to_certnanny_dir or !-d $sap_to_certnanny_dir) {
    CertNanny::Logging->error("keystore.$entryname.sap_to_certnanny_dir is either missing or not a directory, please check.");
    return undef;
  }

  # To enable hooks and to keep in line with
  # the rest of CertNanny's stores, we set the
  # location to where the keystore *currently*
  # can be found. Once a new keystore is created,
  # we will set it to the directory the keystore
  # was written.

  my $filename = $entry->{filename};
  if (!$filename) {
    CertNanny::Logging->info("keystore.$entryname.filename is not specified, will look into $sap_to_certnanny_dir to find a file");
    opendir(DIR, $sap_to_certnanny_dir);
    my @files = grep !/^\.{1,2}$/, readdir(DIR);
    closedir(DIR);
    if (@files > 1) {
      CertNanny::Logging->error("More than one file in $sap_to_certnanny_dir, cannot determine correct file. Please specify keystore.$entryname.filename.");
      return undef;
    }

    if (@files == 1) {
      CertNanny::Logging->error("No file in $sap_to_certnanny_dir, cannot determine correct file. Please specify keystore.$entryname.filename.");
      return undef;
    }
  } ## end if (!$filename)
  
  $entry->{location} = File::Spec->catfile($sap_to_certnanny_dir, $filename);
  $self->{PKCS12}->{XMLFILENAME}          = $filename;
  $self->{PKCS12}->{CERTNANNY_TO_SAP_DIR} = $certnanny_to_sap_dir;
  $self->{PKCS12}->{SAP_TO_CERTNANNY_DIR} = $sap_to_certnanny_dir;

  if (!$filename or !-r ($p12_xml_file = File::Spec->catfile($sap_to_certnanny_dir, $filename))) {
    CertNanny::Logging->info("No file present in $sap_to_certnanny_dir, no renewal required.");
    die("Aborting...");
    return undef;
  }

  if (-r File::Spec->catfile($certnanny_to_sap_dir, $filename)) {
    CertNanny::Logging->info("The renewed keystore was not imported yet. Will not continue");
    die("Aborting...");
    return undef;
  }

  my $p12_data_tag = $entry->{p12_data_tag};
  if (!$p12_data_tag) {
    CertNanny::Logging->info("keystore.$entryname.p12_data_tag no specified, will use default 'P12DATA'");
    $p12_data_tag = 'P12DATA';
  }
  $entry->{p12_data_tag} = $p12_data_tag;

  my $p12_pwd_tag = $entry->{p12_pwd_tag};
  if (!$p12_pwd_tag) {
    CertNanny::Logging->info("keystore.$entryname.p12_pwd_tag no specified, will use default 'PWD'");
    $p12_pwd_tag = 'PWD';
  }
  $entry->{p12_pwd_tag} = $p12_pwd_tag;

  my $p12_xml = CertNanny::Util->readFile($p12_xml_file);
  if (!$p12_xml) {
    CertNanny::Logging->error("XML file $p12_xml is empty.");
    return undef;
  }
  $self->{PKCS12}->{XML} = $p12_xml;

  ##$p12_xml =~ m/.*?\<$p12_data_tag\>([A-Za-z0-9\+\/=]+)\<\/$p12_data_tag\>.*?\<$p12_pwd_tag\>(.*)?\<\/$p12_pwd_tag\>.*/s;
  #$p12_xml =~ m/.*?<$p12_data_tag>([\w\d\s+=\/]+?)<\/$p12_data_tag>.*?<$p12_pwd_tag>(.*?)<\/$p12_pwd_tag>.*?/s;
  if ($p12_xml !~ m/.*?<$p12_data_tag>([\w\d\s+=\/]+?)<\/$p12_data_tag>.*?<$p12_pwd_tag>(.*?)<\/$p12_pwd_tag>.*?/s) {
    CertNanny::Logging->error("Could not parse XML file. Incorrect format");
    return undef;
  }

  my $p12_data = $1;
  my $p12_pwd  = $2;
  $p12_data =~ s/\s//g;
  $p12_data = MIME::Base64::decode($p12_data);
  if (!$p12_data) {
    CertNanny::Logging->error("Could not retrieve PKCS#12 data.");
    return undef;
  }

  if (!$p12_pwd) {
    CertNanny::Logging->error("Could not get the PKCS#12 password, cannot parse data");
    return undef;
  }

  $self->{PKCS12}->{DATA} = $p12_data;
  $self->{PKCS12}->{PWD}  = $p12_pwd;

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
  # Todo Arkadius Frage: getCert: Methode getCert ist mandatory, ist aber in SAP nicht vorhanden?!
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

  # you might want to access keystore configuration here
  #my $location = $self->{OPTIONS}->{ENTRY}->{location};
  #my $foo = $self->{OPTIONS}->{ENTRY}->{someothersetting};

  # use this to signal an error
  if (0) {
    CertNanny::Logging->error("getCert(): some unspecified error happened");
    return undef;
  }

  my $instancecert;

  # either set CERTFILE ***OR*** CERTDATA, not both!!!
  # $instancecert = {CERTFILE   => $filename,     # if the cert is stored on disk
  # 	               CERTDATA   => $certdata,     # if the cert is available in a scalar
  # 	               CERTFORMAT => 'PEM'}         # or 'DER'...
 
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
  return $instancecert;
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

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  # Todo Arkadius Frage: Die Methode get_new_pkcs12_data ist nicht definiert fuer Key SAP
  my $data = MIME::Base64::encode($self->get_new_pkcs12_data(%args));
  return unless $data;

  my $p12_config   = $self->{PKCS12};
  my $new_p12_xml  = $p12_config->{XML};
  my $old_data     = MIME::Base64::encode($p12_config->{DATA});
  my $p12_data_tag = $entry->{p12_data_tag};
  my $p12_pwd_tag  = $entry->{p12_pwd_tag};
  $new_p12_xml =~ s/<$p12_data_tag>([\w\d\s+=\/]+?)<\/$p12_data_tag>/<$p12_data_tag>$data<\/$p12_data_tag>/s;

  # create a temporary file which then will be moved over to the correct dir
  my $tmpDir = $config->get('path.tmpdir', 'FILE');
  my $xml_filename = $p12_config->{XMLFILENAME};

  # This is the TEMPORARY file we store the keystore in
  my $new_p12_xml_file = File::Spec->catfile($tmpDir, $xml_filename);
  if (!CertNanny::Util->writeFile(DSTFILE    => $new_p12_xml_file, 
                                  SRCCONTENT => $new_p12_xml, 
                                  FORCE => 1)) {
    CertNanny::Logging->error("Could not create temporary file to store PKCS12 XML file");
    return undef;
  }

  # temporary file written, before moving it to certnanny_to_sap_dir, remove old file from
  my $sap_to_certnanny_dir = $p12_config->{SAP_TO_CERTNANNY_DIR};
  my $old_xml_file         = File::Spec->catfile($sap_to_certnanny_dir, $xml_filename);
  my $certnanny_to_sap_dir = $p12_config->{CERTNANNY_TO_SAP_DIR};

  # This is the location for the NEW XML
  my $new_xml_file = File::Spec->catfile($certnanny_to_sap_dir, $xml_filename);
  if (!unlink $old_xml_file) {
    CertNanny::Logging->error("Could not delete old XML file. Will continue to prevent loss of renewed certificate.");
  }

  # temporary file written, move it to the certnanny_to_sap_dir
  if ($^O eq "MSWin32") {
    if (!File::Copy::move($new_p12_xml_file, $new_xml_file)) {
      my $output = $!;
      CertNanny::Logging->error("Could not move temporary file to $certnanny_to_sap_dir: $output");
      return undef;
    }
  } else {
    my $output = `mv "$new_p12_xml_file" "$new_xml_file"`;
    if ($?) {
      chomp($output);
      CertNanny::Logging->error("Could not move temporary file to $certnanny_to_sap_dir: $output");
      return undef;
    }
  }

  # Certificate was successfully installed, so we can
  # change the location to the path of the new keystore.
  # This way, a hook will always a receive the expected
  # valid keystore path as a parameter.
  $entry->{location} = "$new_xml_file";

  # only on success:
  return 1;
} ## end sub installCert


sub getKey() {
  # Todo Arkadius Frage: getKey ist mandatorisch, aber fuer SAP nicht definiert
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
  my $self = shift;

  return undef;
}


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
  # trusted root CAs are fetched via k_getAvailableRootCerts.
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



sub _getPKCS12File {
  # returns filename with all PKCS#12 data
  my $self     = shift;
  my $p12_file = CertNanny::Util->getTmpFile();
  my $p12_data = $self->{PKCS12}->{DATA};
  if (!CertNanny::Util->writeFile(DSTFILE    => $p12_file, 
                                  SRCCONTENT => $p12_data, 
                                  FORCE => 1)) {
    CertNanny::Logging->error("Could not write temporary PKCS#12 file");
    return undef;
  }
  return $p12_file;
} ## end sub _getPKCS12File


sub _getPin {
  my $self = shift;
  return $self->{PKCS12}->{PWD};
}


1;
