#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005, 2006 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::Java;

use base qw(Exporter CertNanny::Keystore::OpenSSL);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

# use IO::File;
# use File::Spec;
use File::Copy;
# use File::Basename;
use Data::Dumper;

use CertNanny::Util;

# keyspecific needed modules
use Cwd;

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

  # Needs at least
  #  - Keytool executable
  #  - Java executable
  #  - location
  #  - pin
  $options->{keytool} = $config->get('cmd.keytool', 'FILE');
  croak "cmd.keytool not found" unless (defined $options->{keytool} and -x $options->{keytool});
  
  $options->{java}   = $config->get('cmd.java', 'FILE');
  $options->{java} ||= File::Spec->catfile($ENV{JAVA_HOME}, 'bin', 'java') if (defined $ENV{JAVA_HOME});
  croak "cmd.java not found in config and JAVA_HOME not set"  unless (defined $options->{java} && -x $options->{java});

  if (!defined $entry->{location}) {
    croak("keystore.$entryname.location not defined");
    return undef;
  }
  if (!-r $entry->{location}) {
    croak("keystore file $entry->{location} not readable");
    return undef;
  }
  
#  if (!$config->get("keystore.$entryname.TrustedRootCA.GENERATED.Directory")) {
#    # TrustedRootCA.GENERATED.Directory must be definied in order for k_syncRootCAs to work. For Java it is identical top location
#    $config->set("keystore.$entryname.TrustedRootCA.GENERATED.Directory", $entry->{location});
#  }

  if (!$config->get("keystore.$entryname.TrustedRootCA.GENERATED.Location")) {
    # TrustedRootCA.GENERATED.Location must be definied in order for k_syncRootCAs to work. For Java it is identical top location
    $config->set("keystore.$entryname.TrustedRootCA.GENERATED.Location", $entry->{location});
  }

  if (!defined $entry->{store}->{pin}) {
    croak("keystore.$entryname.store.pin not defined");
    return undef;
  }
  
  # optional keypin defaults to storepin
  if (!defined $entry->{key}->{pin}) {
    $entry->{key}->{pin} = $entry->{store}->{pin};
    CertNanny::Logging->info("keystore.$entryname.key.pin not defined, defaulting to keystore.$entryname.store.pin");

    # TODO sub new() check that keypin works if we are doing "renew"
  }
  
  # optional alias defaults to first key
  if (!defined $entry->{alias}) {
    my @cmd = $self->_buildKeytoolCmd($entry->{location}, '-list');
    # CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));
    # my @keys = `@cmd`;
    # Todo pgk: Testen hidePin, runCommand
    my @keys = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1);
    @keys = grep m{, keyEntry,$}, @keys;
    if ($?) {
      croak("keystore $entry->{location} cannot be listed");
      return undef;
    }
    if (@keys == 0) {
      croak("keystore $entry->{location} does not contain a key");
      return undef;
    }
    if (@keys > 1) {
      croak("keystore $entry->{location} contains muliple keys, cannot determine alias. Please configure keystore.$entryname.alias.");
      return undef;
    }
    ($entry->{alias}) = $keys[0] =~ m{^([^,]*)};
    CertNanny::Logging->info("Using $entry->{alias} as default for keystore.$entryname.alias.");
  } ## end if (!defined $entry->{...})

  # optional keyalg defaults to RSA
  if (!defined $entry->{keyalg}) {
    $entry->{keyalg} = 'RSA';
    CertNanny::Logging->info("Using $entry->{keyalg} as default for keystore.$entryname.keyalg");
  }

  # optional sigalg defaults to RSA
  if (!defined $entry->{sigalg} && uc($entry->{keyalg}) eq 'RSA') {
    $entry->{sigalg} = 'SHA1withRSA';
    CertNanny::Logging->info("Using $entry->{sigalg} as default for keystore.$entryname.sigalg");
  }

  # the rest should remain untouched
  # SANITY CHECKS

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
  my %args = (@_);    # argument pair list
 
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = undef;
  my $certData;

  if (defined $args{CERTDATA}) {
    if (defined $args{CERTFILE}) {
      $rc = CertNanny::Logging->error("getCert(): Either CERTFILE or CERTDATA may be defined.");
    }
    $certData = $args{CERTDATA};
  } else {
    if (!defined $args{CERTFILE}) {
      if (!($args{CERTFILE} = $self->_generateKeystore())) {
        $rc = CertNanny::Logging->error('getCert(): Could not generate a new tem. keystore');
      }
    }
    if (!$rc) {
      my @cmd = $self->_buildKeytoolCmd($args{CERTFILE}, '-export', '-rfc', -alias => qq{"$entry->{alias}"});
      # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
      # Todo pgk: Testen hidePin
      CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));
      $certData = `@cmd`;
      if ($? || !defined $certData) {
        chomp($certData);
        CertNanny::Logging->error("getCert(): keytool -export failed ($certData)");
        $rc = CertNanny::Logging->error("getCert(): Could not read instance certificate file $args{CERTFILE}");
      }
    }
  }

  if (!$rc) {
    local $/ = undef;
    if ($certData =~ m/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)(.*?)[\n\r]*$/s) {
      $rc = {CERTDATA   => $1,
             CERTFORMAT => 'PEM',
             CERTREST   => $2};
    }
  } else {
    $rc = undef;
  }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
  return $rc
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
  my $self     = shift;
  my %args     = (@_);
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $location = $self->_generateKeystore() || return undef;

  # change old key's alias to something meaningful
  my $alias       = $entry->{alias};
  my $timestamp   = time();
  my $backupalias = "old-${alias}-${timestamp}";
  if (!$self->_changeAlias($alias, $backupalias, $location)) {
    CertNanny::Logging->error("Could not change old key's alias from $alias to $backupalias. Cannot proceed with certificate installation.");
    return undef;
  }

  # check that all root certificates that exist are in the keystore
  # all trusted root ca certificates...
  my @trustedcerts = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};

  # ... plus all certificates from the ca key chain minus its root cert
  push(@trustedcerts, @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1 .. $#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);
  my $olddir = getcwd();
# Todo Arkadius Frage: installCert: Hash Element TARGETDIR existiert nur bei diesem Key!!
  chdir($args{TARGETDIR} || $entry->{statedir});
  foreach my $caentry (@trustedcerts) {
    my @rdn = split(/(?<!\\),\s*/, $caentry->{CERTINFO}->{SubjectName});
    my $cn = $rdn[0];
    $cn =~ s/^CN=//;

    CertNanny::Logging->info("Adding certificate '$caentry->{CERTINFO}->{SubjectName}' from file $caentry->{CERTFILE}");

    # rewrite certificate into pem format
    my $cacert = CertNanny::Util->convertCert(OUTFORMAT  => 'PEM',
                                              CERTFILE   => $caentry->{CERTFILE},
                                              CERTFORMAT => 'PEM');

    if (!defined $cacert) {
      CertNanny::Logging->error("installCert(): Could not convert certificate $caentry->{CERTFILE}");
      return undef;
    }

    my $cacertfile = CertNanny::Util->getTmpFile();
    if (!CertNanny::Util->writeFile(DSTFILE    => $cacertfile,
                                    SRCCONTENT => $cacert->{CERTDATA})
      ) {
      CertNanny::Logging->error("installCert(): Could not write temporary ca file");
      return undef;
    }

    if (!$self->_importCert($cacertfile, $cn)) {
      CertNanny::Logging->info("Could not install certificate '$cn', probably already present. Not critical");
    }
  } ## end foreach my $caentry (@trustedcerts)
  chdir $olddir;

  # rename the new key to the old key's alias
  my $newkeyalias = $self->generateKey()->{KEYFILE};
  if (!$self->_changeAlias($newkeyalias, $alias, $location)) {
    CertNanny::Logging->error("Could not rename new key to old key's alias from $newkeyalias to $alias. Rolling back previous renaming to get back the old store");
    if (!$self->_changeAlias($backupalias, $alias, $location)) {
      CertNanny::Logging->error("Could not even rename the old key back to its previous name. Something is seriously wrong. Keystore might be broken, please investigate!");
      return undef;
    }
  }

  # install the new cert with the old alias
  if (!$self->_importCert($args{CERTFILE}, $alias, $location)) {
    CertNanny::Logging->error("Could not import the new certificate. Currently active key has no valid certificate. Rolling back previous renaming to get back working store.");
    if (!$self->_changeAlias($alias, $newkeyalias, $location)) {
      CertNanny::Logging->error("Could not rename the new key back to its previous alias. Thus cannot restore old key's alias. Keystore might be broken, please investigate!");
      return undef;
    }
    if (!$self->_changeAlias($backupalias, $alias, $location)) {
      CertNanny::Logging->error("Could not rename the old key back to its previous name. Keystore might be broken, please investigate!");
      return undef;
    }
  } ## end if (!$self->_importCert...)

  CertNanny::Logging->info("Keystore creation was successful, old keystore will now be backed up and new keystore installed in place.");
  if (!File::Copy::move($entry->{location}, "$entry->{location}.backup")) {
    CertNanny::Logging->error("Could not backup old keystore. New keystore not installed but present in " . $self->_generateKeystore() . ".");
    return undef;
  }

  if (!File::Copy::move($location, $entry->{location})) {
    CertNanny::Logging->error("Could not install the new keystore into the old keystore's location. No keystore present at the moment!");
    return undef;
  }

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
  my $self     = shift;
  my $keystore = shift;    # defaults to $self->_generateKeystore(), see below
  my $alias    = shift;    # defaults to $entry->{alias}, see below

  my $options = $self->{OPTIONS};
  my $entry   = $options->{ENTRY};
  my $config  = $options->{CONFIG};

  my $rc = undef;

  $keystore ||= $self->_generateKeystore() || return undef;
  $alias    ||= $entry->{alias};

  my $pathjavalib = $config->get("path.libjava", "FILE");
  my $extractkey_jar = File::Spec->catfile($pathjavalib, 'ExtractKey.jar');
  if (!-r $extractkey_jar) {
    $rc = CertNanny::Logging->error("getKey(): could not locate ExtractKey.jar file");
  }

  if (!$rc) {
    my $classpath = $extractkey_jar;
    if (defined($ENV{CLASSPATH})) {
      my $sep = $^O eq 'MSWin32' ? ';' : ':';
      $classpath = "$ENV{CLASSPATH}$sep$classpath";
    }

    CertNanny::Logging->info("Extracting key $alias from $keystore");
    my @cmd = $self->_buildKeytoolCmd($keystore, -key => qq{"$alias"});
    shift @cmd;    # remove keytool
    unshift @cmd, qq{"$options->{java}"},
                  -cp => qq{"$classpath"},
                  'de.cynops.java.crypto.keystore.ExtractKey';


    # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
    #CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));
    #my $data = `@cmd`;
    #if ($?) {
    #  chomp($data);
    #  CertNanny::Logging->error("getKey(): keytool -export failed ($data)");
    #  return undef;
    #}

    # Todo pgk: Testen hidePin, runCommand
    my $data = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1);
    if ($?) {
      chomp($data);
      $rc = CertNanny::Logging->error("getKey(): keytool -export failed ($data)");
    } else {
      $rc =  {KEYDATA   => $data,
              KEYTYPE   => 'PKCS8',
              KEYFORMAT => 'DER',
              KEYPASS   => ''};
      $self->{myKey} = $rc;
    }
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
  my $self      = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};

  my $location  = $self->_generateKeystore() || return undef;

  # get a new key (it's either created or the alias is just returned)
  my $newalias = $self->generateKey()->{KEYFILE};
  if (!$newalias) {
    CertNanny::Logging->error("createRequest(): Could not create a new key in keystore $location");
    return undef;
  }
  my @cmd;

  # okay, we have a new key, let's create a request for it
  my $requestfile = File::Spec->catfile($entry->{statedir}, $entryname . "-csr.pem");
  CertNanny::Logging->info("Creating certificate request $requestfile");
  @cmd = $self->_buildKeytoolCmd($location, '-certreq', -alias => qq{"$newalias"}, -file => qq{"$requestfile"});
  if (CertNanny::Util->runCommand(\@cmd) != 0) {
    CertNanny::Logging->error("createRequest(): keytool -certreq failed. See above output for details");
    return undef;
  }

  # decide whether we need to export the key (and do that if it's required)
  my $keyfile;
  unless ($self->_hasEngine()) {

    # okay no engine, export the key
    my $key = $self->getKey($location, $newalias) or return undef;
    $key->{OUTTYPE}   = 'OpenSSL';
    $key->{OUTFORMAT} = 'PEM';
    $key              = $self->k_convertKey(%$key);
    if (!$key) {
      CertNanny::Logging->error("createRequest(): Could not convert key.");
      return undef;
    }

    $key->{OUTTYPE}   = 'OpenSSL';
    $key->{OUTFORMAT} = 'PEM';
    $key->{OUTPASS}   = $entry->{key}->{pin};
    $key              = $self->k_convertKey(%$key);
    if (!$key) {
      CertNanny::Logging->error("createRequest(): Could not convert key");
      return undef;
    }
    $keyfile = File::Spec->catfile($entry->{statedir}, $entryname . "-key.pem");
    if (!CertNanny::Util->writeFile(DSTFILE    => $keyfile, 
                                    SRCCONTENT => $key->{KEYDATA}, 
                                    FORCE => 1)) {
      CertNanny::Logging->error("createreqest(): Could not write key file");
      return undef;
    }
    chmod 0600, $keyfile;

  } else {

    # okay we have an engine, create the correct keyfile variable
    $keyfile = "${location}?alias=${newalias}";
  }
  my $ret = {REQUESTFILE => $requestfile,
             KEYFILE     => $keyfile,};

  return $ret;

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
  
# Generates a new key in the current keystore,
# but only if it has not already done that, i.e. a key
# from a previous run is reused!
  my $self     = shift;
  
  my $entry    = $self->{OPTIONS}->{ENTRY};
  
  my $alias    = $entry->{alias};
  my $newalias = "${alias}-new";
  my $location = $self->_generateKeystore() || return undef;
  my @cmd;

  #first check if key  already exists
  push(@cmd, '-alias');
  push(@cmd, qq{"$newalias"});
  push(@cmd, '-list');
  
  @cmd = $self->_buildKeytoolCmd($location, @cmd);
  # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
  # Todo pgk: Testen hidePin
  if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1) != 0) {
    # we need to generate a new one since we don't already have one
    CertNanny::Logging->info("generateKey(): Creating new key with alias $newalias");
    @cmd = ('-genkeypair',);
    push(@cmd, '-alias');
    push(@cmd, qq{"$newalias"});
    my $DN = $self->{CERT}->{CERTINFO}->{SubjectName};
    push(@cmd, '-dname');
    push(@cmd, qq{"$DN"});
    push(@cmd, '-keyalg');
    push(@cmd, "$entry->{keyalg}");
    push(@cmd, '-sigalg');
    push(@cmd, "$entry->{sigalg}");

    @cmd = $self->_buildKeytoolCmd($location, @cmd);
    # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
    # Todo pgk: Testen hidePin
    if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1) != 0) {
      CertNanny::Logging->error("generateKey(): Could not create the new key, see above output for details");
      return undef;
    }
  } ## end if (CertNanny::Util->runCommand(\@cmd))

  return {KEYFILE => $newalias};
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
  
  if (!defined($args{TARGET}) or ($args{TARGET} eq 'LOCATION')) {
    if (defined(my $locName = $config->get("keystore.$entryname.location", 'FILE'))) {
      my ($certRef, @certList, $certData, $certSha1, $certAlias, $certCreateDate, $certType, $certFingerprint);
      my @cmd = $self->_buildKeytoolCmd($locName, '-list');
      @certList = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1, HIDEPWD => 1);
      foreach (@certList) {
        if ($_ =~ m/^([^,]*), (.*?), (PrivateKeyEntry|trustedCertEntry),.*$/) { # gets Privat Key as well
          ($certAlias, $certCreateDate, $certType) = ($1, $2, $3);
           CertNanny::Logging->debug("alias:$certAlias , certCreateDate: $certCreateDate , certType: $certType");
        }
        if ($_ =~ m/^[^:]*\): ([0-9A-F:]*).*$/) {
          $certFingerprint = $1;
          @cmd = $self->_buildKeytoolCmd($locName, '-list', '-rfc', '-alias', $certAlias);

          $certData = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1, HIDEPWD => 1);
          $certRef  = $self->getCert(CERTDATA => $certData);

          while ($certRef and ($certData = $certRef->{CERTDATA})) {
            my $certInfo = CertNanny::Util->getCertInfoHash(CERTDATA => $certData , CERTFORMAT => $certRef->{CERTFORMAT} );
            if (defined($certInfo) ) {
              if (my $certTyp = $self->k_getCertType(CERTINFO => $certInfo)) { 
                $certSha1 = CertNanny::Util->getCertSHA1(%{$certRef});
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTALIAS}       = $certAlias;
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTCREATEDATE}  = $certCreateDate;
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTTYPE}        = $certType;
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTFINGERPRINT} = $certFingerprint;
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTDATA}        = $certData;
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTFORMAT}      = $certRef->{CERTFORMAT};
                $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTINFO}        = $certInfo;
                CertNanny::Logging->debug("found installed root cert: ". $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTINFO}->{SubjectName}. " Fingerprint $certFingerprint" );
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
  # ToDo pgk : Postinstall Hooks
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
  
  # set rc 0 if TARGET is not defined or TARGET is LOCATION otherwise 1
  my $rc = (defined($args{TARGET}) and ($args{TARGET} ne 'LOCATION'));
  
  # run only if no TARGET is defined or TARGET is LOCATION
  if (!$rc) {
    my $installedRootCAs = $args{INSTALLED};

    my @cmd;
    my $certData;
    my $availableRootCAs = $self->k_getAvailableRootCAs();
    if (!defined($availableRootCAs)) {
      $rc = CertNanny::Logging->error("No root certificates found in " . $config-get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.Directory", 'FILE'));
    } else {
      # build a new temp keystore; Start with a copy of the existing one
      my $locName = $self->_generateKeystore();
      $rc = 1 if (!$locName);
      if (!$rc) {
        # delete every root CA, that does not exist in $availableRootCAs from keystore
        foreach my $certSHA1 (keys ($installedRootCAs)) {
          if (!exists($availableRootCAs->{$certSHA1})) {
            CertNanny::Logging->debug("Deleting root cert " . $installedRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
            @cmd = $self->_buildKeytoolCmd($locName, '-delete', '-alias', $installedRootCAs->{$certSHA1}->{CERTALIAS});
            if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
              CertNanny::Logging->error("Error deleting root cert " . $installedRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
            }
          }
        }

        # copy every root CA, that does not exist in $installedRootCAs to keystore
        foreach my $certSHA1 (keys ($availableRootCAs)) {
          if (!exists($installedRootCAs->{$certSHA1})) {
            CertNanny::Logging->debug("Importing root cert " . $availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
            my $tmpFile = CertNanny::Util->getTmpFile();
            CertNanny::Util->writeFile(DSTFILE => $tmpFile,
                                       SRCFILE => $availableRootCAs->{$certSHA1}->{CERTFILE});
            my $alias = 'newRoot';
            if ($availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName} =~ /CN=([^,]+).*/) {
              ($alias = $1) =~ s/\s/_/g;
            }
            @cmd = $self->_buildKeytoolCmd($locName, '-importcert', '-file', $tmpFile, '-trustcacerts', '-alias' , $alias );
            if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
              CertNanny::Logging->error("Error importing root cert " . $availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
            }
            # collect Postinstallhook information
            $self->{hook}->{Type}   .= 'FILE' . ','                                                               if (defined($self->{hook}->{Type})   && ($self->{hook}->{Type}   !~ m/FILE/s));
            $self->{hook}->{File}   .= $availableRootCAs->{$certSHA1}->{CERTFILE} . ','                           if (defined($self->{hook}->{File})   && ($self->{hook}->{File}   !~ m/$availableRootCAs->{$certSHA1}->{CERTFILE}/s));
            $self->{hook}->{FP}     .= $availableRootCAs->{$certSHA1}->{CERTINFO}->{CertificateFingerprint} . ',' if (defined($self->{hook}->{FP})     && ($self->{hook}->{FP}     !~ m/$availableRootCAs->{$certSHA1}->{CERTINFO}->{CertificateFingerprint}/s));
            $self->{hook}->{Target} .= $entry->{location} . ','                                                   if (defined($self->{hook}->{Target}) && ($self->{hook}->{Target} !~ m/$entry->{location}/s));
          }
        }

        # copy the temp keystore to $location an delete temp keystore
        if (!File::Copy::copy($locName, $entry->{location})) {
          $rc = CertNanny::Logging->error("Could not copy new store <$locName> to current store <$entry->{location}>");
        } else {
          eval {unlink($locName)};
        }
      }
    }
  }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Install all available root certificates");
  return $rc;
} ## end sub installRoots



sub _buildKeytoolCmd {
  # build a keytool command (as an array) containing all common options, the
  # location (if provided as an argument) and further arguments (if provided)
  # the common options are: -storepass -provider -storetype
  my $self     = shift;
  my $location = shift;

  my $options = $self->{OPTIONS};
  my $entry   = $options->{ENTRY};

  my @cmd = (qq("$options->{keytool}"), -noprompt, -storepass => qq("$entry->{store}->{pin}"));
  push(@cmd, -provider  => qq("$entry->{provider}"))      if ($entry->{provider});
  push(@cmd, -storetype => qq("$entry->{key}->{format}")) if ($entry->{key}->{format});
  push(@cmd, -keystore  => qq("$location"))               if ($location);
  push(@cmd, -keypass   => qq("$entry->{key}->{pin}"))    if ($entry->{key}->{pin});
  push(@cmd, @_);
  @cmd;
} ## end sub _buildKeytoolCmd


sub _generateKeystore {
  my $self = shift;
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  
  my $newKeystoreLocation = File::Spec->catfile($entry->{statedir}, "$entryname-tmpkeystore");

  # if not existent -> create new store as a copy of the current one
  unless (-f $newKeystoreLocation) {
    if (!File::Copy::copy($entry->{location}, $newKeystoreLocation)) {
      CertNanny::Logging->error("_generateKeystore(): Could not copy current store to $newKeystoreLocation");
      $newKeystoreLocation = undef;
    }
  }

  return $newKeystoreLocation;
} ## end sub _generateKeystore


sub _importCert {
# Imports certificate to keystore
# first argument is the file to import
# second argument is the alias with which to import
  my $self     = shift;
  my $certfile = shift;
  my $alias    = shift;
  my $location = shift || $self->{OPTIONS}->{ENTRY}->{location};

  my @cmd = $self->_buildKeytoolCmd($location, '-import', '-noprompt', -alias => qq{"$alias"}, -file => qq{"$certfile"});
  CertNanny::Logging->info("Importing certificate with alias $alias");
  
  # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
  # Todo pgk: Testen hidePin
  if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1) == 0) {
    return 1;
  } else {
    return 0;
  }
} ## end sub _importCert


sub _changeAlias {
  my $self      = shift;
  my $alias     = shift;
  my $destalias = shift;
  my $location  = shift || $self->{OPTIONS}->{ENTRY}->{location};
  my @cmd       = ('-changealias',);
  push(@cmd, '-alias');
  push(@cmd, qq{"$alias"});
  push(@cmd, '-destalias');
  push(@cmd, qq{"$destalias"});
  @cmd = $self->_buildKeytoolCmd($location, @cmd);
  
  # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
  # Todo pgk: Testen hidePin
  if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1) != 0) {
    CertNanny::Logging->error("Could not change alias from $alias to $destalias");
    return undef;
  } else {
    return 1;
  }

} ## end sub _changeAlias

sub _hasEngine {
  my $self = shift;
  
  return 0;
}

1;
