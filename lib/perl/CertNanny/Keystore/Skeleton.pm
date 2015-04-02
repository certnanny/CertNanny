#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005, 2006 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::Skeleton;

use base qw(Exporter CertNanny::Keystore);
# Todo Arkadius Frage ok : Der Key ist KEINE abgeleitete Klasse (ISA) von Keystore, warum also base Keystore. Wird m.E. nur fuer DESTROY benutzt. use base qw(Exporter CertNanny::Keystore)

# You may wish to base your class on the OpenSSL keystore instead if
# you deal with PKCS#8 or PKCS#12 in your implementation or if you would
# like to use the key and request generation of the OpenSSL keystore.
#   use base qw(Exporter CertNanny::Keystore::OpenSSL);
#
# You can also base on PKCS12 (used fpr SAP)
#   use base qw(Exporter CertNanny::Keystore::PKCS12);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

# useful modules
#use IO::File;
#use File::Spec;
#use File::Copy;
#use File::Basename;
#use Data::Dumper;

#use CertNanny::Util;

# keyspecific needed modules


################################################################################

sub nuts_and_bolts {
###########################################################################
# Some useful code snippets
#
# Log debug information:
# CertNanny::Logging->debug('MSG', "My debug level is " . CertNanny::Logging->logLevel('TARGET', 'File'));
#
# Log informational message:
# CertNanny::Logging->info('MSG', "Some informational message");
#
# Get a temporary file name (automatically cleaned up after termination)
# my $tmpfile = CertNanny::Util->getTmpFile();
#
# Build file paths from directory components (DON'T simply concatenate
# them, path separators differ between platforms!):
# my $file = File::Spec->catfile('', 'var', 'tmp', 'foobar');
# (On Unix this results in /var/tmp/foobar)
#
# Read file contents to a scalar:
# my $content = CertNanny::Util->readFile($filename);
# if (! defined $content) {
#   CertNanny::Logging->error('MSG', "...");
#   return undef;
# }
#
# Write contents of a scalar variable to a file:
# if (! CertNanny::Util->writeFile(
#   DSTFILE    => $filename,
#   SRCCONTENT => $myvariable,
#   FORCE      => 1,           # existing files will not be overwritten otherwise
# )) {
#   CertNanny::Logging->error('MSG', "...");
#   return undef;
# }
#
# Key conversion: (see CertNanny::Keystore::k_convertKey()), example:
# my $newkey = $self->k_convertKey(KEYFILE => $keyfile,
#                                  KEYFORMAT => 'PEM',
#                                  KEYTYPE   => 'OpenSSL',
#                                  KEYPASS   => $pin,
#                                  OUTFORMAT => 'PKCS8',
#                                  OUTTYPE   => 'DER',
#                                  OUTPASS   => $pin);
# if (! defined $newkey) ...
#
# Certificate conversion: (see CertNanny::Util->convertCert()), example:
# my $newcert = CertNanny::Util->convertCert(CERTDATA => $data,
#                                            CERTFORMAT => 'DER',
#                                            OUTFORMAT => 'PEM');
# if (! defined $newcert) ...
#
# Atomic file installation (see CertNanny::Keystore::k_saveInstallFile()), example:
# if (!$self->k_saveInstallFile({DSTFILE => $destfile1, SRCCONTENT => data1, DESCRIPTION => 'file1...'},
#                               {DSTFILE => $destfile2, SRCFILE    => file2, DESCRIPTION => 'file2...'})) ...
#
}


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

  # Througout this class you will be able to access entry configuration
  # settings via
  # $entry->{setting}
  # It is possible to introduce new entry settings this way you might
  # need for your keystore implementation.
  # It is also possible to introduce additional hierarchy layers in
  # the configuration, e. g. if you have a
  #   keystore.foobar.my.nifty.setting = bla
  # you will be able to access this via
  # $entry->{my}->{nifty}->{setting}
  # Be sure to check all configuration settings for plausiblitiy.

  # You will have to obtain the keystore pin somehow, for some keystores
  # it will be configured in certnanny's config file, for others you
  # might want to deduce it from the keystore itself
  my $pin = "";

  #    $pin = $entry->{key}->{pin};

  # export the pin to this instance
  $self->{PIN} = $entry->{key}->{pin};

  # SANITY CHECKS
  # sample sanity checks for configuration settings
  # foreach my $parameter qw(keyfile location) {
  # 	if (!defined $entry->{$parameter} ||
  # 	   (!-r $entry->{$parameter})) {
  # 	  return "keystore.$parameter $entry->{$parameter} not defined, does not exist or unreadable";
  # 	}
  # }

  # the rest should remain untouched

  # RETRIEVE AND STORE STATE
  # get previous renewal status
  $self->k_retrieveState() || return undef;

  # check if we can write to the file
  if (my $storeErrState = $self->k_storeState()) {
    return $storeErrState;
  }

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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Get main certificate from keystore");
  my $self = shift;

  CertNanny::Logging->debug('MSG', "Start " . (caller(0))[3] . ": ");
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  # you might want to access keystore configuration here
  #my $location = $self->{OPTIONS}->{ENTRY}->{location};
  #my $foo = $self->{OPTIONS}->{ENTRY}->{someothersetting};

  # use this to signal an error
  if (0) {
    CertNanny::Logging->error('MSG', "getCert(): some unspecified error happened");
    return undef;
  }

  my $instancecert;

  # either set CERTFILE ***OR*** CERTDATA, not both!!!
  # $instancecert = {CERTFILE   => $filename,     # if the cert is stored on disk
  #                  CERTDATA   => $certdata,     # if the cert is available in a scalar
  #                  CERTFORMAT => 'PEM'}         # or 'DER'...

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Get main certificate from keystore");
  return $instancecert;
} ## end sub getCert


sub installCert {
  ###########################################################################
  #
  # installs a new main certificate from the SCEPT server in the keystore
  #
  # Input: caller must provide a hash ref:
  #           CERTFILE  => file containing the cert OR
  #         ? TARGETDIR => directory, where the new certificate should be installed to
  #
  # Output: true: success false: failure
  #
  # This method is called once the new certificate has been received from
  # the SCEP server. Its responsibility is to create a new keystore containing
  # the new key, certificate, CA certificate keychain and collection of Root
  # certificates configured for CertNanny.
  # A true return code indicates that the keystore was installed properly.
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " installs a new main certificate from the SCEPT server in the keystore");
  my $self = shift;
  my %args = (@_);    # argument pair list

  # please see examples in other keystores on ideas how to do this

  # in order to access the certificate chain as returned by SCEP, use
  # foreach my $entry (@{$self->{STATE}->{DATA}->{CERTCHAIN}}) {
  #   my $cacertfile = $entry->{CERTFILE};
  #   # ...
  # }

  # in order to access the root certificates configured for CertNanny, use
  # foreach my $entry (@{$self->{STATE}->{DATA}->{ROOTCACERTS}}) {
  #   my $rootcert = $entry->{CERTFILE};
  #   ...
  # }

  if (1) {    # if any error happened
    CertNanny::Logging->error('MSG', "Could not install new keystore");
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " installs a new main certificate from the SCEPT server in the keystore");
    return undef;
  }

  # only on success:
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " installs a new main certificate from the SCEPT server in the keystore");
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get private key for main certificate from keystore");
  my $self = shift;

  # you might want to access keystore configuration here
  #my $location = $self->{OPTIONS}->{ENTRY}->{location};
  #my $foo = $self->{OPTIONS}->{ENTRY}->{someothersetting};

  # somehow deduce the PIN...
  # my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{key}->{pin};

  my $key;

  # either set KEYFILE ***OR*** KEYDATA, not both!!!
  #     $key = {
  # 	KEYDATA => $keydata,        # if the key is contained in a scalar OR
  # 	KEYFILE => $keyfile,        # if the key is contained in a file
  # 	KEYTYPE => 'OpenSSL',       # or 'PKCS8'
  # 	KEYFORMAT => 'DER'          # or 'PEM'
  # 	KEYPASS => $pin,
  #     }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get private key for main certificate from keystore");
  return $key;
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " generate a certificate request");
  my $self = shift;

  # NOTE: you might want to use OpenSSL request generation, see suggestion
  # above.

  # step 1: generate private key or new keystore
  my $keyfile;    # ...

  # step 2: generate certificate request for existing DN (and SubjectAltName)
  # Distinguished Name:
  my $DN = $self->{CERT}->{CERTINFO}->{SubjectName};

  # SubjectAltName: format is 'DNS:foo.example.com DNS:bar.example.com'
  my $SAN = $self->{CERT}->{CERTINFO}->{SubjectAlternativeName};    # may be undef

  # generate a PKCS#10 PEM encoded request file
  my $requestfile;                                              # ...

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " generate a certificate request");
  return {REQUESTFILE => $requestfile,
          KEYFILE     => $keyfile};
} ## end sub createRequest


sub selfSign {
  ###########################################################################
  #
  # sign the certificate
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " sign the certificate");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $openssl      = $config->get('cmd.openssl', 'CMD');
  my $selfsigncert = $entryname . "-selfcert.pem";
  my $outfile      = File::Spec->catfile($entry->{statedir}, $selfsigncert);
  my $pin          = $self->{PIN} || $entry->{key}->{pin} || "";

  ######prepere openssl config file##########

  my $DN;
  #for inital enrollment we override the DN to use the configured desiered DN rather then the preset enrollment certificates DN
  if ($self->{INITIALENROLLEMNT} eq 'yes') {
    $DN = $entry->{initialenroll}->{subject};
  } else {
    $DN = Net::Domain::hostfqdn();
  }
  CertNanny::Logging->debug('MSG', "DN: $DN");

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
  CertNanny::Logging->debug('MSG', "The following configuration was written to $tmpconfigfile:\n" . CertNanny::Util->readFile($tmpconfigfile));

  # generate request
  my @cmd = (CertNanny::Util->osq("$openssl"), 'req', '-config', CertNanny::Util->osq("$tmpconfigfile"), '-x509', '-new', '-sha1', '-out', CertNanny::Util->osq("$outfile"), '-key', CertNanny::Util->osq("$entry->{keyfile}"),);

  push(@cmd, ('-passin', 'env:PIN')) unless $pin eq "";
  $ENV{PIN} = $pin;
  if (CertNanny::Util->runCommand(\@cmd)->{RC} != 0) {
    CertNanny::Logging->error('MSG', "Selfsign certifcate creation failed!");
    delete $ENV{PIN};
  }

  #    openssl req -x509 -days 365 -new -out self-signed-certificate.pem
  # -key pub-sec-key.pem

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " sign the certificate");
  return {CERT => $outfile};
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
# Todo Arkadius Frage ok: generateKey In-Parameter REQUESTFILE: wirklich optional -> bei Java fehlt es?
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " generate a new keypair");
  my $self = shift;

  # step 1: generate private key or new keystore
  my $keyfile;    # ...
  
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " generate a new keypair");
  return {KEYFILE => $keyfile};
} ## end sub generateKey


sub _createPKCS12 {
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " create pkcs12 file");
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
  
  if ($entry->{type} ne 'OpenSSL') {
    # Only valid for OpenSSL Key all others should implement by themselfs or they get an error
    CertNanny::Logging->error('MSG', "WRONG GENERATE KEY! ");
    return undef;
  }
  
  my $openssl = $config->get('cmd.openssl', 'CMD');
  if (!defined $openssl) {
    CertNanny::Logging->error('MSG', "No openssl shell specified");
    return undef;
  }

  if (!defined $args{FILENAME}) {
    CertNanny::Logging->error('MSG', "createpks12(): No output file name specified");
    return undef;
  }

  if (!defined $args{CERTFILE}) {
    CertNanny::Logging->error('MSG', "createpks12(): No certificate file specified");
    return undef;
  }

  if (!defined $args{KEYFILE}) {
    CertNanny::Logging->error('MSG', "createpks12(): No key file specified");
    return undef;
  }

  CertNanny::Logging->debug('MSG', "Certformat: $args{CERTFORMAT}");

  if (!defined $args{CERTFORMAT} or $args{CERTFORMAT} !~ /^(PEM|DER)$/) {
    CertNanny::Logging->error('MSG', "createpks12(): Illegal certificate format specified");
    return undef;
  }

  if (!defined $args{EXPORTPIN}) {
    CertNanny::Logging->error('MSG', "createpks12(): No export PIN specified");
    return undef;
  }

  my @cmd;

  my $certfile = $args{CERTFILE};

  # openssl pkcs12 command does not support DER input format, so
  # convert it to PEM first
  # FIXME: use SUPER::k_convertCert?
  if ($args{CERTFORMAT} eq "DER") {
    $certfile = CertNanny::Util->getTmpFile();

    @cmd = (CertNanny::Util->osq("$openssl"), 'x509', '-in', CertNanny::Util->osq("$args{CERTFILE}"), '-inform', CertNanny::Util->osq("$args{CERTFORMAT}"), '-out', CertNanny::Util->osq("$certfile"), '-outform', 'PEM',);
    if (CertNanny::Util->runCommand(\@cmd)->{RC} != 0) {
      CertNanny::Logging->error('MSG', "Certificate format conversion failed");
      return undef;
    }
  } ## end if ($args{CERTFORMAT} ...)

  my @passin = ();
  if (defined $args{PIN} and $args{PIN} ne "") {
    @passin = ('-passin', 'env:PIN');
    $ENV{PIN} = $args{PIN};
  }

  my @passout = ();
  if (defined $args{EXPORTPIN} and $args{EXPORTPIN} ne "") {
    @passout = ('-password', 'env:EXPORTPIN');
    $ENV{EXPORTPIN} = $args{EXPORTPIN};
  }

  my @name = ();
  if (defined $args{FRIENDLYNAME} and $args{FRIENDLYNAME} ne "") {
    @name = ('-name', CertNanny::Util->osq("$args{FRIENDLYNAME}"));
  }

  my $cachainfile;
  my @cachain = ();
  if (defined $args{CACHAIN} and ref $args{CACHAIN} eq "ARRAY") {
    $cachainfile = CertNanny::Util->getTmpFile;
    my $fh = new IO::File(">$cachainfile");
    if (!$fh) {
      CertNanny::Logging->error('MSG', "createPKCS12(): Could not create temporary CA chain file");
      return undef;
    }

    # add this temp file
    push(@cachain, '-certfile');
    push(@cachain, CertNanny::Util->osq("$cachainfile"));

    foreach my $entry (@{$args{CACHAIN}}) {
      my $file = $entry->{CERTFILE};
      my @RDN  = split(/(?<!\\),\s*/, $entry->{CERTINFO}->{SubjectName});
      my $CN   = $RDN[0];
      $CN =~ s/^CN=//;
      CertNanny::Logging->debug('MSG', "Adding CA certificate '$CN' in $file");

      my $content = CertNanny::Util->readFile($file);
      if (!defined $content) {
        CertNanny::Logging->error('MSG', "createPKCS12(): Could not read CA chain entry");
        $fh->close;
        unlink $cachainfile if (defined $cachainfile);
        return undef;
      }

      print $fh $content;
      push(@cachain, '-caname');
      push(@cachain, CertNanny::Util->osq("$CN"));
    } ## end foreach my $entry (@{$args{...}})
    $fh->close;
  } ## end if (defined $args{CACHAIN...})

  @cmd = (CertNanny::Util->osq("$openssl"), 'pkcs12', 
          '-export', 
          '-out', CertNanny::Util->osq("$args{FILENAME}"), @passout, 
          '-in', CertNanny::Util->osq("$certfile"), 
          '-inkey', CertNanny::Util->osq("$args{KEYFILE}"), @passin, @name, @cachain);
          
  if (CertNanny::Util->runCommand(\@cmd)->{RC} != 0) {
    CertNanny::Logging->error('MSG', "PKCS#12 export failed");
    delete $ENV{PIN};
    delete $ENV{EXPORTPIN};
    unlink $certfile if ($args{CERTFORMAT} eq "DER");
    unlink $cachainfile if (defined $cachainfile);
    return undef;
  }

  delete $ENV{PIN};
  delete $ENV{EXPORTPIN};
  unlink $certfile if ($args{CERTFORMAT} eq "DER");
  unlink $cachainfile if (defined $cachainfile);

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " create pkcs12 file");
  return {FILENAME => $args{FILENAME}};
} ## end sub createPKCS12


sub importP12 {
  ###########################################################################
  #
  # import pkcs12 file
  # 
  # Input: caller must provide a hash ref:
  #           FILE         => mandatory: 'path/file.p12'
  #           PIN          => mandatory: 'file pin'
  # 
  # Output: caller gets a hash ref:
  #           FILENAME    => created pkcs12 file to create
  # 
  # examples:
  # $self->importP12({FILE => 'foo.p12', PIN => 'secretpin'});
  # 
  # Import a p12 with private key and certificate into target keystore
  # also adding the certificate chain if required / included.
  # Is used with inital enrollment
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " import pkcs12 file");
  my $self = shift;
  my %args = (@_);    # argument pair list

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (!CertNanny::Util->writeFile(DSTFILE    => $entry->{location},
                                  SRCCONTENT => CertNanny::Util->readFile($args{FILE}),
                                  FORCE      => 0)) {
    CertNanny::Logging->error('MSG', "Could not write new p12 Keystore, file already exists ?!");
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " import pkcs12 file");
    return undef;
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " import pkcs12 file");
  return 1;
} ## end sub importP12


sub getInstalledRoots {
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get all installed root certificates");
  my $self = shift;

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get all installed root certificates");
  return undef;
} ## end sub getInstalledRoots


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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " install all available root certificates");
  my $self = shift;

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " install all available root certificates");
  return undef;
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
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " synchronize the unstalled root certificates with the avaiable ones");
  my $self = shift;

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " synchronize the unstalled root certificates with the avaiable ones");
  return undef;
}


1;
