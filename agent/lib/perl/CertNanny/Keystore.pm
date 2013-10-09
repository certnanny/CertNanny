#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore;
use base qw(Exporter);

# use Smart::Comments;

use IO::File;
use File::Glob qw(:globally :nocase);
use File::Spec;
use File::Copy;
use File::Temp;
use File::stat;
use File::Basename;

use English;

use Digest::SHA qw(sha1_base64);

use Carp;
use Data::Dumper;

use CertNanny::Logging;
use CertNanny::Util;

use v5.10;
use strict;
use vars qw($VERSION);
use Exporter;

$VERSION = 0.10;


sub new {
  # constructor parameters:
  # location - base name of keystore (required)
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my %args = (@_,    # argument pair list
             );

  my $self = {};
  bless $self, $class;
  
  #  # Store singleton objects in CertNanny
  #  $self->{CONFIG}  = CertNanny::Config->getInstance(%args); return undef unless defined $self->{CONFIG};
  #  $self->{UTIL}    = CertNanny::Util->getInstance(CONFIG => $self->{CONFIG});
  #  $self->{LOGGING} = CertNanny::Logging->getInstance(CONFIG => $self->{CONFIG}); 
  #
  # sanity check keystore config parameters
  # keystore must be available
  my $type = $args{ENTRY}->{type};
  if (!defined $type || ($type eq "none")) {
    print STDERR "Skipping keystore (no keystore type defined)\n";
    return undef;
  }
  
  # CertNanny::Logging->debug("Keystore args dump:". Dumper( $args{ENTRY} ));
 
  # statedir and scepcertdir must exist and be writeable
  foreach my $item (qw(statedir scepcertdir)) {
    if (!exists $args{ENTRY}->{$item}) {croak "No $item specified for keystore " . $args{ENTRY}->{location};}
    if (!-d $args{ENTRY}->{$item})     {croak "$item directory $args{ENTRY}->{$item} does not exist";}
    if (!-x $args{ENTRY}->{$item} or
        !-r $args{ENTRY}->{$item} or
        !-w $args{ENTRY}->{$item})  {croak "Insufficient permissions for $item $args{ENTRY}->{$item}";}
  } ## end foreach my $item (qw(statedir scepcertdir))

  # if there is no statefile defined, create one
  if (!exists $args{ENTRY}->{statefile}) {
    my $entry = $args{ENTRYNAME} || "entry";
    my $statefile = File::Spec->catfile($args{ENTRY}->{statedir}, "$entry.state");
    $args{ENTRY}->{statefile} = $statefile;
  }

  CertNanny::Logging->logLevel($args{CONFIG}->get('loglevel') || 3);

  # set defaults
  # $self->{CONFIG} = $args{CONFIG};
  
  $self->{OPTIONS}->{'path.tmpdir'}  = $args{CONFIG}->get('path.tmpdir', 'FILE');
  $self->{OPTIONS}->{'cmd.openssl'}  = $args{CONFIG}->get('cmd.openssl', 'FILE');
  $self->{OPTIONS}->{'cmd.sscep'}    = $args{CONFIG}->get('cmd.sscep',   'FILE');
  $self->{OPTIONS}->{ENTRYNAME}      = $args{ENTRYNAME};

  croak "No tmp directory specified"            unless defined $self->{OPTIONS}->{'path.tmpdir'};
  croak "No openssl binary configured or found" unless (defined $self->{OPTIONS}->{'cmd.openssl'}
                                                        and -x $self->{OPTIONS}->{'cmd.openssl'});
  croak "No sscep binary configured or found"   unless (defined $self->{OPTIONS}->{'cmd.sscep'}
                                                        and -x $self->{OPTIONS}->{'cmd.sscep'});

  # dynamically load keystore instance module
  eval "require CertNanny::Keystore::${type}";
  if ($@) {
    print STDERR $@;
    print STDERR "ERROR: Could not load keystore handler '$type'\n";
    return undef;
  }

  # attach keystore handler
  # backend constructor is expected to perform sanity checks on the
  # configuration and return undef if options are not appropriate
  eval "\$self->{INSTANCE} = new CertNanny::Keystore::$type((\%args,                   # give it whole configuration plus all keystore parameters and keystore name from configfile
                                                             \%{\$self->{OPTIONS}}))"; # give it some common parameters from configfile
  if ($@) {
    print STDERR $@;
    return undef;
  }

  croak "Could not initialize keystore handler '$type'. Aborted." unless defined $self->{INSTANCE};

  # get certificate
  if (defined $self->{INSTANCE}->{OPTIONS}->{ENTRY}->{INITIALENROLLEMNT}
      and $self->{INSTANCE}->{OPTIONS}->{ENTRY}->{INITIALENROLLEMNT} eq 'yes') {
    CertNanny::Logging->debug("Initialenrollment keystore that has no certificate to read yet.");
  } else {
  	if ($self->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} eq "rootonly") {
	     CertNanny::Logging->debug("rootonly keystore that has no certificate to read.");
	  } else {
	    $self->{CERT} = $self->{INSTANCE}->getCert();
	
  	  if (defined $self->{CERT}) {
	      $self->{CERT}->{CERTINFO} = CertNanny::Util->getCertInfoHash(%{$self->{CERT}});
	      CertNanny::Logging->debug("Certificate Information:\n\tSubjectName: " . $self->{CERT}->{CERTINFO}->{SubjectName}  . "\n\t" .
	                                                            "Serial: "      . $self->{CERT}->{CERTINFO}->{SerialNumber} . "\n\t" . 
	                                                            "Issuer: "      . $self->{CERT}->{CERTINFO}->{IssuerName});
	
  	    my %convopts = %{$self->{CERT}};
	       
	      $convopts{OUTFORMAT}        = 'PEM';
	      $self->{CERT}->{RAW}->{PEM} = CertNanny::Util->convertCert(%convopts)->{CERTDATA};
	      # $self->k_convertCert(%convopts)->{CERTDATA};
	      $convopts{OUTFORMAT}        = 'DER';
	      $self->{CERT}->{RAW}->{DER} = CertNanny::Util->convertCert(%convopts)->{CERTDATA};
	      # $self->k_convertCert(%convopts)->{CERTDATA};
	    } else {
	      CertNanny::Logging->error("Could not parse instance certificate");
	      return undef;
	    }
	    $self->{INSTANCE}->k_setCert($self->{CERT});
  	} ## end else [ if (defined $self->{INSTANCE...})]
	
	  # get previous renewal status
	  $self->k_retrieveState() or return;
	
	  # check if we can write to the file
	  $self->k_storeState() || croak "Could not write state file $self->{STATE}->{FILE}";
  }
	
  return $self;
} ## end sub new


sub DESTROY {
  my $self = shift;

  $self->k_storeState();

  return undef unless (exists $self->{TMPFILE});

  foreach my $file (@{$self->{TMPFILE}}) {
    unlink $file;
  }
} ## end sub DESTROY

#  Abstract methods to be implemented by the instances
#    NOT needed in Keystore Class. Only for documentation
#    No overwriting or fallback if missing in the Key Class
#      - getCert
#      - installCert
#      - getKey
#      - createRequest
#      - selfSign
#      - generateKey
#      - createpkcs12
#      - importP12
#      - getInstalledRoots
#      - installeRoots
#      - syncRootCAs

#sub getCert {
#  ###########################################################################
#  # 
#  # get main certificate from keystore
#  #
#  # Input: caller must provide the file location.
#  #        if no file location is provided default is
#  #        $self->{OPTIONS}->{ENTRY}->{location}
#  #
#  # Output: caller gets a hash ref:
#  #           CERTFILE => file containing the cert OR
#  #           CERTDATA => string containg the cert data
#  #           CERTFORMAT => 'PEM' or 'DER'
#  #         or undef on error
#  return undef;
#} ## end sub getCert


#sub installCert {
#  ###########################################################################
#  #
#  # installs a new main certificate from the SCEPT server in the keystore
#  #
#  # Input: caller must provide a hash ref:
#  #           CERTFILE  => file containing the cert OR
#  #         ? TARGETDIR => directory, where the new certificate should be installed to
#  #
#  # Output: true: success false: failure
#  #
#  # This method is called once the new certificate has been received from
#  # the SCEP server. Its responsibility is to create a new keystore containing
#  # the new key, certificate, CA certificate keychain and collection of Root
#  # certificates configured for CertNanny.
#  # A true return code indicates that the keystore was installed properly.
#  return undef;
#} ## end sub installCert


#sub getKey {
#  ###########################################################################
#  #
#  # get private key for main certificate from keystore
#  # 
#  # Input: caller must provide a hash ref containing the unencrypted private 
#  #        key in OpenSSL format
#  # 
#  # Output: caller gets a hash ref (as expected by k_convertKey()):
#  #           KEYDATA   => string containg the private key OR
#  #           KEYFILE   => file containing the key data
#  #           KEYFORMAT => 'PEM' or 'DER'
#  #           KEYTYPE   => format (e. g. 'PKCS8' or 'OpenSSL'
#  #           KEYPASS   => key pass phrase (only if protected by pass phrase)
#  #         or undef on error
#  return undef;
#} ## end sub getKey


#sub createRequest {
#  ###########################################################################
#  #
#  # generate a certificate request
#  # 
#  # Input: caller must provide a hash ref containing the unencrypted private 
#  #        key in OpenSSL format
#  # 
#  # Output: caller gets a hash ref:
#  #           KEYFILE     => file containing the key data (will
#  #                          only be generated if not initial 
#  #                          enrollment)
#  #           REQUESTFILE => file containing the CSR
#  # 
#  # This method should generate a new private key and certificate request.
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key and PKCS#10 request 'outside' of
#  # your keystore and import this information later.
#  # In this case use the following code:
#  # sub createRequest {
#  #   my $self = shift;
#  #   return $self->SUPER::createRequest(@_) if $self->can("SUPER::createRequest");
#  # }
#  #
#  # If you are able to directly operate on your keystore to generate keys
#  # and requests, you might choose to do all this yourself here:
#}


#sub selfSign {
#  ###########################################################################
#  #
#  # sign the ceritifate
#  # 
#  # Input: -
#  # 
#  # Output: caller gets a hash ref:
#  #           CERT => file containing the signed certificate
#  # 
#  # This signs the current certifiate
#  # This method should selfsign the current certificate.
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key and PKCS#10 request 'outside' of
#  # your keystore and import this information later.
#  # In this case use the following code:
#  # sub selfSign {
#  #   my $self = shift;
#  #   return $self->SUPER::selfSign(@_) if $self->can("SUPER::selfSign");
#  # }
#  #
#  # If you are able to directly operate on your keystore to generate keys
#  # and requests, you might choose to do all this yourself here:
#  return undef;
#}


#sub generateKey {
#  ###########################################################################
#  #
#  # generate a new keypair
#  # 
#  # Input: -
#  # 
#  # Output: caller gets a hash ref:
#  #           KEYFILE     => file containing the key data (will
#  #                          only be generated if not initial 
#  #                          enrollment)
#  #           REQUESTFILE => file containing the CSR
#  # 
#  # This method should generate a new private key.
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key 'outside' of your keystore and 
#  # import this information later.
#  # In this case use the following code:
#  # sub generateKey {
#  #   my $self = shift;
#  #   return $self->SUPER::generateKey(@_) if $self->can("SUPER::generateKey");
#  # }
#  #
#  # If you are able to directly operate on your keystore to generate keys,
#  # you might choose to do all this yourself here:
#  return undef;
#} ## end sub generateKey


#sub createPKCS12 {
#  ###########################################################################
#  #
#  # create pkcs12 file
#  # 
#  # Input: caller must provide a hash ref:
#  #           FILENAME     => mandatory: pkcs12 file to create
#  #           FRIENDLYNAME => optional: cert label to be used in pkcs#12 structure
#  #           EXPORTPIN    => mandatory: PIN to be set for pkcs#12 structure
#  #           CERTFILE     => mandatory: certificate to include in the pkcs#12 file, instance certificate
#  #                           if not specified
#  #           CERTFORMAT   => mandatory: PEM|DER, instance cert format if not specified
#  #           KEYFILE      => mandatory: keyfile, instance key if not specified
#  #           PIN          => optional: keyfile pin
#  #           CACHAIN      => optional: arrayref containing the certificate info structure of
#  #                           CA certificate files to be included in the PKCS#12
#  #                           Required keys for entries: CERTFILE, CERTFORMAT, CERTINFO
#  # 
#  # Output: caller gets a hash ref:
#  #           FILENAME    => created pkcs12 file to create
#  # 
#  # This method should generate a new pkcs12 file 
#  # with all the items that are given
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key 'outside' of your keystore and 
#  # import this information later.
#  # In this case use the following code:
#  # sub createPKCS12 {
#  #   my $self = shift;
#  #   return $self->SUPER::createPKCS12(@_) if $self->can("SUPER::createPKCS12");
#  # }
#  return undef;
#}


#sub importP12 {
#  ###########################################################################
#  #
#  # import pkcs12 file
#  # 
#  # Input: caller must provide a hash ref:
#  #           FILE         => mandatory: 'path/file.p12'
#  #           PIN          => mandatory: 'file pin'
#  # 
#  # Output: caller gets a hash ref:
#  #           FILENAME    => created pkcs12 file to create
#  # 
#  # examples:
#  # $self->importP12({FILE => 'foo.p12', PIN => 'secretpin'});
#  # 
#  # Import a p12 with private key and certificate into target keystore
#  # also adding the certificate chain if required / included.
#  # Is used with inital enrollemnt
#  # IMPORTANT NOTICE: THIS METHOD MUST BE CALLED IN STATIC CONTEXT, NEVER AS A CLASS METHOD
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key 'outside' of your keystore and 
#  # import this information later.
#  # In this case use the following code:
#  # sub importP12 {
#  #   my $self = shift;
#  #   return $self->SUPER::importP12(@_) if $self->can("SUPER::importP12");
#  # }
#  return undef;
#} ## end sub importP12


# ToDo pgk: sub getInstalledRoots
#sub getInstalledRoots {
#  ###########################################################################
#  #
#  # get all installed root certificates
#  #
#  # Input: -
#  # 
#  # Output: caller gets a hash ref:
#  #           ROOTCERTS   => Hash containing currently installed root 
#  #                          certificates
#  #                          Hashkey is tha SHA1 of the certificate
#  #                          Hashcontent ist the parsed certificate
#  #
#  # Reads the config Parameters
#  #   keystore.<name>.TrustedRootCA.GENERATED.Directory
#  #   keystore.<name>.TrustedRootCA.GENERATED.File
#  #   keystore.<name>.TrustedRootCA.GENERATED.ChainFile
#  # and look for Trusted Root Certificates. All found certificates are
#  # returned in a Hash
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key 'outside' of your keystore and 
#  # import this information later.
#  # In this case use the following code:
#  # sub getInstalledRoots {
#  #   my $self = shift;
#  #   return $self->SUPER::getInstalledRoots(@_) if $self->can("SUPER::getInstalledRoots");
#  # }
#  my $self = shift;
#
#  return undef;
#} ## end sub getInstalledRoots


# ToDo pgk: sub installRoots
#sub installRoots {
#  ###########################################################################
#  #
#  # install all available root certificates
#  #
#  # Input: caller must provide a hash ref:
#  #           ROOTCERTS   => Hash containing all rootcertificates to 
#  #                          be installed (as returned by getInstalledRoots)
#  #                          Hashkey is tha SHA1 of the certificate
#  #                          Hashcontent ist the parsed certificate
#  # 
#  # Output: 1 : failure  0 : success 
#  #
#  # this function gets a hash of parsed root certificates
#  # install all roots into the keystore depending on keystore type
#  # (write files, rebuild kestore, etc.)
#  # execute install-root-hook for all certificates that will be new installed
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key 'outside' of your keystore and 
#  # import this information later.
#  # In this case use the following code:
#  # sub installRoots {
#  #   my $self = shift;
#  #   return $self->SUPER::installRoots(@_) if $self->can("SUPER::installRoots");
#  # }
#  my $self = shift;
#
#  return undef;
#} ## end sub installRoots


# ToDo pgk: sub syncRootCAs
#sub syncRootCAs {
#  ###########################################################################
#  #
#  # synchronize the unstalled root certificates with the avaiable ones
#  #
#  # Input: -
#  # 
#  # Output: 1 : failure  0 : success 
#  #
#  # this function synchronizes installed roots with local trusted root CAs.
#  # The installed root CAs are fetched via getInstalledRoots. The available
#  # trusted root CAs are fetched via k_getRootCerts.
#  # Alle available root CAs are installed in a new temp. keystore. The 
#  # installed root CAs are replaced with the new keytore. So all installed
#  # roots CAs that are no longer available are deleted 
#  # after all the post-install-hook is executed.
#  #
#  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
#  # you wish to generate the private key 'outside' of your keystore and 
#  # import this information later.
#  # In this case use the following code:
#  # sub syncRootCAs {
#  #   my $self = shift;
#  #   return $self->SUPER::syncRootCAs(@_) if $self->can("SUPER::syncRootCAs");
#  # }
#  my $self = shift;
#
#  return undef
#}


sub k_storeState {

  # store last state to statefile if it is defined
  my $self = shift;

  my $file = $self->{OPTIONS}->{ENTRY}->{statefile};
  return 1 unless (defined $file and $file ne "");

  # store internal state
  if (ref $self->{STATE}->{DATA}) {
    my $dump = Data::Dumper->new([$self->{STATE}->{DATA}], [qw($self->{STATE}->{DATA})]);

    $dump->Purity(1);

    my $fh;
    if (!open $fh, '>', $file) {
      croak "Could not write state to file $file";
    }
    print $fh $dump->Dump;
    close $fh;
  } ## end if (ref $self->{STATE}...)

  return 1;
} ## end sub k_storeState


sub k_retrieveState {

  # retrieve last state from statefile if it exists
  my $self = shift;

  my $file = $self->{OPTIONS}->{ENTRY}->{statefile};
  return 1 unless (defined $file and $file ne "");

  if (-r $file) {
    $self->{STATE}->{DATA} = undef;

    my $fh;
    if (!open $fh, '<', $file) {
      croak "Could not read state file $file";
    }
    eval do {local $/; <$fh>};

    if (!defined $self->{STATE}->{DATA}) {
      croak "Could not read state from file $file";
    }
  } ## end if (-r $file)
  return 1;
} ## end sub k_retrieveState


sub k_setCert {

  # install a new certificate
  my $self = shift;

  $self->{CERT} = shift;
}


sub k_convertKey {

  # convert private keys to other formats
  # input: hash
  # KEYDATA => string containing private key data OR
  # KEYFILE => file containing private key
  # KEYTYPE => private key type (OpenSSL or PKCS8), default: OpenSSL
  # KEYFORMAT => private key encoding format (PEM or DER), default: DER
  # KEYPASS => private key pass phrase, may be undef or empty
  # OUTFORMAT => desired output key format (PEM or DER), default: DER
  # OUTTYPE => desired output private key type (OpenSSL or PKCS8),
  #            default: OpenSSL
  # OUTPASS => private key pass phrase, may be undef or empty
  #
  # return: hash
  # KEYDATA => string containing key data
  # KEYFORMAT => key encoding format (PEM or DER)
  # KEYTYPE => key type (OpenSSL or PKCS8)
  # KEYPASS => private key pass phrase
  # or undef on error
  my $self = shift;
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my %convertOptions = (KEYFORMAT => 'DER',
                 KEYTYPE   => 'OpenSSL',
                 OUTFORMAT => 'DER',
                 OUTTYPE   => 'OpenSSL',
                 @_,    # argument pair list
                );

  # sanity checks
  foreach my $key (qw( KEYFORMAT OUTFORMAT )) {
    if ($convertOptions{$key} !~ m{ \A (?: DER | PEM ) \z }xms) {
      CertNanny::Logging->error("k_convertKey(): Incorrect $key: $convertOptions{$key}");
      return undef;
    }
  }

  foreach my $key (qw( KEYTYPE OUTTYPE )) {
    if ($convertOptions{$key} !~ m{ \A (?: OpenSSL | PKCS8 ) \z }xms) {
      CertNanny::Logging->error("k_convertKey(): Incorrect $key: $convertOptions{$key}");
      return undef;
    }
  }

  my $output;

  my $openssl = $config->get('cmd.openssl', 'FILE');
  my @cmd = (qq("$openssl"));

  # KEYTYPE OUTTYPE  CMD
  # OpenSSL OpenSSL  rsa
  # OpenSSL PKCS8    pkcs8 -topk8
  # PKCS8   OpenSSL  pkcs8
  # PKCS8   PKCS8    pkcs8 -topk8
  if ($convertOptions{KEYTYPE} eq 'OpenSSL') {
    if ($convertOptions{OUTTYPE} eq 'OpenSSL') {
      push(@cmd, 'rsa');
    } else {
      # must be PKCS#8, see above
      push(@cmd, 'pkcs8');
    }
  } else {
    # must be PKCS#8, see above
    push(@cmd, 'pkcs8');

    if (!defined $convertOptions{KEYPASS} || ($convertOptions{KEYPASS} eq "")) {
      push(@cmd, '-nocrypt');

      if (defined($convertOptions{OUTPASS}) && $convertOptions{OUTPASS} ne "") {
        # if -nocrypt is specified on the command line, the output
        # is always unencrypted, even if -passout is specified.
        CertNanny::Logging->error("k_convertKey(): PKCS8 conversion from unencrypted to encrypted key is not supported");
        return undef;
      }
    } ## end if (!defined $convertOptions{...})
  } ## end else [ if ($convertOptions{KEYTYPE} ...)]

  if ($convertOptions{OUTTYPE} eq 'PKCS8') {
    push(@cmd, '-topk8');
  }

  push(@cmd, '-inform', $convertOptions{KEYFORMAT}, '-outform', $convertOptions{OUTFORMAT},);

  # prepare output
  $output->{KEYTYPE}   = $convertOptions{OUTTYPE};
  $output->{KEYFORMAT} = $convertOptions{OUTFORMAT};
  $output->{KEYPASS}   = $convertOptions{OUTPASS};

  my $infile;
  push(@cmd, '-in');
  if (defined $convertOptions{KEYDATA}) {
    $infile = CertNanny::Util->getTmpFile();
    CertNanny::Logging->debug("k_convertKey(): temporary  in file $infile");
    if (!CertNanny::Util->writeFile(DSTFILE    => $infile,
                                    SRCCONTENT => $convertOptions{KEYDATA},)) {
      CertNanny::Logging->error("k_convertKey(): Could not write temporary file");
      return undef;
    }
    push(@cmd, qq("$infile"));
  } else {
    push(@cmd, qq("$convertOptions{KEYFILE}"));
  }

  $ENV{PASSIN} = "";
  if (defined($convertOptions{KEYPASS}) && ($convertOptions{KEYPASS} ne "")) {
    $ENV{PASSIN} = $convertOptions{KEYPASS};
  }
  if ($ENV{PASSIN} ne "") {
    push(@cmd, '-passin', 'env:PASSIN');
  }

  $ENV{PASSOUT} = "";
  if (defined $convertOptions{OUTPASS} && ($convertOptions{OUTPASS} ne "")) {
    $ENV{PASSOUT} = $convertOptions{OUTPASS};
    if (   ($convertOptions{KEYTYPE} eq 'OpenSSL')
        && ($convertOptions{OUTTYPE} eq 'OpenSSL')) {
      push(@cmd, '-des3');
    }
  }
  if ($ENV{PASSOUT} ne "") {
    push(@cmd, '-passout', 'env:PASSOUT');
  }

  my $cmd = join(' ', @cmd);

  CertNanny::Logging->debug("Execute: " . $cmd);

  ### PASSIN: $ENV{PASSOUT}
  ### PASSOUT: $ENV{PASSOUT}
  #$output->{KEYDATA} = `$cmd`;
  $output->{KEYDATA} = `$cmd`;
  ### keydata: $output->{KEYDATA}

  delete $ENV{PASSIN};
  delete $ENV{PASSOUT};
  unlink $infile if defined $infile;

  if ($? != 0) {
    CertNanny::Logging->error("k_convertKey(): Could not convert key");
    return undef;
  }

  return $output;
} ## end sub k_convertKey


sub k_saveInstallFile {

  # File/keystore installation convenience method
  # This method is very careful about rolling back all modifications if
  # any error happened. Unless something really ugly happens, the original
  # state is always restored even if this method returns an error.
  # This includes permission problems, ownership, file system errors etc.
  # and even if multiple files are to be installed and the error occurs
  # after a portion of them have been installed successfully.
  #
  # options:
  # filespec-hashref or array containing filespec-hashrefs
  # examples:
  # $self->k_saveInstallFile({ FILENAME => 'foo', CONTENT => $data, DESCRIPTION => 'some file...'});
  # or
  # @files = (
  #    { FILENAME => 'foo', CONTENT => $data1, DESCRIPTION => 'some file...'},
  #    { FILENAME => 'bar', CONTENT => $data2, DESCRIPTION => 'other file...'},
  # );
  # $self->k_saveInstallFile(@files);
  #
  my ($self, @args) = @_;

  my $error = 0;

  ###########################################################################
  # write new files

WRITENEWFILES:
  foreach my $entry (@args) {

    # file to replace
    my $filename = $entry->{FILENAME};

    my $ii      = 0;
    my $tmpfile = $filename . ".new";

    # write content data to suitable temporary file
    my $tries = 10;
    while ($ii < $tries
           && (!CertNanny::Util->writeFile(DSTFILE    => $tmpfile,
                                           SRCCONTENT => $entry->{CONTENT}))
      ) {
      # writeFile() will not overwrite existing files, an error
      # indicates that e. g. the file already existed, so:
      # try next filename candidate
      $tmpfile = $filename . ".new$ii";
      $ii++;
    } ## end while ($ii < $tries && (!...))

    # error: could not write one of the tempory files
    if (($ii == $tries) || (!-e $tmpfile)) {

      # remember to clean up the files created up to now
      $error = 1;
      last WRITEFILES;
    }

    # the temporary file should be given the existing owner/group and
    # mode - if possible
    my @stats = stat($filename);

    # NOTE/FIXME: we ignore problems with setting user, group or
    # permissions here on purpose, we don't want to rollback the
    # operation due to permission problems or because this is not
    # supported by the target system
    if (scalar(@stats)) {

      #           uid        gid
      chown $stats[4], $stats[5], $tmpfile;

      #          mode, integer - which is OK for chmod
      chmod $stats[2] & 07777, $tmpfile;    # mask off file type
    }

    # remember new file name for file replacement
    $entry->{TMPFILENAME} = $tmpfile;
  } ## end WRITENEWFILES: foreach my $entry (@args)

  ###########################################################################
  # error checking for temporary file creation
  if ($error) {

    # something went wrong, clean up and bail out
    foreach my $entry (@args) {
      unlink $entry->{TMPFILENAME};
    }
    CertNanny::Logging->error("k_saveInstallFile(): could not create new file(s)");
    return undef;
  }

  ###########################################################################
  # temporary files have been created with proper mode and permissions,
  # now back up original files

  my @original_files = ();
  foreach my $entry (@args) {
    my $file       = $entry->{FILENAME};
    my $backupfile = $file . ".backup";

    # remove already existing backup file
    if (-e $backupfile) {
      unlink $backupfile;
    }

    # check if it still persists
    if (-e $backupfile) {
      CertNanny::Logging->error("k_saveInstallFile(): could not unlink backup file $backupfile");

      # clean up and bail out

      # undo rename operations
      foreach my $undo (@original_files) {
        rename $undo->{DST}, $undo->{SRC};
      }

      # clean up temporary files
      foreach my $entry (@args) {
        unlink $entry->{TMPFILENAME};
      }
      return;
    } ## end if (-e $backupfile)

    # rename orignal files: file -> file.backup
    if (-e $file) {

      # only if the file exists
      if (
        (!rename $file, $backupfile)    # but cannot be moved away
        || (-e $file)
        ) {                             # or still exists after moving
        CertNanny::Logging->error("k_saveInstallFile(): could not rename $file to backup file $backupfile");

        # undo rename operations
        foreach my $undo (@original_files) {
          rename $undo->{DST}, $undo->{SRC};
        }

        # clean up temporary files
        foreach my $entry (@args) {
          unlink $entry->{TMPFILENAME};
        }
        return undef;
      } ## end if ((!rename $file, $backupfile...))

      # remember what we did here already
      push(@original_files,
           {SRC => $file,
            DST => $backupfile,});
    } ## end if (-e $file)
  } ## end foreach my $entry (@args)

  # existing keystore files have been renamed, now rename temporary
  # files to original file names
  foreach my $entry (@args) {
    my $tmpfile = $entry->{TMPFILENAME};
    my $file    = $entry->{FILENAME};

    my $msg = "Installing file $file";
    if (exists $entry->{DESCRIPTION}) {
      $msg .= " ($entry->{DESCRIPTION})";
    }

    CertNanny::Logging->info($msg);

    if (!rename $tmpfile, $file) {

      # should not happen!
      # ... but we have to handle this nevertheless

      CertNanny::Logging->error("k_saveInstallFile(): could not rename $tmpfile to target file $file");

      # undo rename operations
      foreach my $undo (@original_files) {
        unlink $undo->{SRC};
        rename $undo->{DST}, $undo->{SRC};
      }

      # clean up temporary files
      foreach my $entry (@args) {
        unlink $entry->{TMPFILENAME};
      }
      return undef;
    } ## end if (!rename $tmpfile, ...)
  } ## end foreach my $entry (@args)

  return 1;
} ## end sub k_saveInstallFile


sub k_getInfo {
  # return certificate information for this keystore
  # optional arguments: list of entries to return
  my $self     = shift;
  my @elements = @_;

  return $self->{CERT}->{CERTINFO} unless @elements;

  my $result;
  foreach (@elements) {
    $result->{$_} = $self->{CERT}->{CERTINFO}->{$_};
  }
  return $result;
} ## end sub k_getInfo


sub k_checkValidity {

  # return true if certificate is still valid for more than <days>
  # return false otherwise
  # return undef on error
  my $self = shift;
  my $days = shift || 0;

  my $notAfter = CertNanny::Util->isoDateToEpoch($self->{CERT}->{CERTINFO}->{NotAfter});

  return unless defined $notAfter;

  my $cutoff = time + $days * 24 * 3600;

  return ($cutoff < $notAfter);
} ## end sub k_checkValidity


sub k_renew {

  # handle renewal operation
  my $self = shift;

  $self->_renewalState("initial") unless defined $self->_renewalState();
  my $laststate = "n/a";

  while ($laststate ne $self->_renewalState()) {
    $laststate = $self->_renewalState();

    # renewal state machine
    if (   $self->_renewalState() eq "initial"
        or $self->_renewalState() eq "keygenerated") {
      CertNanny::Logging->debug("State: initial");

      $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST} = $self->createRequest();

      if (!defined $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}) {
        CertNanny::Logging->error("Could not create certificate request");
        return undef;
      }
      $self->_renewalState("sendrequest");
    } elsif ($self->_renewalState() eq "sendrequest") {
      CertNanny::Logging->debug("State: sendrequest");

      if (!$self->_sendRequest()) {
        CertNanny::Logging->error("Could not send request");
        return undef;
      }
    } elsif ($self->_renewalState() eq "completed") {
      CertNanny::Logging->debug("State: completed");

      # reset state
      $self->_renewalState(undef);

      # clean state entry
      foreach my $entry (qw( CERTFILE KEYFILE REQUESTFILE )) {
        unlink $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{$entry};
      }

      # delete state file
      unlink $self->{OPTIONS}->{ENTRY}->{statefile};
      last;
    } else {
      CertNanny::Logging->error("State unknown: " . $self->_renewalState());
      return undef;
    }

  } ## end while ($laststate ne $self...)

  return 1;
} ## end sub k_renew


sub k_getNextTrustAnchor {
  ###########################################################################
  #
  # get the next trust anchor
  # 
  # Input: -
  # 
  # Output: -
  #
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get the next trust anchor");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $rc = 0;

  my $scepracert;
  my $scepCertChain;
  my $pemchain;
  my $certchainfile = CertNanny::Util->getTmpFile();

  CertNanny::Logging->debug("CertNanny::Keystore::k_getNextTrustAnchor ");
  CertNanny::Logging->error("Could not get CA certs") if (!$self->k_getCaCerts());
  #CertNanny::Logging->debug("getEnroller config: " . Dumper($self));

  $scepracert->{CERTINFO} = CertNanny::Util->getCertInfoHash(CERTFILE   => $self->{STATE}->{DATA}->{SCEP}->{RACERT},
                                                             CERTFORMAT => 'PEM');
  $scepCertChain = $self->k_buildCertificateChain($scepracert);

  foreach my $cert (@{$scepCertChain}) {
    #CertNanny::Logging->debug("Each ele: $cert " .ref ($cert) . Dumper($cert) );
    $pemchain .= "-----BEGIN CERTIFICATE-----\n" . $cert->{CERTINFO}->{Certificate} . "-----END CERTIFICATE-----\n"
  }

  if (!CertNanny::Util->writeFile(DSTFILE => $certchainfile,
                                   SRCCONTENT  => $pemchain,
                                   FORCE    => 0)) {
    CertNanny::Logging->error("Could not write certificatechain file");
  } else {
    my $enroller = $self->_getEnroller();
    my %certs    = $enroller->getNextCA($certchainfile);

    if (%certs) {
      my $signerCertificate = $certs{SIGNERCERT};
      my @newrootcerts      = @{$certs{NEXTCACERTS}};

      # list of trusted root certificates
      my @trustedroots = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};
    
      my %rootcertfingerprint;
      foreach my $item (@trustedroots) {
        my $fingerprint = $item->{CERTINFO}->{CertificateFingerprint};
        $rootcertfingerprint{$fingerprint}++;
      }

      CertNanny::Logging->debug("k_getNextTrustAnchor signer cert:" . $signerCertificate->{SubjectName});
      CertNanny::Logging->debug("DN: $signerCertificate->{SubjectName}");
      # split DN into individual RDNs. This regex splits at the ','
      # character if it is not escaped with a \ (negative look-behind)
      my @RDN = split(/(?<!\\),\s*/, $signerCertificate->{SubjectName});
      if ($RDN[0] =~ $entry->{rootcaupdate}->{signerSubjectRegex}) {
        CertNanny::Logging->debug("Subject signer check successful " . $RDN[0]);
      } else {
        $rc = CertNanny::Logging->error("Subject signer check failed new root CA cert WILL NOT BE ACCEPTED" . $RDN[0]);
      }

      if (!$rc) {
        CertNanny::Logging->debug("k_getNextTrustAnchor signer issuerName:" . $signerCertificate->{IssuerName});
        # split DN into individual RDNs. This regex splits at the ','
        # character if it is not escaped with a \ (negative look-behind)
        my @IRDN = split(/(?<!\\),\s*/, $signerCertificate->{IssuerName});
        if ($IRDN[0] =~ $entry->{rootcaupdate}->{signerIssuerSubjectRegex}) {
          CertNanny::Logging->debug("signer certificate issuer subject check successful " . $IRDN[0]);
        } else {
          $rc = CertNanny::Logging->error("signer certificate issuer subject check failed rootcerts WILL NOT BE ACCEPTED" . $RDN[0]);
        }
      }
      
      if (!$rc) {
        my $signerCertInfo->{CERTINFO} = $signerCertificate;
        if (!$self->k_buildCertificateChain($signerCertInfo)) {
          $rc = CertNanny::Logging->error("signer certificate NOT trusted against lokal root CA certs, rootcerts WILL NOT BE ACCEPTED" . $RDN[0]);
        }
      }

      if (!$rc) {
        foreach my $newroot (@newrootcerts) {
          if (defined $newroot) {
            CertNanny::Logging->debug("new root cert found:" . $newroot->{CERTINFO}->{CertificateFingerprint});

            my @fingerprint = split(/:/, $newroot->{CERTINFO}->{CertificateFingerprint});
            my $qname = join("", @fingerprint);

            my $newRootCertFile = File::Spec->catfile($entry->{rootcaupdate}->{quarantinedir}, $qname);
            my $pemCACert = "-----BEGIN CERTIFICATE-----\n" . $newroot->{CERTINFO}->{Certificate} . "-----END CERTIFICATE-----\n";

            if (-e $newRootCertFile) {
              ##check quaratine days , install into configured roots dir
              my $filestat = (stat($newRootCertFile));
              my $now      = time();
              my $fileage  = $filestat->ctime;

              #CertNanny::Logging->debug("qfile age :" . $filestat->ctime . Dumper (stat($newRootCertFile) ) );
              CertNanny::Logging->debug("now :" . $now);
              CertNanny::Logging->debug("sub age minus now:" . ($now - $fileage));

              my $quarantineTimeInSec = $entry->{rootcaupdate}->{quarantinetime} * 86400;

              ##if file older then the specified quarantine days in sec
              if (($now - $fileage) > $quarantineTimeInSec) {
                if (not defined $rootcertfingerprint{$newroot->{CERTINFO}->{CertificateFingerprint}}) {
                  CertNanny::Logging->info("install new root CA cert with fingerprint" . $newroot->{CERTINFO}->{CertificateFingerprint} . " into trusted roots");

                  my @CARDN         = split(/(?<!\\),\s*/, $newroot->{CERTINFO}->{SubjectName});
                  my @certname      = split(/=/,           $CARDN[0]);
                  my @newCAfilePart = split(/ /,           $certname[1]);
                  my $newCAFileName = join("-", @newCAfilePart);
                  $newCAFileName .= ".pem";

                  my $RootCertFile = File::Spec->catfile($entry->{TrustedRootCA}->{AUTHORITATIVE}->{Directory}, $newCAFileName);
                  CertNanny::Logging->debug("newRootCertFile:" . $RootCertFile ."\n content: ". $pemCACert);
                  
                  if (!CertNanny::Util->writeFile(DSTFILE    => $RootCertFile,
                                                  SRCCONTENT => $pemCACert,
                                                  FORCE      => 1)) {
                    CertNanny::Logging->error("Could not write new Root CA into trusted roots dir " . $entry->{TrustedRootCA}->{authoritative}->{dir});
                    last;
                  }
                  ##delete new root CA cert from quarantine
                  unlink $newRootCertFile;
                } else {
                  CertNanny::Logging->debug("new root with fingerprint" . $newroot->{CERTINFO}->{CertificateFingerprint} . " already exists as trusted root cert");
                }
              } else {
                CertNanny::Logging->debug("Quarantine for root CA cert with fingerprint " . $newroot->{CERTINFO}->{CertificateFingerprint} . "still pending");
              }
            } else {
              if (not defined $rootcertfingerprint{$newroot->{CERTINFO}->{CertificateFingerprint}}) {
                CertNanny::Logging->debug("Quarantine new root CA cert with fingerprint: " . $newroot->{CERTINFO}->{CertificateFingerprint});
                if (!CertNanny::Util->writeFile(DSTFILE    => $newRootCertFile,
                                                SRCCONTENT => $pemCACert,
                                                FORCE      => 0)) {
                  CertNanny::Logging->error("Could not write new Root CA into quarantine dir");
                  last;
                }
              } else {
                CertNanny::Logging->debug("new root CA cert with fingerprint" . $newroot->{CERTINFO}->{CertificateFingerprint} . " already exists as trusted root cert");
              }
            } ## end else [ if (-e $newRootCertFile)]
          } ## end if (defined $newroot)
        } ## end foreach my $newroot (@newrootcerts)
      } ## end if ($rc)
    } ## end if (%certs)
  } ## end if (!CertNanny::Util->write_file ...

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get the next trust anchor");
  return $rc;
} ## end sub k_getNextTrustAnchor


sub k_getDefaultEngineSection {
  my $self = shift;

  return $self->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine}
    || 'engine_section';
}


sub k_warnExpiry {
  # call k_warnExpiry hook for notification event
  my $self         = shift;
  my $notification = shift;
  return $self->_executeHook($self->{INSTANCE}->{OPTIONS}->{ENTRY}->{hook}->{warnexpiry},
                             '__NOTAFTER__'  => $self->{CERT}->{CERTINFO}->{NotAfter},
                             '__NOTBEFORE__' => $self->{CERT}->{CERTINFO}->{NotBefore},
                             '__STATE__'     => $self->{STATE}->{DATA}->{RENEWAL}->{STATUS},);
} ## end sub k_warnExpiry


sub k_getRootCerts {
  ###########################################################################
  #
  # get all root certificates from the configuration that are currently
  # valid
  #
  # Input: -
  # 
  # Output: caller gets a hash ref:
  #           CERTINFO => hash as returned by getCertInfoHash()
  #           CERTFILE => filename
  #           CERTFORMAT => cert format (PEM, DER)
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get all root certificates from the configuration that are currently valid");
  my $self   = shift;
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my @result = ();
  my $res;
  my $locRootCA = $config->get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.Directory", 'FILE');
  foreach (@{CertNanny::Util->fetchFileList($locRootCA)}) {
    push(@result, $res) if ($res = $self->_checkCert($_));
  }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get all root certificates from the configuration that are currently valid");
  return \@result;
} ## end sub k_getRootCerts


sub _checkCert {
  ###########################################################################
  #
  # check whether cert is valid
  #
  # Input: caller must provide:
  #           $1 certificate file
  #
  # Output: caller gets a hash ref:
  #           CERTINFO   => hash as returned by getCertInfoHash()
  #           CERTFILE   => filename
  #           CERTFORMAT => cert format (PEM, DER)
  #  
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "check whether cert is valid");
  my $self     = shift;
  my $certfile = shift;

  my $rc = 1;

  my $exclude_expired     = $self->{OPTIONS}->{ENTRY}->{excludeexpiredrootcerts}     || 'yes';
  my $exclude_notyetvalid = $self->{OPTIONS}->{ENTRY}->{excludenotyetvalidrootcerts} || 'no';

  # FIXME: determine certificate format of root certificate
  #my $certfile = $self->{OPTIONS}->{ENTRY}->{rootcacert}->{$index};
  my $certformat = 'PEM';
  my $certinfo   = CertNanny::Util->getCertInfoHash(CERTFILE   => $certfile,
                                                    CERTFORMAT => $certformat);
  $rc = 0 if (!defined $certinfo);

  if ($rc) {
    my $notBefore = CertNanny::Util->isoDateToEpoch($certinfo->{NotBefore});
    my $notAfter  = CertNanny::Util->isoDateToEpoch($certinfo->{NotAfter});
    my $now       = time;
    if ($exclude_expired =~ m{ yes }xmsi && ($now > $notAfter)) {
      CertNanny::Logging->info("Skipping expired root certificate " . $certinfo->{SubjectName});
      $rc = 0;
    }

    if ($rc && $exclude_notyetvalid =~ m{ yes }xmsi && ($now < $notBefore)) {
      CertNanny::Logging->info("Skipping not yet valid root certificate " . $certinfo->{SubjectName});
      $rc = 0;
    }
  }

  if ($rc) {
    CertNanny::Logging->info("Trusted root certificate: " . $certinfo->{SubjectName});
    $rc = {CERTINFO   => $certinfo,
           CERTFILE   => $certfile,
           CERTFORMAT => $certformat};
  }
  
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "check whether cert is valid");
  return $rc;
} ## end sub _checkCert


sub k_buildCertificateChain {
  ###########################################################################
  #
  # build a certificate chain for the specified certificate
  #
  # Input:  caller must provide a parsed certificate
  # 
  # Output: caller gets a array ref
  #             [0] root cert
  #             [1] intermediate cert 1
  #             [2] intermediate cert 2 ... 
  #         or undef on error (e. g. root certificate could not be found)
  #
  # The certificate chain will NOT be verified cryptographically.
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "build a certificate chain for the specified certificate");
  my $self = shift;
  my $cert = shift;

  my $is_issuer = sub {
    # local helper function that accepts two cert entries.
    # returns undef if the elements are unrelated
    # returns true if the first argument is the issuer of the second arg
    #   (1: authority key identifier chaining, 2: DN chaining)
    ### is_issuer...
    my $parent = shift;
    my $child  = shift;
   
    if (!defined $parent || !defined $child) {
      print STDERR "ERROR: is_issuer: missing parameters\n";
      return undef;
    }

    if (ref $parent ne 'HASH' || ref $child ne 'HASH') {
      print STDERR "ERROR: is_issuer: illegal parameters\n";
      return undef;
    }

    my ($child_issuer, $child_akeyid);
    my ($parent_subject, $parent_skeyid);

    $child_issuer   = $child->{CERTINFO}->{IssuerName};
    $child_akeyid   = $child->{CERTINFO}->{AuthorityKeyIdentifier};
    $parent_subject = $parent->{CERTINFO}->{SubjectName};
    $parent_skeyid  = $parent->{CERTINFO}->{SubjectKeyIdentifier};

    if (defined $child_akeyid) {                                                  ### keyid chaining...
      if (defined $parent_skeyid && 'keyid:' . $parent_skeyid eq $child_akeyid) { ### MATCHED via keyid...
        return 1;
      }
    } else {                                                                      ### DN chaining...
      if ($child_issuer eq $parent_subject) {                                     ### MATCHED via DN...
        return 2;
      }
    }
    return undef;
  };

  # list of trusted root certificates
  my @trustedroots = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};

  my %rootcertfingerprint;
  foreach my $entry (@trustedroots) {
    my $fingerprint = $entry->{CERTINFO}->{CertificateFingerprint};
    $rootcertfingerprint{$fingerprint}++;
    CertNanny::Logging->debug("Authoritife Root CA found:".$entry->{CERTINFO}->{SubjectName}." - ".$entry->{CERTINFO}->{CertificateFingerprint} );
  }

  # remove root certs from certificate list
  my @cacerts = grep(!exists $rootcertfingerprint{$_->{CERTINFO}->{CertificateFingerprint}}, @{$self->{STATE}->{DATA}->{SCEP}->{CACERTS}});

  # @cacerts now contains the certificates delivered by SCEP minus
  # the configured root certificates.
  # NOTE: it may still contain root certificates NOT specified in
  # the config file!

  # output structure, for building the chain start with the end entity cert
  my @chain = ($cert);

  CertNanny::Logging->info("Building certificate chain");
BUILDCHAIN:
  while (1) {
    ### check if the first cert in the chain is a root certificate...
    if (&$is_issuer($chain[0], $chain[0])) {
      ### found root certificate...
      last BUILDCHAIN;
    }

    my $cert;
    my $issuer_found = 0;
    my $subject      = $chain[0]->{CERTINFO}->{SubjectName};
    CertNanny::Logging->info("Subject: $subject");

  FINDISSUER:
    foreach my $entry (@cacerts, @trustedroots) {
      # work around a bug in Perl (?): when using $cert instead of
      # $entry in the foreach loop the value of $cert was lost
      # after leaving the loop!?
      $cert = $entry;
      if (!defined $entry) {
        ### undefined entry 1 - should not happen...
      }
      ### scanning ca entry...
      ### $entry->{CERTINFO}->{SubjectName}
      ### $chain[0]

      $issuer_found = &$is_issuer($entry, $chain[0]);
      if (!defined $entry) {
        ### undefined entry 2 - should not happen...
      }

      $subject = $entry->{CERTINFO}->{SubjectName};
      if ($issuer_found) {
        if ($issuer_found == 1) {
          CertNanny::Logging->info("  Issuer identified via AuthKeyID match: $subject");
        } else {
          CertNanny::Logging->info("  Issuer identified via DN match: $subject");
        }
      } else {
        CertNanny::Logging->debug("  Unrelated: $subject");
      }

      last FINDISSUER if ($issuer_found);
    } ## end FINDISSUER: foreach my $entry (@cacerts...)

    if (!$issuer_found) {
      CertNanny::Logging->error("No matching issuer certificate was found");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "build a certificate chain for the specified certificate");
      return undef;
    }
    if (!defined $cert) {
      ### undefined entry 3 - should not happen...
    }

    ### prepend to chain...
    ### $cert
    unshift @chain, $cert;
  } ## end BUILDCHAIN: while (1)

  # remove end entity certificate
  pop @chain;

  ### @chain

  # verify that the first certificate in the chain is a trusted root
  if (scalar @chain == 0) {
    CertNanny::Logging->error("Certificate chain could not be built");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "build a certificate chain for the specified certificate");
    return undef;
  }

  my $fingerprint = $chain[0]->{CERTINFO}->{CertificateFingerprint};
  if (!exists $rootcertfingerprint{$fingerprint}) {
    CertNanny::Logging->error("Root certificate is not trusted");
    CertNanny::Logging->info("Untrusted root certificate DN: " . $chain[0]->{CERTINFO}->{SubjectName});
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "build a certificate chain for the specified certificate");
    return undef;
  }
  CertNanny::Logging->info("Root certificate is marked as trusted in configuration");
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "build a certificate chain for the specified certificate");

  return \@chain;
} ## end sub k_buildCertificateChain


sub k_syncRootCAs {
  ###########################################################################
  #
  # synchronize the installed root certificates with the avaiable ones
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
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "synchronize the installed root certificates with the avaiable ones");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $rc = 0;

  # Data structure $availableRootCAs and $installedRootCAs
  #  -<certSHA1> #1
  #     |- CERTDATA  
  #     |- CERTINFO  
  #     |- optional: CERTFILE  
  #        ...
  #  
  #  -<certSHA1> #2
  #     |- CERTDATA  
  #     |- CERTINFO  
  #     |- optional: CERTFILE  
  #        ...
  #  
  #  -<certSHA1> #3
  #   ...

  # First fetch available root certificates
  my $rootCertList = $self->k_getRootCerts();
  if (!defined($rootCertList)) {
    $rc = CertNanny::Logging->error("No root certificates found in " . $config-get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.Directory", 'FILE'));
  }
  
  if (!$rc) {
    my $availableRootCAs = {};
    # Foreach available root cert get the SHA1
    foreach my $certRef (@{$rootCertList}) {
      my $certSHA1 = CertNanny::Util->getCertSHA1(%{$certRef})->{CERTSHA1};
      if (exists($availableRootCAs->{$certSHA1})) {
        if (exists($availableRootCAs->{$certSHA1}->{CERTFILE}) and ($certRef->{CERTFILE})) {
          CertNanny::Logging->debug("Identical root certificate in <" . $availableRootCAs->{$certSHA1}->{CERTFILE} . "> and <" . $certRef->{CERTFILE} . ">");
        } else {
          CertNanny::Logging->debug("Identical root certificate <" . $availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName} . "> found.");
        }
      } else {
        $availableRootCAs->{$certSHA1} = $certRef;
      }
    }

    # then compare against DIR, FILE and CHAINFILE in case of an 
    # inconsistence rebuild DIR, FILE or CHAINIFLE
    foreach my $target ('DIRECTORY', 'FILE', 'CHAINFILE', 'LOCATION') {
      # Fetch installed root certificates into
# Todo Dumper Löschen      
print Dumper($target);
      my $installedRootCAs = $self->getInstalledRoots(TARGET => $target);
  
      my $rebuild = 0;
      # comparison $installedRootCAs to $availableRootCAs
      foreach my $certSHA1 (keys ($installedRootCAs)) {
        $rebuild ||= !exists($availableRootCAs->{$certSHA1});
        last if $rebuild;
      }  

      if (!$rebuild) {
        # comparison $availableRootCAs to $installedRootCAs
        foreach my $certSHA1 (keys ($availableRootCAs)) {
          $rebuild ||= !exists($installedRootCAs->{$certSHA1});
          last if $rebuild;
        }
      }

      if ($rebuild) {
        CertNanny::Logging->debug("rebuilding " . lc($target) . ".");
        $self->installRoots(TARGET    => $target,
                            INSTALLED => $installedRootCAs,
                            AVAILABLE => $availableRootCAs);
      }
    }
  }

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "synchronize the uinstalled root certificates with the avaiable ones");
  return $rc;
}


sub _verifyCertificateChain {

  # cryptographically verify certificate chain
  # TODO

  return 1;
}


sub _executeHook {
  ###########################################################################
  #
  # call an execution hook
  #
  # Input: $1 Hook execution command
  #        $2 Hash containing parameters that are replaced in the hook
  #           executions command prior to execution
  # 
  # Output: 1 : success  0 : failure  # : returncode of the hook command 
  #
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "synchronize the unstalled root certificates with the avaiable ones");
  my $self = shift;
  my $hook = shift;
  my %args = ('__ENTRY__'       => $self->{INSTANCE}->{OPTIONS}->{ENTRYNAME}           || $self->{OPTIONS}->{ENTRYNAME},
              '__SUBJECT__'     => qq ( "$self->{CERT}->{CERTINFO}->{SubjectName}" )   || 'UnknownSubject',
              '__SERIAL__'      => $self->{CERT}->{CERTINFO}->{SerialNumber}           || 'UnknownSerial',
              '__FINGERPRINT__' => $self->{CERT}->{CERTINFO}->{CertificateFingerprint} || 'UnknownFingerprint',
              @_);    # argument pair list

  # hook not defined -> success
  if (!defined $hook) {
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "synchronize the unstalled root certificates with the avaiable ones");
    return 1;
  }

  CertNanny::Logging->info("Running external hook function");

  if ($hook =~ /::/) {
    # execute Perl method
    CertNanny::Logging->info("Perl method hook not yet supported");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "synchronize the unstalled root certificates with the avaiable ones");
    return undef;
  } else {
    # assume it's an executable
    if (!exists($args{__LOCATION__})) {
      if (exists $self->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} and $self->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} ne '') {
        $args{__LOCATION__} = qq("$self->{INSTANCE}->{OPTIONS}->{ENTRY}->{location}");
      } else {
        $args{__LOCATION__} = qq("$self->{OPTIONS}->{ENTRY}->{location}");
      }
    }

    # replace values passed to this function
    foreach my $key (keys %args) {
      my $value = $args{$key} || "";
      $hook =~ s/$key/$value/g;
    }

    CertNanny::Logging->info("Exec: $hook");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "synchronize the unstalled root certificates with the avaiable ones");
    return CertNanny::Util->runCommand($hook);
  } ## end else [ if ($hook =~ /::/) ]
} ## end sub _executeHook


sub k_getCaCerts {

  # obtain CA certificates via SCEP
  # returns a hash containing the following information:
  # RACERT => SCEP RA certificate (scalar, filename)
  # CACERTS => CA certificate chain, starting at highes (root) level
  #            (array, filenames)
  my $self = shift;

  # get root certificates
  # these certificates are configured to be trusted
  $self->{STATE}->{DATA}->{ROOTCACERTS} = $self->k_getRootCerts();

  my $scepracert = $self->{STATE}->{DATA}->{SCEP}->{RACERT};

  my $enroller = $self->_getEnroller();
  my %certs    = $enroller->getCA();

  $self->{STATE}->{DATA}->{SCEP}->{CACERTS} = $certs{CACERTS};
  $self->{STATE}->{DATA}->{SCEP}->{RACERT}  = $certs{RACERT};

  return $certs{RACERT} if -r $certs{RACERT};
  return undef;
} ## end sub k_getCaCerts


sub _sendRequest {
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  #my $enroller = $self->_getEnroller();
  #return $enroller->enroll();
  #print Dumper $self->{STATE}->{DATA};

  if (!$self->k_getCaCerts()) {
    CertNanny::Logging->error("Could not get CA certs");
    #return undef;
  }
  #CertNanny::Logging->debug("Keystore _sendrequest self" .Dumper($self));

  my $requestfile      = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{REQUESTFILE};
  my $requestkeyfile   = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
  my $pin              = $self->{PIN} || $entry->{key}->{pin};
  my $scepsignaturekey = $entry->{scepsignaturekey};
  my $scepracert = $self->{STATE}->{DATA}->{SCEP}->{RACERT};
  my $scepchecksubjectname ; 
  if(defined $entry->{scepchecksubjectname}){
  	$scepchecksubjectname = $entry->{scepchecksubjectname}; 
  }else{
  	$scepchecksubjectname = 'no';
  }

  if (!exists $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE}) {
    my $certfile = $entryname . "-cert.pem";
    $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE} = File::Spec->catfile($entry->{statedir}, $certfile);
  }

  my $newcertfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE};
  my $rc          = 0;

  CertNanny::Logging->debug("request:              $requestfile");
  CertNanny::Logging->debug("keyfile:              $requestkeyfile");
  CertNanny::Logging->debug("sscep:                " . $config->get('cmd.sscep'));
  CertNanny::Logging->debug("scepurl:              " . $entry->{enroll}->{sscep}->{URL});
  CertNanny::Logging->debug("scepsignaturekey:     $scepsignaturekey");
  CertNanny::Logging->debug("scepchecksubjectname: " . $scepchecksubjectname);
  CertNanny::Logging->debug("scepracert:           $scepracert");
  CertNanny::Logging->debug("newcertfile:          $newcertfile");
  CertNanny::Logging->debug("openssl:              " . $options->{'cmd.openssl'});
  my $newkey;

  unless ($self->_hasEngine()) {

    # get unencrypted new key in PEM format
    $newkey = $self->k_convertKey(KEYFILE   => $requestkeyfile,
                                  KEYPASS   => $pin,
                                  KEYFORMAT => 'PEM',
                                  KEYTYPE   => 'OpenSSL',
                                  OUTFORMAT => 'PEM',
                                  OUTTYPE   => 'OpenSSL');   # no pin
                             
    if (!defined $newkey) {
      CertNanny::Logging->error("Could not convert new key");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
      return undef;
    }

    # write new PEM encoded key to temp file
    $requestkeyfile = CertNanny::Util->getTmpFile();
    CertNanny::Logging->debug("requestkeyfile: $requestkeyfile");
    chmod 0600, $requestkeyfile;

    if (!CertNanny::Util->writeFile(DSTFILE    => $requestkeyfile,
                                    SRCCONTENT => $newkey->{KEYDATA},
                                    FORCE      => 1)) {
      CertNanny::Logging->error("Could not write unencrypted copy of new file to temp file");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
      return undef;
    }
  } ## end unless ($self->k_hasEngine)

  my @autoapprove = ();
  my $oldkeyfile;
  my $oldcertfile;
  if ($scepsignaturekey =~ /(old|existing)/i) {

    # get existing private key from keystore
    
    my $oldkey = $self->getKey();
#    my $oldkeyfile = CertNanny::Util->getTmpFile();
#    
#    if (!CertNanny::Util->writeFile(DSTFILE    => $oldkeyfile,
#                                    SRCCONTENT => $oldkey->{KEYDATA},
#                                    FORCE      => 1)) {
#      CertNanny::Logging->error("Could not write copy of oldkey to temp file");
#      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
#      return undef;
#    }
#    
#	 CertNanny::Logging->debug("Oldkey tmp file:" .$oldkeyfile );
# 
#    if (!defined $oldkeyfile) {
#      CertNanny::Logging->error("Could not get old key from certificate instance");
#      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
#      return undef;
#    }

    unless ($self->_hasEngine()) {

      # convert private key to unencrypted PEM format
      # only necessary if no engine support is available
      # otherwise the keystore or engine is responsible for returning
      # the correct format
      #CertNanny::Logging->debug(Dumper($oldkey));

      my $oldkey_pem_unencrypted = $self->k_convertKey(%{$oldkey},
                                                       OUTFORMAT => 'PEM',
                                                       OUTTYPE   => 'OpenSSL',
                                                       OUTPASS   => '',);

      if (!defined $oldkey_pem_unencrypted) {
        CertNanny::Logging->error("Could not convert (old) private key");
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
        return undef;
      }

      $oldkeyfile = CertNanny::Util->getTmpFile();
      chmod 0600, $oldkeyfile;

      if (!CertNanny::Util->writeFile(DSTFILE    => $oldkeyfile,
                                      SRCCONTENT => $oldkey_pem_unencrypted->{KEYDATA},
                                      FORCE      => 1,)
        ) {
        CertNanny::Logging->error("Could not write temporary key file (old key)");
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
        return undef;
      }
    } else {
      $oldkeyfile = $oldkey;
    }

    CertNanny::Logging->debug("Old keyfile: $oldkeyfile");

    $oldcertfile = CertNanny::Util->getTmpFile();
    if (!CertNanny::Util->writeFile(DSTFILE    => $oldcertfile,
                                    SRCCONTENT => $self->{CERT}->{RAW}->{PEM},
                                    FORCE      => 1,)
      ) {
      CertNanny::Logging->error("Could not write temporary cert file (old certificate)");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
      return undef;
    }

    CertNanny::Logging->debug("Old certificate: $oldcertfile");
  } ## end if ($scepsignaturekey ...)

  my %options = (sscep_enroll => {PrivateKeyFile => $requestkeyfile,
                                  CertReqFile    => $requestfile,
                                  SignKeyFile    => $oldkeyfile,
                                  SignCertFile   => $oldcertfile,
                                  LocalCertFile  => $newcertfile},
                 sscep        => {CACertFile => $scepracert,});

  my $enroller = $self->_getEnroller();
  $enroller->enroll(%options);

  unless ($self->_hasEngine()) {
    unlink $requestkeyfile;
    unlink $oldkeyfile  if (defined $oldkeyfile);
    unlink $oldcertfile if (defined $oldcertfile);
  }

  if (-r $newcertfile) {

    # successful installation of the new certificate.
    # parse new certificate.
    # NOTE: in previous versions the hooks reported the old certificate's
    # data. here we change it in a way that the new data is reported
    my $newcert;
    $newcert->{CERTINFO} = CertNanny::Util->getCertInfoHash(CERTFILE   => $newcertfile,
                                                            CERTFORMAT => 'PEM');

    # build new certificate chain
    $self->{STATE}->{DATA}->{CERTCHAIN} = $self->k_buildCertificateChain($newcert);

    if (!defined $self->{STATE}->{DATA}->{CERTCHAIN}) {
      CertNanny::Logging->error("Could not build certificate chain, probably trusted root certificate was not configured");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
      return undef;
    }

    $self->_executeHook($entry->{hook}->{renewal}->{install}->{pre},
                        '__NOTAFTER__'          => $self->{CERT}->{CERTINFO}->{NotAfter},
                        '__NOTBEFORE__'         => $self->{CERT}->{CERTINFO}->{NotBefore},
                        '__NEWCERT_NOTAFTER__'  => $newcert->{CERTINFO}->{NotAfter},
                        '__NEWCERT_NOTBEFORE__' => $newcert->{CERTINFO}->{NotBefore},);

    if (exists $entry->{INITIALENROLLEMNT}
        and $entry->{INITIALENROLLEMNT} eq 'yes') {

      CertNanny::Logging->debug("Install cert in initial entrollment build p12 first to import into the final location. ");

      my $importp12 = $entryname . "-import.p12";
      my $outp12 = File::Spec->catfile($entry->{statedir}, $importp12);

      chmod 0600, $outp12;

      # Todo Arkadius: Macht das sinn? Config ist singleton. Besser $config direkt verwenden
      my $conf = CertNanny::Config->new($self->{OPTIONS}->{CONFIG}->{CONFIGFILE});
      ##reset location to be passed correctly to the post install hook
      $entry->{location} = $conf->{CONFIG}->{certmonitor}->{$entryname}->{location};

      my %args = (FILENAME     => $outp12,
                  FRIENDLYNAME => 'cert1',
                  CACHAIN      => $self->{STATE}->{DATA}->{CERTCHAIN},
                  KEYFILE      => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE},
                  CERTFORMAT   => 'PEM',
                  CERTFILE     => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE},
                  EXPORTPIN    => $conf->{CONFIG}->{certmonitor}->{$entryname}->{key}->{pin});

# Todo Testen createPKCS12: Passt das noch? Die Methode war im Keystore als Dummy implementiert und nur in den Keys ausprogrammiert, wird aber über $self aufgerufen?!?
# Todo Testen createPKCS12: Was passiert hier? keine Zuweisung des Ergebnisses ....
      $self->createPKCS12(%args);
      CertNanny::Logging->debug("Created importp12 file :" . $importp12);
      my $target = $entry->{initialenroll}->{targetType};
      CertNanny::Logging->debug("Target keystore:" . $target);

      eval {
        eval "require CertNanny::Keystore::$target";
      };
      if ($@) {
        croak "Could not load $target keystore Aborted. $@";
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
        return 0;
      }

      eval {
        my %p12args = (FILENAME  => $outp12,
                       PIN       => $self->{PIN},
                       ENTRYNAME => $entryname,
                       ENTRY => $entry,
                       CONF      => $conf);

        # create pkcs12 file
        # in:
        # FILENAME => pkcs12 file to create
        # PIN => cert label to be used in pkcs#12 structure
        # ENTRYNAME => certificate location
        # CONF => keystore config to be implemented
		
		#CertNanny::Logging->debug("CertNanny::Keystore::${target}::importP12 ". Dumper(%p12args) );
		
        eval "CertNanny::Keystore::${target}::importP12( %p12args )";
        if ($@) {
          croak "Problem calling importP12 $@";
          CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
          return 0;
        }
      };
      if ($@) {
        croak "Could not execute $target keystore importP12 function. Aborted. $@";
        CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
        return 0;
      } else {
        CertNanny::Logging->debug("Compleated clean up after initial enrollment and p12 import.");
        if (   $entry->{initialenroll}->{auth}->{mode} eq "password"
            or $entry->{initialenroll}->{auth}->{mode} eq "anonymous") {

          my $selfsigncert = $entryname . "-selfcert.pem";
          my $outCert = File::Spec->catfile($entry->{statedir}, $selfsigncert);
          CertNanny::Logging->debug("delete selfsign cert: " . $outCert);

          if (-e $outCert) {
            unlink $outCert;
            CertNanny::Logging->debug("deleted " . $outCert);
          }
        } ## end if ($entry->...)

        unlink $outp12;
        $rc = 1;
      } ## end else [ if ($@) ]
    } else {
      $rc = $self->installCert(CERTFILE   => $newcertfile,
                               CERTFORMAT => 'PEM');
    }

    if (defined $rc and $rc) {

      $self->_renewalState("completed");

      $self->_executeHook($entry->{hook}->{renewal}->{install}->{post},
                          '__NOTAFTER__'          => $self->{CERT}->{CERTINFO}->{NotAfter},
                          '__NOTBEFORE__'         => $self->{CERT}->{CERTINFO}->{NotBefore},
                          '__NEWCERT_NOTAFTER__'  => $newcert->{CERTINFO}->{NotAfter},
                          '__NEWCERT_NOTBEFORE__' => $newcert->{CERTINFO}->{NotBefore},);

      # done
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
      return $rc;
    } ## end if (defined $rc and $rc)
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
    return undef;
  } ## end if (-r $newcertfile)

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Sending request");
  return 1;
} ## end sub _sendRequest


sub _getEnroller {
  ###########################################################################
  #
  # get enroller
  #
  # Input: -
  # 
  # Output: Enroller 
  #
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get enroller");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  unless (defined $entry->{ENROLLER}) {
    my $enrollertype_cfg = $entry->{enroll}->{type} || 'sscep';
    my $enrollertype     = ucfirst($enrollertype_cfg);
    eval "use CertNanny::Enroll::$enrollertype";
    if ($@) {
      print STDERR $@;
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get enroller");
      return undef;
    }

    CertNanny::Logging->debug("getEnroller" . ref($self->{INSTANCE}));
    
    eval "\$entry->{ENROLLER} = CertNanny::Enroll::$enrollertype->new(\$entry, \$config, \$entryname)";
    if ($@) {
      print STDERR $@;
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get enroller");
      return undef;
    }
  } ## end unless (defined $entry->{ENROLLER})

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get enroller");
  return $entry->{ENROLLER};
} ## end sub _getEnroller


sub _renewalState {

  # accessor method for renewal state
  my $self = shift;

  if (@_) {
    $self->{STATE}->{DATA}->{RENEWAL}->{STATUS} = shift;
    my $hook = $self->{INSTANCE}->{OPTIONS}->{ENTRY}->{hook}->{renewal}->{state}
      || $self->{OPTIONS}->{ENTRY}->{hook}->{renewal}->{state};
    $self->_executeHook($hook, '__STATE__' => $self->{STATE}->{DATA}->{RENEWAL}->{STATUS},);
  }
  return $self->{STATE}->{DATA}->{RENEWAL}->{STATUS};
} ## end sub _renewalState

1;
