#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::MQ;

use base qw(Exporter CertNanny::Keystore::OpenSSL);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

# use IO::File;
# use File::Spec;
use File::Copy;
use File::Basename;
# use Data::Dumper;

use CertNanny::Util;

# keyspecific needed modules
use Cwd;
use English;
# use Smart::Comments;
# use CertNanny::Keystore;
# use CertNanny::Keystore::OpenSSL;

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

  # get keystore PIN
  $self->{PIN} = $self->_unStash($entry->{location} . ".sth");

  $options->{gsk6cmd} = $config->get('cmd.gsk6cmd', 'FILE');

  # on certain platforms we need cannot find the location of the
  #   GSKit library directory ourselves, in this case it must be configured.
  $options->{gsklibdir} = $config->get('path.gsklib', 'FILE');
  $options->{gsklibdir} = undef if ($options->{gsklibdir} eq '');
  croak "gsk6cmd not found" unless (defined $options->{gsk6cmd} and -x $options->{gsk6cmd});

  $options->{JAVA} = $config->get('cmd.java', 'FILE');
  if (defined $ENV{JAVA_HOME}) {
    $options->{JAVA} ||= File::Spec->catfile($ENV{JAVA_HOME}, 'bin', 'java');
  }

  $options->{GSKIT_CLASSPATH} = $config->get('path.gskclasspath', 'FILE');

  # set key generation operation mode:
  # internal: create RSA key and request with MQ keystore
  # external: create RSA key and request outside MQ keystore (OpenSSL)
  #           and import resulting certificate/key as PKCS#12 into keystore
  $options->{keygenmode} = "external";
  if (exists $entry->{keygenmode}) {
    $options->{keygenmode} = $entry->{keygenmode};
  }

  # SANITY CHECKS
  croak "Illegal keygenmode: $options->{keygenmode}" unless ($options->{keygenmode} =~ /^(external)$/);

  # RETRIEVE AND STORE STATE
  # get previous renewal status
  $self->k_retrieveState() || return undef;

  # check if we can write to the file
  $self->k_storeState()    || croak "Could not write state file $self->{STATE}->{FILE}";

  # return new keystore object
  return $self;
} ## end sub new


sub DESTROY {
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
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (exists $self->{CERTINFO}) {
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
    return undef;
  }
  
  my $filename = $entry->{location};

  if (!-r "$filename.kdb") {
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
    return undef;
  }

  my $gsk6cmd = $options->{gsk6cmd};

  my $label = $self->_getCertLabel();
  if (!defined $label) {
    CertNanny::Logging->error("getCert(): could not get label");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
    return undef;
  }

  my $certfile = CertNanny::Util->getTmpFile();

  # get label name for user certificate
  my @cmd;
  @cmd = (qq("$gsk6cmd"), '-cert', '-extract', '-db', qq("$filename.kdb"), '-pw', qq("$self->{PIN}"), '-label', qq("$label"), '-target', qq("$certfile"), '-format', 'binary');

  # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
  # Todo pgk: Testen hidePin
  CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));

  if (system(join(' ', @cmd)) != 0) {
    unlink $certfile;
    CertNanny::Logging->error("getCert(): could not extract certificate");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
    return undef;
  }

  # read certificate from file and remove temp file
  my $content = CertNanny::Util->readFile($certfile);
  unlink $certfile;
  if (!defined $content) {
    CertNanny::Logging->error("getCert(): Could not open input file $certfile");
    CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
    return undef;
  }

# Todo Arkadius Frage: getCert: Wieso setzt die Methode dieses CERTINFO, die anderen Keymethoden geben nur einen Hash zurueck
# Todo Arkadius Frage: getCert: Hash Element LABEL existiert nur bei diesem Key!!
  $self->{CERTINFO}->{LABEL}      = $label;
  $self->{CERTINFO}->{CERTDATA}   = $content;
  $self->{CERTINFO}->{CERTFORMAT} = "DER";

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get main certificate from keystore");
  return $self->{CERTINFO};
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

  my $gsk6cmd = $options->{gsk6cmd};

  # new MQ keystore base filename
  my $newkeystorebase = File::Spec->catfile($entry->{statedir}, "tmpkeystore-" . $entryname);
  my $newkeystoredb = $newkeystorebase . ".kdb";

  # clean up
  unlink $newkeystoredb;

  if ($options->{keygenmode} eq "external") {
    CertNanny::Logging->info("Creating MQ keystore (via PKCS#12)");

    # create prototype PKCS#12 file
    # Todo pgk: {KEYFILE} oder {key}->{file}
    my $keyfile  = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
    my $certfile = $args{CERTFILE};
    my $label    = $self->{CERT}->{LABEL};

    CertNanny::Logging->info("Creating prototype PKCS#12 from certfile $certfile, keyfile $keyfile, label $label");

    #   # build array of ca certificate filenames
    #   my @cachain;
    #   foreach my $item (@{$self->{STATE}->{DATA}->{CERTCHAIN}}) {
    #       print Dumper $item;
    #       push(@cachain, $item);
    #   }

    # pkcs12file must be an absolute filename (see below, gsk6cmd bug)
    my $pkcs12file = $self->createPKCS12(FILENAME     => CertNanny::Util->getTmpFile(),
                                         FRIENDLYNAME => $label,
                                         EXPORTPIN    => $self->{PIN})->{FILENAME};

    #              CACHAIN => \@cachain);

    if (!defined $pkcs12file) {
      CertNanny::Logging->error("Could not create prototype PKCS#12 from received certificate");
      return undef;
    }
    CertNanny::Logging->info("Created PKCS#12 file $pkcs12file");

    # FIXME: create new pin?
    my @cmd = (qq("$gsk6cmd"), '-keydb', '-create', '-type', 'cms', '-db', qq("$newkeystoredb"), '-pw', qq("$self->{PIN}"), '-stash',);

    # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
    # CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));
    #
    # if (system(join(' ', @cmd)) != 0) {
    #   CertNanny::Logging->error("Keystore creation failed");
    #   return undef;
    # }
    # Todo pgk: Testen hidePin, runCommand
    if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
      CertNanny::Logging->error("Keystore creation failed");
      return undef;
    }

    CertNanny::Logging->info("New MQ Keystore $newkeystoredb created.");

    # remove all certificates from this keystore

    @cmd = (qq("$gsk6cmd"), '-cert', '-list', '-db', qq("$newkeystoredb"), '-pw', qq("$self->{PIN}"),);
    my @calabels;

#    CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));
#
#    my $fh;
#    if (!open $fh, join(' ', @cmd) . " |") {
#      CertNanny::Logging->error("Could not retrieve certificate list in MQ keystore");
#      return undef;
#    }
#    my $match = $entry->{labelmatch} || "ibmwebspheremq.*";
#    while (<$fh>) {
#      chomp;
#      s/\s*$//;
#      next if (m{ \A Certificates\ in\ database}xms);
#      next if (m{ \A No\ key}xms);
#      next if (m{ \A \S }xms);
#      next if (m{ $match }xms);
#      s/^\s*//;
#      push(@calabels, $_);
#    } ## end while (<$fh>)
#    close $fh;

    # Todo pgk: Testen hidePin, runCommand
    my $match = $entry->{labelmatch} || "ibmwebspheremq.*";
    chomp(my @certs = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1, HIDEPWD => 1));
    if (@certs) {
      foreach (@certs) {
        s/\s*$//;
        next if (m{ \A Certificates\ in\ database}xms);
        next if (m{ \A No\ key}xms);
        next if (m{ \A \S }xms);
        next if (m{ $match }xms);
        s/^\s*//;
        push(@calabels, $_);
      }
    } else {
      CertNanny::Logging->error("Could not retrieve certificate list in MQ keystore");
      return undef;
    }

    # now delete all preloaded CAs
    foreach (@calabels) {
      CertNanny::Logging->debug("deleting label '$_' from MQ keystore");

      @cmd = (qq("$gsk6cmd"), '-cert', '-delete', '-db', qq("$newkeystoredb"), '-pw', qq("$self->{PIN}"), '-label', qq("$_"),);

      # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));

      # if (system(join(' ', @cmd)) != 0) {
      #   CertNanny::Logging->error("Could not delete certificate from keystore");
      #   return undef;
      # }
      # Todo pgk: Testen hidePin, runCommand
      if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
        CertNanny::Logging->error("Could not delete certificate from keystore");
        return undef;
      }
    } ## end foreach (@calabels)

    # keystore is now empty
    # subordinate certificates from the CA Cert chain

    # all trusted Root CA certificates...
    my @trustedcerts = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};

    # ... plus all certificates from the CA key chain minus its root cert
    push(@trustedcerts, @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1 .. $#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);

    foreach my $item (@trustedcerts) {
      my @RDN = split(/(?<!\\),\s*/, $item->{CERTINFO}->{SubjectName});
      my $CN = $RDN[0];
      $CN =~ s/^CN=//;

      CertNanny::Logging->info("Adding certificate '$item->{CERTINFO}->{SubjectName}' from file $item->{CERTFILE}");

      # rewrite certificate into PEM format
      my $cacert = CertNanny::Util->convertCert(OUTFORMAT  => 'PEM',
                                                CERTFILE   => $item->{CERTFILE},
                                                CERTFORMAT => 'PEM',);

      if (!defined $cacert) {
        CertNanny::Logging->error("installCert(): Could not convert certificate $item->{CERTFILE}");
        return undef;
      }

      my $cacertfile = CertNanny::Util->getTmpFile();
      if (!CertNanny::Util->writeFile(DSTFILE    => $cacertfile,
                                      SRCCONTENT => $cacert->{CERTDATA})) {
        CertNanny::Logging->error("installCert(): Could not write temporary CA file");
        return undef;
      }

      @cmd = (qq("$gsk6cmd"), '-cert', '-add', '-db', qq("$newkeystoredb"), '-pw', qq("$self->{PIN}"), '-file', qq("$cacertfile"), '-format', 'ascii', '-label', qq("$CN"),);

      # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
      #
      # if (system(join(' ', @cmd)) != 0) {
      #   unlink $cacertfile;
      #   CertNanny::Logging->error("Could not add certificate to keystore");
      #   return undef;
      # }
      # Todo pgk: Testen hidePin, runCommand
      if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
        unlink $cacertfile;
        CertNanny::Logging->error("Could not add certificate to keystore");
        return undef;
      }
      unlink $cacertfile;

    } ## end foreach my $item (@trustedcerts)

    # finally add the PKCS#12 file to the keystore

    # NOTE: gsk6cmd contains a bug that makes it impossible to
    # specify absolute path names as -target
    # pkcs12file is guaranteed to be an absolute pathname (see above),
    # so it is safe to chdir to the target directory temporarily
    my ($basename, $dirname) = fileparse($newkeystoredb);
    my $lastdir = getcwd();
    if (!chdir($dirname)) {
      CertNanny::Logging->error("Could not import PKCS#12 file to keystore (chdir to $dirname failed)");
      return undef;
    }

    @cmd = (qq("$gsk6cmd"), '-cert', '-import', '-target', qq("$basename"), '-target_pw', qq("$self->{PIN}"), '-file', qq("$pkcs12file"), '-pw', qq("$self->{PIN}"), '-type', 'pkcs12',);

    # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
    #
    # if (system(join(' ', @cmd)) != 0) {
    #   CertNanny::Logging->error("Could not import PKCS#12 file to keystore");
    #   chdir($lastdir);
    #   return undef;
    # }
    # Todo pgk: Testen hidePin, runCommand
    if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
      CertNanny::Logging->error("Could not import PKCS#12 file to keystore");
      chdir($lastdir);
      return undef;
    }
    chdir($lastdir);

    CertNanny::Logging->info("Keystore created");
  } elsif ($options->{keygenmode} eq "internal") {
    CertNanny::Logging->info("Internal key generation not supported");

    #   my @cmd = (qq("$gsk6cmd"),
    #        '-certreq',
    #        '-create',
    #        '-file',
    #        qq("$result->{REQUESTFILE}"),
    #        '-db',
    #        qq("$kdbfile"),
    #        '-pw',
    #        qq("$self->{PIN}"),
    #        '-dn',
    #        qq("$DN"),
    #        '-label',
    #        qq("$label"),
    #        '-size',
    #        '1024');

    return undef;
  } ## end elsif ($options->...)

  # now replace the old keystore with the new one
  if (!-r $newkeystoredb) {
    CertNanny::Logging->error("Could not access new prototype keystore file $newkeystoredb");
    return undef;
  }

  CertNanny::Logging->info("Installing MQ keystore");
  my $oldlocation = $entry->{location};

  my @newkeystore = ();
  foreach my $ext (qw(.crl .rdb .kdb .sth)) {

    my $data = CertNanny::Util->readFile($newkeystorebase . $ext);
    if (!defined $data) {
      CertNanny::Logging->error("Could read new keystore file " . $newkeystorebase . $ext);
      return undef;
    }

    # schedule for installation
    push(@newkeystore, {DESCRIPTION => "End entity $ext file",
                        FILENAME    => $oldlocation . $ext,
                        CONTENT     => $data});
  } ## end foreach my $ext (qw(.crl .rdb .kdb .sth))

  ######################################################################
  # try to write the new keystore

  if (!$self->k_saveInstallFile(@newkeystore)) {
    CertNanny::Logging->error("Could not install new keystore");
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
  #           KEYFILE   => file containing the key data
  #           KEYFORMAT => 'PEM' or 'DER'
  #           KEYTYPE   => format (e. g. 'PKCS8' or 'OpenSSL'
  #           KEYPASS   => key pass phrase (only if protected by pass phrase)
  #         or undef on error
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  # initialize Java and GSKit environment
  if (!$self->_getIBMJavaEnvironment()) {
    CertNanny::Logging->error("Could not determine IBM Java environment");
    return undef;
  }

  my $keystore = $entry->{location} . ".kdb";

  my $label = $self->_getCertLabel();
  if (!defined $label) {
    CertNanny::Logging->error("Could not get certificate label");
    return undef;
  }

  my $p8file = CertNanny::Util->getTmpFile();
  chmod 0600, $p8file;

  my $extractkey_jar = File::Spec->catfile($config->get("path.libjava", "FILE"), 'ExtractKey.jar');
  if (!-r $extractkey_jar) {
    CertNanny::Logging->error("getKey(): could not locate ExtractKey.jar file");
    return undef;
  }

  my $separator = $OSNAME =~ m{ MSWin }xms ? ';' : ':';
  #if ($OSNAME =~ m{ MSWin }xms) {
  #  $separator = ';';
  #}

  my $classpath = $options->{GSKIT_CLASSPATH} . $separator . $extractkey_jar;

  my @gsklibdir;
  if (defined $options->{gsklibdir}) {
    @gsklibdir = ('-Djava.library.path=' . qq("$options->{gsklibdir}"));
    $ENV{PATH} .= $separator . $self->{OPTIONS}->{gsklibdir};
  }
  
  my @cmd = (qq("$options->{JAVA}"), 
             '-classpath', qq("$classpath"), 
             'de.cynops.java.crypto.keystore.ExtractKey', @gsklibdir, 
             '-keystore', qq("$keystore"), 
             '-storepass', qq("$self->{PIN}"), 
             '-keypass', qq("$self->{PIN}"), 
             '-key', qq("$label"), 
             '-keyfile', qq("$p8file"), 
             '-provider', 'IBMJCE', 
             '-type', 'CMS');

  # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
  #CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));
  #if (system(join(' ', @cmd)) != 0) {
  #  CertNanny::Logging->error("getKey(): could not extract private key");
  #  unlink $p8file;
  #  return undef;
  #}

  # Todo pgk: Testen hidePin, runCommand
  if (CertNanny::Util->RunCommand(\@cmd, HIDEPWD => 1)) {
    CertNanny::Logging->error("getKey(): could not extract private key");
    unlink $p8file;
    return undef;
  }
  my $keydata = CertNanny::Util->readFile($p8file);
  unlink $p8file;

  if ((!defined $keydata) or ($keydata eq "")) {
    CertNanny::Logging->error("getKey(): Could not convert private key");
    return undef;
  }

  return {KEYDATA   => $keydata,
          KEYTYPE   => 'PKCS8',
          KEYFORMAT => 'DER'};  # no keypass, unencrypted
} ## end sub getKey


sub createRequest {
  ###########################################################################
  #
  # generate a certificate request
  # 
  # Input: -
  # 
  # Output: caller gets a hash ref (as expected by k_convertKey()):
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

  if ($self->{OPTIONS}->{keygenmode} eq "external") {
    CertNanny::Logging->info("External request generation (using OpenSSL)");
    return $self->SUPER::createRequest() if $self->can("SUPER::createRequest");
  }

  return undef;
} ## end sub createRequest


sub selfSign {
  ###########################################################################
  #
  # sign the ceritifate
  # 
  # Input: -
  # 
  # Output: caller gets a hash ref (as expected by k_convertKey()):
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
  # sub getInstalledRoots {
  #   my $self = shift;
  #   return $self->SUPER::getInstalledRoots(@_) if $self->can("SUPER::getInstalledRoots");
  # }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get all installed root certificates");
  my $self = shift;
  my %args = (@_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = 0;
  my $certFound = {};
  
  if (!defined($args{TARGET}) or ($args{TARGET} eq 'LOCATION')) {
    if (defined(my $locName = $config->get("keystore.$entryname.location", 'FILE'))) {
      my ($certRef, @certList, $certData, $certSha1, $certAlias, $certCreateDate, $certType, $certFingerprint);
      my @cmd = $self->_buildGskCmd($locName, '-list');
      @certList = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1, HIDEPWD => 1);
      foreach (@certList) {
        if ($_ =~ m/^([^,]*), ([0-3][0-9]\.[0-1][0-9]\.20[0-9][0-9]), (PrivateKeyEntry|trustedCertEntry),.*$/) { # gets Privat Key as well
        # if ($_ =~ m/^([^,]*), ([0-3][0-9]\.[0-1][0-9]\.20[0-9][0-9]), (trustedCertEntry),.*$/) {
          ($certAlias, $certCreateDate, $certType) = ($1, $2, $3);
        }
        if ($_ =~ m/^[^:]*\): ([0-9A-F:]*).*$/) {
          $certFingerprint = $1;
          @cmd = $self->_buildKeytoolCmd($locName, '-list', '-rfc', '-alias', $certAlias);

          $certData = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1, HIDEPWD => 1);
          $certRef  = $self->getCert(CERTDATA => $certData);
          while ($certRef and ($certData = $certRef->{CERTDATA})) {
            $certSha1 = CertNanny::Util->getCertSHA1(%{$certRef});
            
            $certFound->{$certSha1->{CERTSHA1}}->{CERTALIAS}       = $certAlias;
            $certFound->{$certSha1->{CERTSHA1}}->{CERTCREATEDATE}  = $certCreateDate;
            $certFound->{$certSha1->{CERTSHA1}}->{CERTTYPE}        = $certType;
            $certFound->{$certSha1->{CERTSHA1}}->{CERTFINGERPRINT} = $certFingerprint;
            $certFound->{$certSha1->{CERTSHA1}}->{CERTDATA}        = $certData;
            $certFound->{$certSha1->{CERTSHA1}}->{CERTFORMAT}      = $certRef->{CERTFORMAT};
            $certFound->{$certSha1->{CERTSHA1}}->{CERTINFO}        = CertNanny::Util->getCertInfoHash(CERTDATA => $certData);
            
            $certRef  = $self->getCert(CERTDATA => $certRef->{CERTREST});
          }
        }
      }
    }
  }
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "get all installed root certificates");
  return $certFound;
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
  #   - ebenfalls keine Unterscheidung zwischen den Typen der Zertifikate. 
  #     Deswegen gilt das gleiche für Root Certs wie schon bei jks.
  #   - für die Cert Installation:
  #       gsk7capicmd_64 -cert -add -file CA/uat/testca10.pem -label TestCA -db name_your_db.kdb -format ascii
  #   - wenn die Kette nicht vollständig ist, dann verweigert gsk die Aufnahme 
  #     des Zertifikats in den Store.

  # Beispiel:
  # #!/bin/bash
  # 
  # gsk7cmd_64 -cert -import -db certnanny.reworktest.example.com_certnannyOpenSSL.p12new -pw yPdNQfoR55RTajom7VU44g -target key.kdb -target_pw 1234567890 -label cert1
  #
  # #create gsk7 keystore
  # gsk7capicmd_64 -keydb -create -db name_your_db -pw password1
  # 
  # #view available certificates
  # gsk7capicmd_64 -cert -list -db name_your_db.kdb
  # 
  # #install certificate
  # #Parameter:
  # #-file: <certificate you want to install>
  # #-label: <alias for the certificate to use in your database>
  # #-db: <name of your database>.kdb
  # #-format: ascii when using .pem files, binary when using .der files
  # #NOTE: when trying to install a certificate chain, start with the Root of the chain!
  # gsk7capicmd_64 -cert -add -file CA/uat/testca10.pem -label TestCA -db name_your_db.kdb -format ascii
  # 
  # #known errors:
  # #Error 146: GSKKM_ERR_INVALID_CERT_CHAIN
  # #Part of the certificate chain is missing

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
    my $availableRootCAs = $args{AVAILABLE};

    my @cmd;
    my $certData;

    if (!defined($availableRootCAs)) {
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
      }
    }

    if (!defined($availableRootCAs)) {
      $rc = CertNanny::Logging->error("No root certificates found in " . $config-get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.dir", 'FILE'));
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
                                       SRCFILE => $availableRootCAs->{$certSHA1}->{CERTDATA});
            @cmd = $self->_buildKeytoolCmd($locName, '-importcert', '-file', $tmpFile, '-trustcacerts', '-alias', $availableRootCAs->{$certSHA1}->{CERTALIAS});
            if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
              CertNanny::Logging->error("Error importing root cert " . $availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
            }
            # Postinstallhook
            $self->_executeHook($entry->{hook}->{roots}->{install}->{post},
                                '__TYPE__'        => 'FILE',
                                '__CERTFILE__'    => $availableRootCAs->{$certSHA1}->{CERTFILE},
                                '__FINGERPRINT__' => $availableRootCAs->{$certSHA1}->{CERTINFO}->{CertificateFingerprint},
                                '__TARGET__'      => $locName);
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


sub _buildGskCmd {
  # build a GSK command (as an array) containing all common options, the
  # location (if provided as an argument) and further arguments (if provided)
  # the common options are:
  my $self     = shift;
  my $location = shift;

  my $options = $self->{OPTIONS};
  my $entry   = $options->{ENTRY};

  my @cmd = (qq("$options->{gsktool}"));
  # Commands-keydb - create | -cert -add |  -cert -import | -cert -list
  push(@cmd, -db        => qq("$entry->{db}"))        if ($entry->{db});
  push(@cmd, -pw        => qq("$entry->{pw}"))        if ($entry->{pw});
  push(@cmd, -target    => qq("$entry->{target}"))    if ($entry->{target});
  push(@cmd, -target_pw => qq("$entry->{target_pw}")) if ($entry->{target_pw});
  push(@cmd, -label     => qq("$entry->{label}"))     if ($entry->{label});
  push(@cmd, -file      => qq("$entry->{file}"))      if ($entry->{file});
  push(@cmd, -format    => qq("$entry->{format}"))    if ($entry->{format});
  push(@cmd, @_);
  @cmd;
} ## end sub _buildKeytoolCmd


sub _getIBMJavaEnvironment {
  # determine location of the JAVA binary and the necessary CLASSPATH
  # definition for GSKit
  # sets global option JAVA to the location of the Java executable
  # sets global option GSKIT_CLASSPATH to classpath required for accessing
  #   the IBM GSKIT Keystore Implementation
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (defined $options->{JAVA}            && $options->{JAVA}            ne '' && 
      defined $options->{GSKIT_CLASSPATH} && $options->{GSKIT_CLASSPATH} ne '') {
    return 1;
  }

  if ($OSNAME =~ m{ MSWin }xms) {
    # determine classpath for IBM classes
    my $gsk6cmd = $options->{gsk6cmd};

    my $cmd = qq("$gsk6cmd") . " -version";

    CertNanny::Logging->debug("Execute: $cmd");
    open my $fh, $cmd . '|';
    if (!$fh) {
      CertNanny::Logging->error("getIBMJavaEnvironment(): could not run gskit command line executable");
      return undef;
    }

    my $java;
    my $classpath;
  LINE:
    while (my $line = <$fh>) {
      if ($line =~ m{ \A \s* "(.*)" \s* -classpath \s* "(.*?)" }xms) {
        $options->{JAVA}            = $1;
        $options->{GSKIT_CLASSPATH} = $2;
        close $fh;
        return 1;
      }
    }
    close $fh;
    CertNanny::Logging->error("getIBMJavaEnvironment(): could not determine GSK classpath");
    return undef;
  } else {
    # assume we have a Unix-like system
    my $javacmd = File::Spec->catfile($ENV{JAVA_HOME}, 'bin', 'java');
    if (!-x $javacmd) {
      CertNanny::Logging->error("getIBMJavaEnvironment(): could not determine Java executable (JAVA_HOME not set?)");
      return undef;
    }
    $options->{JAVA} = $javacmd;

    # determine classpath for IBM classes
    my $gsk6cmd = $options->{gsk6cmd};

    my $cmd = ". $gsk6cmd >/dev/null 2>&1 ; echo \$JAVA_FLAGS";
    CertNanny::Logging->debug("Execute: $cmd");
    my $classpath = `$cmd`;
    chomp $classpath;

    if (($? != 0) or (!defined $classpath) or ($classpath eq "")) {
      CertNanny::Logging->error("getIBMJavaEnvironment(): could not determine GSK classpath");
      return undef;
    }

    # remove any options left over
    $classpath =~ s/-?-\w+//g;
    $classpath =~ s/^\s*//g;
    $classpath =~ s/\s*$//g;

    CertNanny::Logging->debug("gsk6cmd classpath: $classpath");

    $options->{GSKIT_CLASSPATH} = $classpath;

    return 1;
  } ## end else [ if ($OSNAME =~ m{ MSWin }xms)]

  return undef;
} ## end sub getIBMJavaEnvironment


sub _unStash {
# descramble password in MQ stash file
  my $self      = shift;
  my $stashfile = shift;

  my $content = CertNanny::Util->readFile($stashfile);
  if (!defined $content) {
    CertNanny::Logging->error("_unStash(): Could not open input file $stashfile");
    return undef;
  }

  # =8->
  my $result = pack("C*", map {$_ ^ 0xf5} unpack("C*", $content));
  return substr($result, 0, index($result, chr(0)));
} ## end sub _unStash

sub _getCertLabel {
# get label of end entity certificate
  my $self = shift;

  if (exists $self->{CERTLABEL}) {
    return $self->{CERTLABEL};
  }

  my $filename = $self->{OPTIONS}->{ENTRY}->{location};

  return unless (-r "$filename.kdb");

  my $gsk6cmd = $self->{OPTIONS}->{gsk6cmd};
  croak "Could not get gsk6cmd location" unless defined $gsk6cmd;

  # get label name for user certificate
  my @cmd = (qq("$gsk6cmd"), '-cert', '-list', 'personal', '-db', qq("$filename.kdb"), '-pw', qq("$self->{PIN}"));

  # CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
  # Todo pgk: Testen hidePin
  CertNanny::Logging->debug("Execute: " . CertNanny::Util->hidePin(join(' ', @cmd)));

  my $fh;
  if (!open $fh, join(" ", @cmd) . "|") {
    CertNanny::Logging->error("getCert(): could not run gsk6cmd");
    return undef;
  }
  binmode $fh;

  my $label;
  my $match = $self->{OPTIONS}->{ENTRY}->{labelmatch} || "ibmwebspheremq.*";

  while (<$fh>) {
    chomp;
    next if /Certificates in database/;
    s/^\s*//;
    s/\s*$//;
    if (!defined $match
        or /$match/) {
      $label = $_;
      last;
    }
  } ## end while (<$fh>)
  close $fh;

  if (!defined $label) {
    CertNanny::Logging->error("getCert(): could not get label");
    return undef;
  }

  # cache information
  $self->{CERTLABEL} = $label;

  return $label;
} ## end sub _getCertLabel


1;
