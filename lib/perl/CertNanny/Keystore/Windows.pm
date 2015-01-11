#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::Windows;

use base qw(Exporter CertNanny::Keystore::OpenSSL);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;
use Data::Dumper;

use IO::File;
use File::Spec;
use File::Copy;
use POSIX;
# use File::Basename;
# use Data::Dumper;

use CertNanny::Util;

# keyspecific needed modules
use Cwd;

################################################################################


sub new {
  #implement new?
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
  CertNanny::Logging->debug("new(): Windows Keystore.\n");

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
  #my $pin = "";
  #    $pin = $entry->{key}->{pin};
  $entry->{key}->{pin} = "" if (!exists $entry->{key}->{pin});

  # export the pin to this instance
  $self->{PIN} = $entry->{key}->{pin};

  # sample sanity checks for configuration settings
  foreach my $parameter (qw(location)) {
    if (!defined $entry->{$parameter}) {
      croak("keystore.$parameter $entry->{$parameter} not defined.");
      return undef;
    }
  }

  $entry->{storelocation} ||= 'user';

  my $engine_section                                  = $self->k_getDefaultEngineSection();
  $entry->{enroll}->{sscep}->{engine}                 = $engine_section;
  $entry->{enroll}->{$engine_section}->{engine_id}    = "capi";
  $entry->{enroll}->{$engine_section}->{dynamic_path} = $entry->{hsm}->{dynamic_path};

  if (!$self->_certReqReadTemplate()) {
    CertNanny::Logging->error("new(): Could not read template file for certreq.");
    return undef;
  }
  
  if ($entry->{storelocation} eq "machine") {
    $entry->{certreq}->{NewRequest}->{MachineKeySet}       = "TRUE";
    $entry->{enroll}->{sscep_engine_capi}->{storelocation} = "LOCAL_MACHINE";
  }

  # RETRIEVE AND STORE STATE
  # get previous renewal status
  $self->k_retrieveState($entry->{selfhealing) || return undef;

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
  my $self     = shift;
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $certdata = "";

  my $serial;
  my $returned_data = "";

  # delete any old certificates, just to be sure
  foreach my $cert (glob File::Spec->catfile($entry->{statedir}, 'Blob*.crt')) {
    unlink $cert;
  }
  my $derfile_tmp = $self->_certUtilWriteCerts((SERIAL => $serial));
  
  unless (defined($derfile_tmp)) {
    CertNanny::Logging->debug("No serial was defined before so all certs were dumped and are now parsed");
    my $olddir = getcwd();
    chdir $entry->{statedir};
    my @certs = glob "Blob*.crt";
    my $active_cert;
 
    foreach my $certfilename (@certs) {
      my $certinfo = CertNanny::Util->getCertInfoHash(CERTFILE => $certfilename);
      CertNanny::Logging->debug("Parsing certificate with filname $certfilename and subjectname $certinfo->{SubjectName}");
      my $notbefore = CertNanny::Util->isoDateToEpoch($certinfo->{NotBefore});
      my $notafter  = CertNanny::Util->isoDateToEpoch($certinfo->{NotAfter});
      my $now       = time;
      CertNanny::Logging->debug("Searching for " . $entry->{location} . " in $certinfo->{SubjectName} and NotAfter $notafter where current time is $now");
      CertNanny::Logging->debug("Result of index: " . index($certinfo->{SubjectName}, $entry->{location}));
 
      if (index($certinfo->{SubjectName}, $entry->{location}) != -1 && $notafter > $now) {
        CertNanny::Logging->debug("Found something!");
        my $active_notafter = CertNanny::Util->isoDateToEpoch($active_cert->{NotAfter}) if (defined($active_cert));
 
        if (!defined($active_cert) || $active_notafter < $notafter) {
          $active_cert = $certinfo;
          $serial      = $certinfo->{SerialNumber};
          $serial =~ s/://g;
          CertNanny::Logging->debug("The current certificate is the newest and thus will be used from hereon");
        }
      } ## end if (index($certinfo->{...}))
    } ## end foreach my $certfilename (@certs)
 
    chdir $olddir;
    if (!defined($serial)) {
      CertNanny::Logging->error("Could not retrieve a valid certificate from the keystore");
      CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
      return undef;
    }
 
    $derfile_tmp = $self->_certUtilWriteCerts((SERIAL => $serial));
  } ## end unless (defined($derfile_tmp...))
 
# Todo pgk: Testen {CONFIG}->get
  my $openssl = $config->get('cmd.openssl', 'FILE');
  my @cmd = (qq("$openssl"), 'x509', '-in', qq("$derfile_tmp"), '-inform', 'DER');
# Todo pgk: Testen
  $certdata = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1);
#  my $cmd = join(" ", @cmd);
#  CertNanny::Logging->debug("Execute: $cmd");
#  $certdata = `$cmd`;
#  CertNanny::Logging->debug("Dumping resulting certificate in PEM format:\n$certdata");
  
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Get main certificate from keystore");
  return {CERTDATA   => $certdata,
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
  # convert cert to pkcs#12
  # execute import_cert.exe import test100-cert.pfx
  my $self = shift;
  my %args = (@_);    # argument pair list
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $ret = 1;
  CertNanny::Logging->debug("enter sub installCert in widnows.pm \n");
  $self->_installCertchain();

  #my $keyfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
  my $certfile = $args{CERTFILE};

  my @cmd      = ('certreq', '-accept', qq("$certfile"));
#  my $cmd      = join(" ", @cmd);
#  CertNanny::Logging->debug("Execute: $cmd");
#  my $cmd_output = `$cmd`;
#  CertNanny::Logging->debug("certreq output:\n$cmd_output");
#  if ($? != 0) {
#    CertNanny::Logging->error("installCert(): Certificate could not be imported. Output of command $cmd was:\n$cmd_output");
#    return undef;
#  }
  # Todo pgk: Testen hidePin, runCommand
  if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)) {
    CertNanny::Logging->error("installCert(): Certificate could not be imported.");
    return undef;
  }

  # if everything was successful, we need to execute cleanup
  my $requestfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{REQUESTFILE};

  # delete request, otherwise certnanny thinks we have a pending request...
  if (-e $requestfile) {
    unless (unlink $requestfile) {
      CertNanny::Logging->error("installCert(): Could not delete the old csr. Since the certificate was already installed, this is *critical*. Delete it manually or the next renewal will fail.");
    }
  }
  
  my $certinfo = CertNanny::Util->getCertInfoHash(CERTFILE   => $certfile,
                                                    CERTFORMAT => 'PEM');  
  if (!$self->_deleteOldCerts($certfile)) {
    return 0;
  }
   
  if((POSIX::uname())[2] ne "5.2"){
    if(defined $entry->{iis} && defined $entry->{iis}->{ipport}){
    CertNanny::Logging->debug("found app configuration for IIS 7 $entry->{iis}->{appid} try to bind  certificate to port ". $entry->{iis}->{ipport});
  	my @netshdel 	= ('netsh','http', 'delete','sslcert', 'ipport='.$entry->{iis}->{ipport});
  	my $netshdel    = join(" ", @netshdel);
  	CertNanny::Logging->debug("netsh cmd: $netshdel");
       
    if (CertNanny::Util->runCommand(\@netshdel)) {
      CertNanny::Logging->error("installCert(): failed to unbind https certificate for IIS7.");
      #return undef;
    }

  	my @wincerthash = split(':', $certinfo->{CertificateFingerprint});
  	my $hash = join('', @wincerthash);
  	$hash = lc($hash);
  	
  	my @netsh      = ('netsh','http', 'add','sslcert', 'ipport='.$entry->{iis}->{ipport},'certhash="'. $hash. '"','appid="{' . $entry->{iis}->{appid} . '}"'); 
      my $netsh      = join(" ", @netsh);
      CertNanny::Logging->debug("netsh cmd: $netsh");
       
    	if (CertNanny::Util->runCommand(\@netsh)) {
      	CertNanny::Logging->error("installCert(): failed to register https certificate for IIS 7.");
      	#return undef;
    	}
    } 
    }else{
      if(defined $entry->{iis} && defined $entry->{iis}->{ipport}){
      CertNanny::Logging->debug("found app configuration for IIS6  $entry->{iis}->{appid} try to bind  certificate to port ". $entry->{iis}->{ipport});
      #my @netshdel  = ('netsh','http', 'delete','sslcert', 'ipport='.$entry->{iis}->{ipport});
      # httpcfg delete ssl -i 0.0.0.0:443     
      my @netshdel  = ('httpcfg','delete','ssl', '-i' , '"'.$entry->{iis}->{ipport}.'"');
      
      my $netshdel    = join(" ", @netshdel);
      CertNanny::Logging->debug("httpcfg cmd: $netshdel");
         
      if (CertNanny::Util->runCommand(\@netshdel)) {
        CertNanny::Logging->error("installCert(): failed to unbind https certificate on IIS 6.");
        #return undef;
      }
  
      my @wincerthash = split(':', $certinfo->{CertificateFingerprint});
      my $hash = join('', @wincerthash);
      $hash = lc($hash);
      
      #my @netsh      = ('netsh','http', 'add','sslcert', 'ipport='.$entry->{iis}->{ipport},'certhash="'. $hash. '"','appid="{' . $entry->{iis}->{appid} . '}"'); 
      my @netsh  = ('httpcfg','set', 'ssl','-i', '"'.$entry->{iis}->{ipport}.'"' ,'-h', '"'. $hash.'"','-g',  '"{'. $entry->{iis}->{appid}. '}"'); 
    
        my $netsh      = join(" ", @netsh);
        CertNanny::Logging->debug("httpcfg cmd: $netsh");
         
        if (CertNanny::Util->runCommand(\@netsh)) {
          CertNanny::Logging->error("installCert(): failed to register https certificate on IIS 6.");
          #return undef;
        }
    } 
     
     
     
    }

  return $ret;
} ## end sub installCert


sub getKey() {
  # Todo Arkadius Frage: getKey Input/Output passt nicht zu den restlichen Keys
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
  # 
  # Because it supports engines, this is easy.
  # It returns its location value which is okay for the capi engine
  my $self = shift;

  return $self->{OPTIONS}->{ENTRY}->{location};
}


sub createRequest() {
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
  my %args = (@_);    # argument pair list

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  $entry->{certreq}->{NewRequest}->{Subject} = qq("$self->{CERT}->{CERTINFO}->{SubjectName}");
  my $inf_file_out = $self->_certReqWriteConfig();
  my $result;

  $result->{REQUESTFILE} = File::Spec->catfile($entry->{statedir}, $entryname . ".csr");
  $result->{KEYFILE}     = $entry->{location};

  unless ($self->_checkRequestSanity()) {
    CertNanny::Logging->error("createRequest(): Sanitycheck could not resolve all problems. Please fix manually.");
    return undef;
  }

  # if the file exists, the sanity check has checked that everything is just fine...
  unless (-e $result->{REQUESTFILE}) {
    my @cmd = ('certreq', '-new', qq("$inf_file_out"), qq("$result->{REQUESTFILE}"));
    # my $cmd = join(' ', @cmd);
    # CertNanny::Logging->debug("Execute: $cmd");
    # `$cmd`;
    # if ($? != 0) {
    #   CertNanny::Logging->error("createRequest(): Executing certreq cmd error: $cmd");
    #   return undef;
    # }
    
    #Todo pgk Testen: runCommand
    my $rc = CertNanny::Util->runCommand(\@cmd);
    if ($rc != 0) {
      CertNanny::Logging->error("createRequest(): Executing certreq cmd: " . join(' ', @cmd) . " error: " . $rc);
      return undef;
    }
  } ## end unless (-e $result->{REQUESTFILE...})

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
  #my $self = shift;
  my %args = (@_);    # argument pair list

  my $entry     = $args{ENTRY};
  my $config    =  $args{CONFIG};

  my @cmd;
  push(@cmd, 'certutil');

  CertNanny::Logging->debug("storelocation:" . $entry->{storelocation});
  
  if ($entry->{storelocation} eq 'user') {
    CertNanny::Logging->debug("Store location for import is user");
    push(@cmd, '-user');
  }

  push(@cmd, '-p');
  push(@cmd, "$args{PIN}");
  push(@cmd, "-importPFX");
  push(@cmd, "$args{FILENAME}");
  push(@cmd, "NoExport,NoRoot");

  my $cmd_output = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1);

  #chdir $olddir;
  CertNanny::Logging->debug("Dumping output of above command:\n $cmd_output");
  return 1;
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
  # 
  # Installation and Certificate Binding for Windows Server 2008
  # ===============================================================
  # 
  # 1.) import certificate to certificate store
  # certutil -p <password> -importpfx <filename.pfx>
  # 
  # 2) delete old binding
  # netsh http delete sslcert 0.0.0.0:<portnumber>
  # 
  # Step 2 is only necessary when renewing certificate
  # 
  # 3.) bind new certificate to port
  # netsh http add sslcert ipport=0.0.0.0:<portnumber> certhash=<fingerprint_new_cert> appid={<application_id>}
  # 
  # The current application_id for the IIS server is 4dc3e181-e14b-4a21-b022-59fc669b0914 (source: google.com).
  # NOTE: you can only bind one certificate to a port. If another certificate is already bound to a port then netsh will throw an error. Run step 2 in this case
  # 
  # 4.) enable certificate in IIS
  # %windir%\System32\inetsrv\appcmd.exe set config -section:system.applicationHost/sites /+"[name='<IIS_name_for_website>'].bindings.[protocol='https',bindingInformation='*:<port_to_listen_at>:']" /commit:apphost
  # 
  # Step 4 is only necessesary for initial certificate installation. Not necessary for certificate renewal because IIS will always use the certificate that is currently bound to the port  
  
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



sub _certUtilWriteCerts() {
  my $self = shift;
  my %args = (@_,);
  $args{OPTIONS} = ['-split'];
  push(@{$args{OPTIONS}}, '-user') if $self->{OPTIONS}->{ENTRY}->{storelocation} eq "user";
  $args{COMMAND} = '-store';
  my $tmpfile = CertNanny::Util->getTmpFile();
  $args{OUTFILE} = qq($tmpfile) if defined $args{SERIAL};
  CertNanny::Logging->debug("Calling certutil.exe to retrieve certificates.");
  my $outfile_tmp = $self->_certUtilWriteCertsCmd(%args);
  return $outfile_tmp;
} ## end sub _certUtilWriteCerts


sub _certUtilWriteCertsDeleteCert() {
  my $self = shift;
  my %args = (@_,);
  $args{OPTIONS} = [];
  push(@{$args{OPTIONS}}, '-user') if $self->{OPTIONS}->{ENTRY}->{storelocation} eq "user";
  $args{COMMAND} = '-delstore';
  my $serial = $args{SERIAL};

  #	my $store = $args{STORE} || "My";
  unless ($serial) {
    CertNanny::Logging->error("A deletion was requested, no serial.");
    return undef;
  }
  CertNanny::Logging->debug("Deleting ceritifcate with serial $serial from store $self->{OPTIONS}->{ENTRY}->{storelocation}");
  $self->_certUtilWriteCertsCmd(%args);
  return !$?;
} ## end sub _certUtilWriteCertsDeleteCert


sub _certUtilWriteCertsCmd() {
  my $self        = shift;
  my %args        = (@_,);
  my $serial      = $args{SERIAL} if defined $args{SERIAL};
  my $store       = $args{STORE} || "My";
  my $outfile_tmp = $args{OUTFILE} if defined $args{OUTFILE};

  CertNanny::Logging->debug("Serial is $serial.") if defined($serial);

  my @cmd;
  push(@cmd, 'certutil');
  foreach my $option (@{$args{OPTIONS}}) {
    push(@cmd, $option);
  }
  push(@cmd, $args{COMMAND});
  push(@cmd, qq("$store"));                                 # NOTE: It is *mandatory* to have double quotes here!
  push(@cmd, $serial) if defined $serial;
  push(@cmd, qq("$outfile_tmp")) if defined $outfile_tmp;
  my $cmd = join(" ", @cmd);
  my $olddir = getcwd();
  chdir($args{TARGETDIR} || $self->{OPTIONS}->{ENTRY}->{statedir});
  my @certs = glob "Blob*.crt";

  foreach my $cert (@certs) {
    unlink $cert;
  }
  CertNanny::Logging->debug("Execute: $cmd.");
  my $cmd_output = `$cmd`;
  chdir $olddir;
  CertNanny::Logging->debug("Dumping output of above command:\n $cmd_output");
  CertNanny::Logging->debug("Output was written to $outfile_tmp") if defined($outfile_tmp);
  return $outfile_tmp;
} ## end sub _certUtilWriteCertsCmd


sub _certReqWriteConfig() {
  my $self = shift;
  my %args = (@_,);

  my $inf_file_out = CertNanny::Util->getTmpFile();
  open(my $configfile, ">", $inf_file_out) or die "Cannot write $inf_file_out";

  foreach my $section (keys %{$self->{OPTIONS}->{ENTRY}->{certreq}}) {
    print $configfile "[$section]\n";
    while (my ($key, $value) = each(%{$self->{OPTIONS}->{ENTRY}->{certreq}->{$section}})) {
      if (-e $value and $^O eq "MSWin32") {

        #on Windows paths have a backslash, so in the string it is \\.
        #In the config it must keep the doubled backslash so the actual
        #string would contain \\\\. Yes this is ridiculous...
        $value =~ s/\\/\\\\/g;
      }

      if ($key eq "Subject") {
        $value =~ s/,\s+(\w+=)/,$1/g;
      }
      print $configfile "$key=$value\n";
    } ## end while (my ($key, $value) ...)
  } ## end foreach my $section (keys $self...)

  close $configfile;

  return $inf_file_out;
} ## end sub _certReqWriteConfig


sub _certReqReadTemplate() {
  my $self = shift;

  my $inf_file_in = $self->{OPTIONS}->{ENTRY}->{certreqinf};
  if (!$inf_file_in or !-e $inf_file_in) {
    CertNanny::Logging->error("_certReqReadTemplate(): Could not find certreq template file in the following path: $inf_file_in, please check your certreqinf setting for the keystore!");
    return undef;
  }
  open INF_FILE_IN, "<", $inf_file_in
    or CertNanny::Logging->error("_certReqReadTemplate(): Could not open input file: $inf_file_in");
  my $section;
  while (<INF_FILE_IN>) {
    chomp;
    my $line = $_;
    if ($line =~ m/\[([\w]+)\]/) {
      $section = $1;
      next;
    }

    # skip if not valid
    next if not defined $section;    # need to have an active section
    next if $line =~ m/^;.*/;        # line is a comment, skip it
    next if $line =~ m/^\s*$/;       # line is empty, skip it

    $line =~ m/^(\w+)=(.*)$/;
    $self->{OPTIONS}->{ENTRY}->{certreq}->{$section}->{$1} = $2;
  } ## end while (<INF_FILE_IN>)

  close INF_FILE_IN;
} ## end sub _certReqReadTemplate


sub _getStoreCerts() {
  my $self  = shift;
  my $store = shift;

  $self->_certUtilWriteCerts((STORE => $store));
  my $olddir = getcwd();
  chdir $self->{OPTIONS}->{ENTRY}->{statedir};
  my @certs = glob "Blob*.crt";
  my @certinfos;
  foreach my $cert (@certs) {
    my $certinfo = CertNanny::Util->getCertInfoHash(CERTFILE => $cert);
    push(@certinfos, $certinfo);
  }
  chdir $olddir;

  return @certinfos;
} ## end sub _getStoreCerts


sub _checkRequestSanity() {
  # check if both a csr AND a key exist AND check if they match
  # this functions cleans up all irregularities
  # this means, after this function was executed, either a valid csr + key exist
  # or both were removed. Thus the existence of a CSR indicated that everything is fine
  my $self = shift;

  # Steps:
  CertNanny::Logging->debug("Checking request sanity.");

  # 1. read all keys from REQUEST store
  my @certs = $self->_getStoreCerts("REQUEST");

  # 2. read csr
  my $csrfile = File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir}, $self->{OPTIONS}->{ENTRYNAME} . ".csr");

  # 3. if csr does not exist
  unless (-e $csrfile) {
    CertNanny::Logging->debug("No CSR was found under $csrfile for keystore " . $self->{OPTIONS}->{ENTRYNAME} . ". Checking if there is a pending request in keystore that matched Certificate subject " . $self->{OPTIONS}->{ENTRY}->{SubjectName} . ".");

    # 3.1. if object with same subject name as current cert exists
    my @delete_certs;
    foreach my $cert (@certs) {
      if ((index $self->{CERT}->{CERTINFO}->{SubjectName}, $cert->{SubjectName}) != -1) {
        push(@delete_certs, $cert);
      }
    }

    if (@delete_certs) {

      # 3.1.1 delete the objects
      CertNanny::Logging->info("There is at least one old pending request in the keystore although no CSR was found for it. All pending requests that have the same subject as the current ceritficate will be deleted.");
      foreach my $cert (@delete_certs) {
        my $serial = $cert->{SerialNumber};
        $serial =~ s/://g;
        unless ($self->_certUtilWriteCertsDeleteCert((SERIAL => $serial, STORE => "REQUEST"))) {
          CertNanny::Logging->error("Could not delete certificate with serial $serial from store REQUEST");
          return undef;
        }
      }

    } ## end if (@delete_certs)
    return 1;

  } ## end unless (-e $csrfile)

  # 4. if csr exists
  if (-e $csrfile) {

    # 4.1 if no key in REQUEST
    unless (@certs) {
      CertNanny::Logging->info("There is no pending request in the keystore so the current csr will be deleted.");

      # 4.1.1 delete the csr
      unless (unlink $csrfile) {
        CertNanny::Logging->error("Could not delete csr $csrfile. Please remove manually.");
        return undef;
      }
      return 1;
    } ## end unless (@certs)

    # 4.2 if csr does not match REQUEST
    my $csr = CertNanny::Util->getCSRInfoHash((CERTFILE => $csrfile));
    my $request_key;
    my @delete_certs;
    foreach my $cert (@certs) {
      if (index($cert->{SubjectName}, $csr->{SubjectName}) != -1) {
        if ($cert->{Modulus} eq $csr->{Modulus}) {
          $request_key = $cert;
        } else {
          push(@delete_certs, $cert);
        }
      }
    }

    unless ($request_key) {
      my $subject = $csr->{SubjectName};
      CertNanny::Logging->info("The existing csr does not match any currently pending request in the keystore so the csr and all pending requests with subject $subject will be deleted.");
    }
    unless (defined $request_key) {

      # 4.2.1 delete the csr
      unless (unlink $csrfile) {
        CertNanny::Logging->error("Could not delete csr $csrfile. Please remove manually.");
        return undef;
      }
    }

    # 4.2.2 delete the object
    foreach my $cert (@delete_certs) {
      my $serial = $cert->{SerialNumber};
      $serial =~ s/://g;
      CertNanny::Logging->debug("Deleting certificate with serial $serial");
      unless ($self->_certUtilWriteCertsDeleteCert((SERIAL => $serial, STORE => "REQUEST"))) {
        CertNanny::Logging->error("Could not delete certificate with serial $serial from store REQUEST");
        return undef;
      }
    }
  } ## end if (-e $csrfile)

  return 1;
} ## end sub _checkRequestSanity


sub _installCertchain() {
  # convert cert to pkcs#12
  # execute import_cert.exe import test100-cert.pfx
  my $self = shift;
  my %args = (@_,    # argument pair list
             );
  my $ret = 1;

  CertNanny::Logging->debug("write certificate chain: \n");

  # list of chain certificates
  my @certchain = @{$self->{STATE}->{DATA}->{CERTCHAIN}};

  foreach my $chaincert (@certchain) {

    CertNanny::Logging->debug("certificate subject:" . $chaincert->{CERTINFO}->{SubjectName});

    if ($chaincert->{CERTINFO}->{SubjectName} eq $chaincert->{CERTINFO}->{IssuerName}) {

      my $rootToInstall = CertNanny::Util->getTmpFile();
      CertNanny::Logging->debug("Root Cert to install: $rootToInstall");

      if (!CertNanny::Util->writeFile(DSTFILE    => $rootToInstall,
                                      SRCCONTENT => $chaincert->{CERTINFO}->{Certificate},
                                      FORCE      => 1,)
        ) {
        CertNanny::Logging->error("Could not write root cert to install to temp file");
        return undef;
      }

      my @cmd = ('certutil', '-addstore', 'root', qq("$rootToInstall"));
      my $cmd = join(" ", @cmd);

      CertNanny::Logging->debug("Execute: $cmd");
      my $cmd_output = `$cmd`;
      CertNanny::Logging->debug("certreq output:\n$cmd_output");
      if ($? != 0) {
        CertNanny::Logging->error("_installCertchain(): Root Certificate could not be imported. Output of command $cmd was:\n$cmd_output");
        return undef;
      }

      unless (unlink $rootToInstall) {
        CertNanny::Logging->error("_installCertchain(): Could not delete root tmp file. Since the certificate was already installed no worries.");
      }
    } else {

      my $CAToInstall = CertNanny::Util->getTmpFile();
      CertNanny::Logging->debug("Root Cert to install: $CAToInstall");

      if (!CertNanny::Util->writeFile(DSTFILE    => $CAToInstall,
                                      SRCCONTENT => $chaincert->{CERTINFO}->{Certificate},
                                      FORCE      => 1,)
        ) {
        CertNanny::Logging->error("Could not write CA cert to install to temp file");
        return undef;
      }

      my @cmd = ('certutil', '-addstore', 'CA', qq("$CAToInstall"));
      my $cmd = join(" ", @cmd);

      CertNanny::Logging->debug("Execute: $cmd");
      my $cmd_output = `$cmd`;
      CertNanny::Logging->debug("certreq output:\n$cmd_output");
      if ($? != 0) {
        CertNanny::Logging->error("_installCertchain(): Root Certificate could not be imported. Output of command $cmd was:\n$cmd_output");
        return undef;
      }

      unless (unlink $CAToInstall) {
        CertNanny::Logging->error("_installCertchain(): Could not delete CA tmp file. Since the certificate was already installed no worries.");
      }
    } ## end else [ if ($chaincert->{CERTINFO...})]
  } ## end foreach my $chaincert (@certchain)

  return $ret;
} ## end sub _installCertchain


sub _deleteOldCerts() {
  # TODO sub _deleteOldCerts delete the old certificate (or archive it?)
  my $self         = shift;
  my $certfile     = shift;
  my $ret          = 1;
  my $newcert_info = CertNanny::Util->getCertInfoHash((CERTFILE   => $certfile, 
                                                   CERTFORMAT => 'PEM'));
  CertNanny::Logging->info("Deleting old certificate from keystore");
  my @store_certs = $self->_getStoreCerts();
  foreach my $storecert (@store_certs) {
    my $newcert_subject   = $newcert_info->{SubjectName};
    my $newcert_serial    = $newcert_info->{SerialNumber};
    my $storecert_subject = $storecert->{SubjectName};
    my $storecert_serial  = $storecert->{SerialNumber};
    if ($storecert_subject eq $newcert_subject && $storecert_serial ne $newcert_serial) {
      my $delserial = $storecert_serial;
      $delserial =~ s/://g;
      CertNanny::Logging->debug("Deleting certificate with serial $delserial");
      unless ($self->_certUtilWriteCertsDeleteCert((SERIAL => $delserial))) {
        CertNanny::Logging->error("Could not delete the old certificate. The next update will fail if this is not fixed!");
        $ret = undef;
      }
    }
  } ## end foreach my $storecert (@store_certs)

  return $ret;
} ## end sub _deleteOldCerts

sub _hasEngine {
  my $self = shift;
  
  return 1;
}

1;
