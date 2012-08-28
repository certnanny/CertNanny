#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005, 2006 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::Windows;

use base qw(Exporter CertNanny::Keystore);
# You may wish to base your class on the OpenSSL keystore instead if
# you deal with PKCS#8 or PKCS#12 in your implementation or if you would
# like to use the key and request generation of the OpenSSL keystore.
#use base qw(Exporter CertNanny::OpenSSL);

use strict;
use vars qw($VERSION);
use Exporter;
use Carp;
use English;
use Data::Dumper;
use Win32::OLE;
use Win32::OLE::Variant;
use Win32::OLE::Const;

# CAPICOM constant definitions
my $const = Win32::OLE::Const->Load('CAPICOM');
$const->{XECR_PKCS10_V1_5} = 0x4;
$const->{CRYPT_EXPORTABLE} = 0x00000001;
$const->{AT_KEYEXCHANGE} = 1;
$const->{AT_SIGNATURE} = 2;

my %capicomlocation = (
	memory => $const->{CAPICOM_MEMORY_STORE},
	machine => $const->{CAPICOM_LOCAL_MACHINE_STORE},
	user => $const->{CAPICOM_CURRENT_USER_STORE},
	ad => $const->{CAPICOM_ACTIVE_DIRECTORY_USER_STORE},
	sc => $const->{CAPICOM_SMART_CARD_USER_STORE},
);

my %certlocation = (
        user => 1 << 16,
	machine => 2 << 16,
	service => 4 << 16,
	services => 5 << 16,
	users => 6 << 16,
);	

$VERSION = 0.10;


###########################################################################
# Some useful code snippets
#
# Log debug information:
# $self->debug("My debug level is " . $self->loglevel());
#
# Log informational message:
# $self->info("Some informational message");
#
# Get a temporary file name (automatically cleaned up after termination)
# my $tmpfile = $self->gettmpfile();
#
# Build file paths from directory components (DON'T simply concatenate
# them, path separators differ between platforms!):
# my $file = File::Spec->catfile('', 'var', 'tmp', 'foobar');
# (On Unix this results in /var/tmp/foobar)
#
# Read file contents to a scalar:
# my $content = $self->read_file($filename);
# if (! defined $content) {
#   $self->seterror("...");
#   return;
# }
#
# Write contents of a scalar variable to a file:
# if (! $self->write_file(
#   FILENAME => $filename,
#   CONTENT  => $myvariable,
#   FORCE    => 1,           # existing files will not be overwritten otherwise
# )) {
#   $self->seterror("...");
#   return;
# }
#
# Key conversion: (see CertNanny::Keystore::convertkey()), example:
# my $newkey = $self->convertkey(
#   KEYFILE => $keyfile,
#   KEYFORMAT => 'PEM',
#   KEYTYPE   => 'OpenSSL',
#   KEYPASS   => $pin,
#   OUTFORMAT => 'PKCS8',
#   OUTTYPE   => 'DER',
#   OUTPASS   => $pin,
# );
# if (! defined $newkey) ...
#
# Certificate conversion: (see CertNanny::Keystore::convertcert()), example:
# my $newcert = $self->convertcert(
#   CERTDATA => $data,
#   CERTFORMAT => 'DER',
#   OUTFORMAT => 'PEM',
# );
# if (! defined $newcert) ...
#
# Atomic file installation (see CertNanny::Keystore::installfile()), example:
# if (! $self->installfile(
#   { FILENAME => $destfile1, CONTENT => data1, DESCRIPTION => 'file1...' },
#   { FILENAME => $destfile2, CONTENT => data2, DESCRIPTION => 'file2...' },
# )) ...
#



# constructor
sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = ( 
        @_,         # argument pair list
    );

    my $self = {};
    bless $self, $class;

    $self->{OPTIONS} = \%args;


    # Througout this class you will be able to access entry configuration
    # settings via
    # $self->{OPTIONS}->{ENTRY}->{setting}
    # It is possible to introduce new entry settings this way you might
    # need for your keystore implementation. 
    # It is also possible to introduce additional hierarchy layers in
    # the configuration, e. g. if you have a
    #   keystore.foobar.my.nifty.setting = bla
    # you will be able to access this via
    # $self->{OPTIONS}->{ENTRY}->{my}->{nifty}->{setting}
    # Be sure to check all configuration settings for plausiblitiy.


    # You will have to obtain the keystore pin somehow, for some keystores
    # it will be configured in certnanny's config file, for others you
    # might want to deduce it from the keystore itself
    #my $pin = "";
#    $pin = $self->{OPTIONS}->{ENTRY}->{pin};
    if (! exists $self->{OPTIONS}->{ENTRY}->{pin}) {
	    $self->{OPTIONS}->{ENTRY}->{pin} = "";
    }

    # export the pin to this instance
    $self->{PIN} = $self->{OPTIONS}->{ENTRY}->{pin};
    
    # sample sanity checks for configuration settings
     foreach my $entry qw( location ) {
 	if (! defined $self->{OPTIONS}->{ENTRY}->{$entry} ) {
 	    croak("keystore.$entry $self->{OPTIONS}->{ENTRY}->{$entry} not defined.");
 	    return;
 	}
     }
    
    Win32::OLE->Option ('Warn' => 3);
    
    $self->{OPTIONS}->{ENTRY}->{storename} ||= 'MY';
    $self->{OPTIONS}->{ENTRY}->{storelocation} ||= 'machine';

    $self->{STORE}=$self->openstore( $self->{OPTIONS}->{ENTRY}->{storename},$self->{OPTIONS}->{ENTRY}->{storelocation});
    # the rest should remain untouched

    # get previous renewal status
    $self->retrieve_state() || return;

    # check if we can write to the file
    $self->store_state() || croak "Could not write state file $self->{STATE}->{FILE}";

    # instantiate keystore
    return $self;
}


# you may add additional destruction code here but be sure to retain
# the call to the parent destructor
sub DESTROY {
    my $self = shift;
    # check for an overridden destructor...
    if ($self->{STORE}) {
	eval { $self->{STORE}->Close() };
	if ($@) {
	    chomp($@);
	    $self->debug("Ignoring store close error: [$@]\n");
        }
    }
    $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}




# This method should extract the certificate from the instance keystore
# and return a hash ref:
# CERTFILE => file containing the cert **OR**
# CERTDATA => string containg the cert data
# CERTFORMAT => 'PEM' or 'DER'
# or undef on error
sub getcert {
    my $self = shift;
    
    # you might want to access keystore configuration here
         
    my $cert;

    eval { $cert = $self->getcertobject( $self->{STORE} ) };

    if ($@) {
	chomp($@);
	my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};
	my $storename = $self->{OPTIONS}->{ENTRY}->{storename};
	$self->seterror("store $storelocation/$storename: $@");
	return;
    }
   
    my $certdata = 
    	"-----BEGIN CERTIFICATE-----\n" . 
    	$cert->Export($const->{CAPICOM_ENCODE_BASE64}) . 
	"-----END CERTIFICATE-----\n";
    
    my $instancecert;

    # either set CERTFILE ***OR*** CERTDATA, not both!!!
     $instancecert = {
# 	CERTFILE   => $filename,     # if the cert is stored on disk
 	CERTDATA   => $certdata,     # if the cert is available in a scalar
 	CERTFORMAT => 'PEM',         # or 'DER'...
     };
	    
    return $instancecert;
}



# This method should return the keystore's private key.
# It is expected to return a hash ref containing the unencrypted 
# private key:
# hashref (as expected by convertkey()), containing:
# KEYDATA => string containg the private key OR
# KEYFILE => file containing the key data
# KEYFORMAT => 'PEM' or 'DER'
# KEYTYPE => format (e. g. 'PKCS8' or 'OpenSSL'
# KEYPASS => key pass phrase (only if protected by pass phrase)
# or undef on error
sub getkey {
    my $self = shift;

    my $keydata;
    eval { $keydata = $self->getkeydata($self->{STORE}) };
    if ($@)
    {
	chomp($@);
	my $storelocation = $self->{OPTIONS}->{ENTRY}->{location};
	my $storename = $self->{OPTIONS}->{ENTRY}->{storename};
	$self->seterror("store $storelocation/$storename: $@");
        return;
    }    

    my $key;

    #everything in front of the first five - in the private key will be deleted
    $keydata =~ s{.*(-----BEGIN)}{$1}xms;

    # either set KEYFILE ***OR*** KEYDATA, not both!!!
     $key = {
 	KEYDATA => $keydata,        # if the key is contained in a scalar OR
# 	KEYFILE => $keyfile,        # if the key is contained in a file
# 	KEYTYPE => 'OpenSSL',       # or 'PKCS8'
 	KEYFORMAT => 'PEM'          # or 'DER'
# 	KEYPASS => $pin,
     };

    return $key;
}



# This method should generate a new private key and certificate request.
sub createrequest {
    my $self = shift;
     
    # NOTE: you might want to use OpenSSL request generation, see suggestion
    # above.
  
    # step 1: generate private key or new keystore
      
    my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};
    my $enroll = Win32::OLE->new ('CEnroll.CEnroll') or die;
    if (!$enroll) {
	    $self->seterror("CEnroll.CEnroll is not installed");
	    return;
    }
    my $cert;
    eval { $cert = $self->getcertobject( $self->{STORE} ) };
    if ($@) {
	chomp($@);
	my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};
	my $storename = $self->{OPTIONS}->{ENTRY}->{storename};
	$self->seterror("store $storelocation/$storename: $@");
	return;
    }
    my $privkey = $cert->{PrivateKey};
    if (!$privkey) {
	    $self->seterror("cannot access PrivateKey");
	    return;
    }
    $enroll->{ProviderName} = $privkey->{ProviderName};
    $enroll->{ProviderType} = $privkey->{ProviderType};
    $enroll->{RequestStoreFlags} = $certlocation{lc($storelocation)};
    $enroll->{KeySpec} = $privkey->{KeySpec};
    my $keysize = $cert->{PublicKey}->{Length};
    $enroll->{GenKeyFlags} = $const->{CRYPT_EXPORTABLE} | ($keysize << 16);
    my $extensions = $cert->{Extensions};
    if ($extensions) {
	$extensions = Win32::OLE::Enum->new($extensions);
	my $sanoid = '2.5.29.17'; # subjectAltName
	while (defined (my $ext = $extensions->Next)) {
		next if ($ext->{OID}->{Value} ne $sanoid);
		$self->debug("adding subjectAltName extension");
		$enroll->addExtensionToRequest($ext->{IsCritical},$sanoid,
					       $ext->{EncodedData}->{Value});
		last;
	}
    }

    #print "STOREFLAGS: $enroll->{CAStoreFlags}\n";
    my $requestfile = $self->{OPTIONS}->{ENTRYNAME} . ".csr";
       
    #If the .csr file already exists, the file will be deleted to avoid 
    #messages on the screen
    if(-e "$self->{OPTIONS}->{ENTRY}->{statedir}/".$requestfile) # FIXME catfile bzw. $requestfile (s.u.) verwenden
    {
       unlink("$self->{OPTIONS}->{ENTRY}->{statedir}/".$requestfile); # FIXME catfile
    }
   
    $requestfile =  
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $requestfile);
    #########################################################################
    my $location = $self->{OPTIONS}->{ENTRY}->{location};
    #array
    my @tmpcn;
    #split the string after all , and write the new strings in an array
    @tmpcn=split(/(?<!\\),\s*/,$location);
    #change the order of the array
    @tmpcn = reverse(@tmpcn);
    #replace the , and write the string to $location
    $location = join(',',@tmpcn);
    #########################################################################
    #createFileRequest has no return value
    $enroll->createFileRequest($const->{XECR_PKCS10_V1_5},$location,"",
	    	$requestfile);
    # generate a PKCS#10 PEM encoded request file
    #keyfile aus request holen, dazu muss location nicht mehr von MY sondern von request geholt werden
    my $storename = "REQUEST";
    
    my $requeststore = $self->openstore($storename, $storelocation);
    
    my $keydata;
    eval { $keydata = $self->getkeydata($requeststore) };
    if ($@)
    {
	chomp($@);
	$self->seterror("store $storelocation/$storename: $@");
        return;
    }    
  
    eval { $requeststore->Close() };
    if ($@) {
	chomp($@);
	$self->debug("Ignoring store close error: [$@]");
    }
    
    my $keyfile = $self->{OPTIONS}->{ENTRYNAME} . ".key";
    $keyfile =  
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $keyfile);
    #create a keyfile out of the  
    if (! $self->write_file(
	FILENAME => $keyfile,
	CONTENT  => $keydata,
	FORCE    => 1,
	)) {
	$self->seterror("Could not create file $keyfile");
	return;
    }

    return({ REQUESTFILE => $requestfile,
	     KEYFILE     => $keyfile,
	   });
}

# This method is called once the new certificate has been received from
# the SCEP server. Its responsibility is to create a new keystore containing
# the new key, certificate, CA certificate keychain and collection of Root
# certificates configured for CertNanny.
# A true return code indicates that the keystore was installed properly.
sub installcert {
    my $self = shift;


    
    my %args = ( 
		 @_,         # argument pair list
		 );

    # please see examples in other keystores on ideas how to do this
    my $enroll = Win32::OLE->new ('CEnroll.CEnroll') or die;
    my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};

    #Install cert chain without root certificates
    $self->installcertchain(); #install certificate chain 

    my $cert;
    eval { $cert = $self->getcertobject( $self->{STORE} ) };
    if ($@) {
	chomp($@);
	my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};
	my $storename = $self->{OPTIONS}->{ENTRY}->{storename};
	$self->seterror("store $storelocation/$storename: $@");
	return;
    }
    my $privkey = $cert->{PrivateKey};
    if (!$privkey) {
	    $self->seterror("cannot access PrivateKey");
	    return;
    }
    $enroll->{RequestStoreFlags}=$certlocation{lc($storelocation)};
    $enroll->{ProviderName} = $privkey->{ProviderName};
    $enroll->{ProviderType} = $privkey->{ProviderType};
    $enroll->{KeySpec} = $privkey->{KeySpec};
    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
       
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return;
    }

    my $p7bfilename =  $self->{OPTIONS}->{ENTRYNAME} . "-cert.p7b"; 
     $p7bfilename =  
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $p7bfilename);
    my $pemfilename = $self->{OPTIONS}->{ENTRYNAME} . "-cert.pem";
     $pemfilename =  
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $pemfilename);
    if(system("\"$openssl\" crl2pkcs7 -nocrl -out \"$p7bfilename\" -certfile \"$pemfilename\" ") != 0){
   
    $self->seterror("\"$p7bfilename\" could not be created ($!)");
	return;
       }    
    local $/=undef;
    
    if($?!=0)
    {
      $self->seterror("pem could not be converted.");
	return;
    } 
      
    #install certificate in cert mgr
    eval { $enroll->acceptFilePKCS7($p7bfilename) };

    if ($@) {
	chomp($@);
	$self->seterror("Could not install new keystore ($@)");
	return;
    }
    
    # only on success:
     
    if(-e $p7bfilename)
    {
       unlink($p7bfilename);
    }

    my $count = $self->deleteoldcerts();

    if($count == 0)
    {
       $self->importrequest();
    }
       
    return 1;
}

sub deleteoldcerts {
    my $self = shift;
    my $store =$self->{STORE};
    my $certs = $store->Certificates;
       
    my $thumbprint = $self->{CERT}->{INFO}->{CertificateFingerprint};
    $thumbprint =~ s/://g;
    my $certstoremove;
    eval {

         $certstoremove = 
	 	$certs->Find($const->{CAPICOM_CERTIFICATE_FIND_SHA1_HASH},
			$thumbprint);
    };
    if ($@) {
	chomp($@);
	my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};
	my $storename = $self->{OPTIONS}->{ENTRY}->{storename};
	$self->seterror("deleteoldcerts: can't find certificate/request with has $thumbprint in $storelocation/$storename: $@");
	return 0;
    }	
    my $count = $certstoremove->Count;
    
    for(my $i=1;$i<=$count; $i++)
    {
       $store->Remove($certstoremove->Item($i));
    }
    return 1;
   
}

#This method searches through the certificate store to find the matching certificate.
#First the number of certificates in this store is saved in $certcount. The SubjectName of every
#certificate in the store to the location in the config file. If 0 or more than 1 certificate
#was found the method stops with an error.
#If only one certificate was found, this one will be returned.
sub getcertobject {
    my $self = shift;
    my $store = shift;
   
    my $location = $self->{OPTIONS}->{ENTRY}->{location};
    $location =~ s/(?<!\\)((\\\\)*),\s*/$1,/g;
  
    #my $issuerregex = $self->{OPTIONS}->{ENTRY}->{issuerregex};
    
    my $certs = $store->Certificates;
    my $count = 0;
    my $cert;
    my $matchedcert;

    #go through all certificates in the store
    my $enum = Win32::OLE::Enum->new($certs);
    while (defined( $cert = $enum->Next)) {
       my $subjectname=$cert->SubjectName;
       #my $issuername=$cert->IssuerName;
       
       #Because the subject names in the certificates from the certificate store are formated in a different way
       #the subject names from the config file. The blanks after the seperating "," need to be deleted. 
       $subjectname =~ s/(?<!\\)((\\\\)*),\s*/$1,/g;
       #$issuername =~ s/(?<!\\)((\\\\)*),\s*/$1,/g;
      
       #if ($subjectname eq $location && (!$issuername || $issuername =~ m/^$issuerregex$/)) { 
       if($subjectname eq $location) {
         $count++;
	 $matchedcert = $cert;
       }
    }
    $enum->Reset;

    die "certificate/request not found ($location)\n"
	if ($count == 0);

    die "found multiple certificates/requests ($location)\n"
	if ($count > 1);
    
    return $matchedcert;
}	

#Opens a certificate store with maximum allowed rights.
sub openstore {

    my $self = shift;
    my $store_name = shift;
    my $store_location_string = shift;
    	
    #my $store_name = $self->{OPTIONS}->{ENTRY}->{storename} || 'MY';
    my $store_location = $capicomlocation{lc($store_location_string)};
   
    my $store_mode = $const->{CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED};
  
    #ist Capicom installiert?
    my $store = Win32::OLE->new ('CAPICOM.Store');
   
    #Open() has no return value
    $store->Open ($store_location, $store_name, $store_mode);
    
    return $store;    
}

#
sub getkeydata {

    my $self = shift;
    my $store = shift;

    my $cert=$self->getcertobject($store) or return;
    
    #create .p12 file
    my $filename = $self->{OPTIONS}->{ENTRYNAME} . ".p12";
    $filename =  
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $filename);

    Win32::OLE->Option ('Warn' => 3); # FIXME global setting changed locally
    
    #save the certificate in the .p12 file as pfx
    eval { 
       $cert->Save($filename,"",$const->{CAPICOM_CERTIFICATE_SAVE_AS_PFX});
    };
    if ($@) {
	unlink $filename;
	chomp($@);
	die "PKCS#12 export: $@\n";
    }
   
    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
   
    #create pkcs12 file via OpenSSL
    if (!open(OPENSSL,  "\"$openssl\" pkcs12 -in \"$filename\" -nocerts -passin pass: -nodes |")) {
   
	die("\"filename\" could not be opened ($!)\n");
    }    
    
    #the OpenSSL output is saved in $keyfile
    local $/;
    my $keydata = <OPENSSL>;
    
    close(OPENSSL);

    #delete the created .p12 file
    #if(-e $filename)
    #{
    #   unlink($filename);
    #}

    die("pkcs12 could not be converted.\n")
	if ($? != 0);

    return $keydata;
}

sub importrequest {
    my $self = shift;

    my $storename = "REQUEST";
    my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation}; 
    my $requeststore = $self->openstore($storename, $storelocation);
    
    my $filename = $self->{OPTIONS}->{ENTRYNAME} . ".pfx";
    $filename =	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $filename);
    
    $requeststore->Load($filename,"",$const->{CAPICOM_KEY_STORAGE_EXPORTABLE});
        
    eval { $requeststore->Close() };
    if ($@) {
	chomp($@);
	$self->debug("Ignoring store close error: [$@]\n");
    }
}

sub installcertchain{
my $self = shift;

my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};

# all trusted Root CA certificates... 
my $storename = 'Root';
my @trustedcerts = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};
my $rootstore = $self->openstore($storename, $storelocation);
my $extension = ".cer"; 
my $tmpfilename;
my $certs = $rootstore->Certificates;


# trusted root certificates will not be installed in the chain since there is manual action (OK confirmation) required by the windows root keystore
	$self->info("installing configured root certificates");
	foreach my $entry (@trustedcerts){
		my $tmpfilename = $self->gettmpfile($extension);
		my @rdn = split(/(?<!\\),\s*/, $entry ->{CERTINFO}->{SubjectName});
		my $cn = $rdn[0];
		$cn =~ s/^CN=//;
		my $subject= $entry ->{CERTINFO}->{SubjectName};
		
		$self->info("Adding certificate '$subject' from file $entry ->{CERTFILE}");
		# rewrite certificate into pem format
		my $cacert = $self->convertcert(OUTFORMAT => 'PEM',
					    CERTFILE => $entry ->{CERTFILE},
					    CERTFORMAT => 'PEM',
		);
		
		if (! defined $cacert)
		{
		    $self->seterror("installcert(): Could not convert certificate $entry ->{CERTFILE}");
		return;
		}
    
		
		if (! $self->write_file(FILENAME => $tmpfilename,
				    CONTENT  => $cacert->{CERTDATA})) {
		    $self->seterror("installcert(): Could not write temporary ca file");
		    return;
		}
		#$self->write_file(FILENAME =>$tmpfilename, CONTENT=>$entry );
		$rootstore->Load($tmpfilename);
	}
	
	eval { $rootstore->Close() };
	if ($@) {
		chomp($@);
		$self->debug("Ignoring store close error: [$@]\n");
	    }



$self->info("Check for configured root certificates...");
$rootstore = $self->openstore($storename, $storelocation);
$certs = $rootstore->Certificates;

foreach my $entry (@trustedcerts){
	my $thumbprint = $entry ->{CERTINFO}->{CertificateFingerprint};
	   $thumbprint =~ s/://g;
	my $subject = $entry ->{CERTINFO}->{SubjectName};
	   
	my $installedrootCAs = $certs->Find($const->{CAPICOM_CERTIFICATE_FIND_SHA1_HASH},$thumbprint);
	
	if($installedrootCAs->Count == 0)
	{
            my $rootCN = $entry ->{CERTINFO}->{SubjectName}; 
	    $self->seterror("installcertificatechain: Can't install valid certificate chain when missung '$subject' in keystore.");
	    return 0;
	}else
	{
	   $self->info("Found $subject in key store.");
	}
	
}



$self->info("installing certificate chain");
# all certificates from the CA key chain minus its root cert will be installed 
my $storename = 'CA';
my @cachain;
my $CAstore = $self->openstore($storename, $storelocation);

	push(@cachain,@{$self->{STATE}->{DATA}->{CERTCHAIN}}[1..$#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);
	
	foreach my $entry (@cachain){
		$tmpfilename= $self->gettmpfile(".cer");
			
		my @rdn = split(/(?<!\\),\s*/, $entry ->{CERTINFO}->{SubjectName});
		my $cn = $rdn[0];
		$cn =~ s/^CN=//;
	    
		print("debug line 741", $entry ->{CERTINFO}->{SubjectName} , "\n");
		$self->info("Adding certificate '$entry ->{CERTINFO}->{SubjectName}' from file $entry ->{CERTFILE}");
	    
		# rewrite certificate into pem format
		my $cacert = $self->convertcert(OUTFORMAT => 'PEM',
					    CERTFILE => $entry ->{CERTFILE},
					    CERTFORMAT => 'PEM',
		);
		
		if (! defined $cacert)
		{
		    $self->seterror("installcert(): Could not convert certificate $entry ->{CERTFILE}");
		return;
		}
    
		if (! $self->write_file(FILENAME => $tmpfilename,
				    CONTENT  => $cacert->{CERTDATA})) {
		    $self->seterror("installcert(): Could not write temporary ca file");
		    return;
		}
				
		$CAstore->Load($tmpfilename);
	}
	
	eval { $CAstore->Close() };
	if ($@) {
		chomp($@);
		$self->debug("Ignoring store close error: [$@]\n");
	    }
}

1;
