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

# useful modules
#use IO::File;
#use File::Spec;
#use File::Copy;
#use File::Basename;
use English;
use Data::Dumper;
use Win32::OLE;
use Win32::OLE::Variant;
use Win32::OLE::Const;
# CAPICOM constant definitions
use constant Win32::OLE::Const->Load('CAPICOM');
use constant {
	XECR_PKCS10_V1_5 => 0x4,
	CRYPT_EXPORTABLE => 0x00000001,
};
my %capicomlocation = (
	memory => CAPICOM_MEMORY_STORE,
	machine => CAPICOM_LOCAL_MACHINE_STORE,
	user => CAPICOM_CURRENT_USER_STORE,
	ad => CAPICOM_ACTIVE_DIRECTORY_USER_STORE,
	sc => CAPICOM_SMART_CARD_USER_STORE,
);

my %certlocation = (
        user => 1 << 16,
	machine => 2 << 16,
	service => 4 << 16,
	services => 5 << 16,
	users => 6 << 16,
);	

$VERSION = 0.7;


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
    $self->{STORE}->Close() if($self->{STORE});
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
         
    my $cert=$self->getcertobject( $self->{STORE}) or return;
   
    my $certdata = "-----BEGIN CERTIFICATE-----\n" . $cert->Export(CAPICOM_ENCODE_BASE64) . "-----END CERTIFICATE-----\n";
    
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

    my $keydata =$self->getkeydata($self->{STORE});
    if(!defined $keydata)
    {
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
# You may want to inherit this class from CertNanny::Keystore::OpenSSL if
# you wish to generate the private key and PKCS#10 request 'outside' of
# your keystore and import this information later.
# In this case use the following code:
# sub createrequest
# {
#   return $self->SUPER::createrequest() 
#     if $self->can("SUPER::createrequest");
# }
#
# If you are able to directly operate on your keystore to generate keys
# and requests, you might choose to do all this yourself here:
sub createrequest {
    my $self = shift;
     
    # NOTE: you might want to use OpenSSL request generation, see suggestion
    # above.
  
    # step 1: generate private key or new keystore
      
    my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation};
    my $enroll = Win32::OLE->new ('CEnroll.CEnroll') or die;
    $enroll->{GenKeyFlags}=CRYPT_EXPORTABLE;
    $enroll->{RequestStoreFlags}=$certlocation{lc($storelocation)};
    
    #print "STOREFLAGS: $enroll->{CAStoreFlags}\n";
    my $requestfile = $self->{OPTIONS}->{ENTRYNAME} . ".csr";
       
    #If the .csr file already exists, the file will be deleted to avoid 
    #messages on the screen
    if(-e "$self->{OPTIONS}->{ENTRY}->{statedir}/".$requestfile)
    {
       unlink("$self->{OPTIONS}->{ENTRY}->{statedir}/".$requestfile);
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
    $enroll->createFileRequest(XECR_PKCS10_V1_5,$location,"",$requestfile);

    # step 2: generate certificate request for existing DN (and SubjectAltName)
    # Distinguished Name:
    my $DN  = $self->{CERT}->{INFO}->{SubjectName};

    # SubjectAltName: format is 'DNS:foo.example.com DNS:bar.example.com'
    my $SAN = $self->{CERT}->{INFO}->{SubjectAlternativeName}; # may be undef

    # generate a PKCS#10 PEM encoded request file
    #keyfile aus request holen, dazu muss location nicht mehr von MY sondern von request geholt werden
    my $storename = "REQUEST";
    
    my $requeststore = $self->openstore($storename, $storelocation);
    
    my $keydata = $self->getkeydata($requeststore);
  
    $requeststore->Close();
    
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
    $enroll->{RequestStoreFlags}=$certlocation{lc($storelocation)};

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
    $enroll->acceptFilePKCS7($p7bfilename);
#     # in order to access the certificate chain as returned by SCEP, use
#     foreach my $entry (@{$self->{STATE}->{DATA}->{CERTCHAIN}}) {
# 	my $cacertfile = $entry->{CERTFILE};
# 	# ...
#     }

#     # in order to access the root certificates configured for CertNanny, use
#     foreach my $entry (@{$self->{STATE}->{DATA}->{ROOTCACERTS}}) {
# 	my $rootcert = $entry->{CERTFILE};
# 	...
#     }

    #if (1) {   # if any error happened
#	$self->seterror("Could not install new keystore");
#	return;
    #   }
    
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

sub deleteoldcerts{
    my $self = shift;
    my $store =$self->{STORE};
    my $certs = $store->Certificates;
       
    my $thumbprint = $self->{CERT}->{INFO}->{CertificateFingerprint};
    $thumbprint =~ s/://g;
    my $certstoremove;
    eval {

         $certstoremove = $certs->Find(CAPICOM_CERTIFICATE_FIND_SHA1_HASH,$thumbprint);
    };
    if ($@) {
       #Fehlerausgabe	
       print "Fehler: $@\n";
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
sub getcertobject{
  
    my $self = shift;
    my $store = shift;
   
    my $location = $self->{OPTIONS}->{ENTRY}->{location};
  
    #my $issuerregex = $self->{OPTIONS}->{ENTRY}->{issuerregex};
    
    my $certs=$store->Certificates;
    my $certcount = $certs->Count();
    my $i=1;
    my $count=0;
    my $cert;
    my $subjectname;
    #my $issuername;
    #go through all certificates in the store
    while ($i<=$certcount) {
       
       $subjectname=$certs->Item($i)->SubjectName;
       #$issuername=$certs->Item($i)->IssuerName;
       
       #Because the subject names in the certificates from the certificate store are formated in a different way
       #the subject names from the config file. The blanks after the seperating "," need to be deleted. 
       $subjectname =~ s/(?<!\\)((\\\\)*),\s*/$1,/g;
       #$issuername =~ s/(?<!\\)((\\\\)*),\s*/$1,/g;
      
       #if ($subjectname eq $location && (!$issuername || $issuername =~ m/^$issuerregex$/)) { 
       if($subjectname eq $location){
         $count++;
	 $cert=$certs->Item($i);
       }
       $i++;       
    }
        
    # use this to signal an error
    if ($count == 0) {
	$self->seterror("getcert(): certificate not found");
	return;
    }
    # use this to signal an error
    if ($count > 1) {
	$self->seterror("getcert(): more than one certificate found");
	return;
    } 
    
    return $cert;
}	

#Opens a certificate store with maximum allowed rights.
sub openstore{

    my $self = shift;
    my $store_name = shift;
    my $store_location_string = shift;
    	
    #my $store_name = $self->{OPTIONS}->{ENTRY}->{storename} || 'MY';
    my $store_location = $capicomlocation{lc($store_location_string)};
   
    my $store_mode = CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED;
  
    #ist Capicom installiert?
    my $store = Win32::OLE->new ('CAPICOM.Store');
   
    #Open() has no return value
    $store->Open ($store_location, $store_name, $store_mode);
     
    return $store;    
}

#
sub getkeydata{

    my $self = shift;
    my $store = shift;

    my $cert=$self->getcertobject($store) or return;
    
    #create .p12 file
    my $filename = $self->{OPTIONS}->{ENTRYNAME} . ".p12";
    $filename =  
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $filename);

    Win32::OLE->Option ('Warn' => 3);
    
    #save the certificate in the .p12 file as pfx
    eval { 
       $cert->Save($filename,"",CAPICOM_CERTIFICATE_SAVE_AS_PFX); #(Dateiname, pw, als was speichern)anpassen
    };
    if($EVAL_ERROR) {
	    $self->seterror();
	    return;
    }
   
    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    #if OpenSSL is not installed   
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return;
    }
   
    #create pkcs12 file via OpenSSL
    if(!open(OPENSSL,  "\"$openssl\" pkcs12 -in \"$filename\" -nocerts -passin pass: -nodes |")){
   
    $self->seterror("\"filename\" could not be opened ($!)");
	return;
    }    
    local $/=undef;
    
    #the OpenSSL output is saved in $keyfile
    my $keydata = <OPENSSL>;
    
    close(OPENSSL);

    #delete the created .p12 file
    #if(-e $filename)
    #{
    #   unlink($filename);
    #}

    if($?!=0)
    {
      $self->seterror("pkcs12 could not be converted.");
	return;
    }
    return $keydata;
}

sub importrequest{
    my $self = shift;

    my $storename = "REQUEST";
    my $storelocation = $self->{OPTIONS}->{ENTRY}->{storelocation}; 
    my $requeststore = $self->openstore($storename, $storelocation);
    
    my $filename = $self->{OPTIONS}->{ENTRYNAME} . ".pfx";
    $filename =  
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $filename);
    
    $requeststore->Load($filename,"",CAPICOM_KEY_STORAGE_EXPORTABLE);
        
    $requeststore->Close();
}

1;
