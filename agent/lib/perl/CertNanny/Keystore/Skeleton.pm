#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005, 2006 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::Skeleton;

use base qw(Exporter CertNanny::Keystore);
# You may wish to base your class on the OpenSSL keystore instead if
# you deal with PKCS#8 or PKCS#12 in your implementation or if you would
# like to use the key and request generation of the OpenSSL keystore.
#use base qw(Exporter CertNanny::Keystore::OpenSSL);

use strict;
use vars qw($VERSION);
use Exporter;
use Carp;

# useful modules
#use IO::File;
#use File::Spec;
#use File::Copy;
#use File::Basename;


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
    my $pin = "";
#    $pin = $self->{OPTIONS}->{ENTRY}->{pin};

    # export the pin to this instance
    $self->{PIN} = $self->{OPTIONS}->{ENTRY}->{pin};

    
    # sample sanity checks for configuration settings
#     foreach my $entry qw( keyfile location ) {
# 	if (! defined $self->{OPTIONS}->{ENTRY}->{$entry} ||
# 	    (! -r $self->{OPTIONS}->{ENTRY}->{$entry})) {
# 	    croak("keystore.$entry $self->{OPTIONS}->{ENTRY}->{$entry} not defined, does not exist or unreadable");
# 	    return;
# 	}
#     }
    


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
    #my $location = $self->{OPTIONS}->{ENTRY}->{location};
    #my $foo = $self->{OPTIONS}->{ENTRY}->{someothersetting};

    # use this to signal an error
    if (0) {
	$self->seterror("getcert(): some unspecified error happened");
	return;
    }

    my $instancecert;

    # either set CERTFILE ***OR*** CERTDATA, not both!!!
#     $instancecert = {
# 	CERTFILE   => $filename,     # if the cert is stored on disk
# 	CERTDATA   => $certdata,     # if the cert is available in a scalar
# 	CERTFORMAT => 'PEM',         # or 'DER'...
#     }
	    
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

    # you might want to access keystore configuration here
    #my $location = $self->{OPTIONS}->{ENTRY}->{location};
    #my $foo = $self->{OPTIONS}->{ENTRY}->{someothersetting};

    # somehow deduce the PIN...
    # my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin};
    
    my $key;
    # either set KEYFILE ***OR*** KEYDATA, not both!!!
#     $key = {
# 	KEYDATA => $keydata,        # if the key is contained in a scalar OR
# 	KEYFILE => $keyfile,        # if the key is contained in a file
# 	KEYTYPE => 'OpenSSL',       # or 'PKCS8'
# 	KEYFORMAT => 'DER'          # or 'PEM'
# 	KEYPASS => $pin,
#     }

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
    my $keyfile;  # ...

    # step 2: generate certificate request for existing DN (and SubjectAltName)
    # Distinguished Name:
    my $DN  = $self->{CERT}->{INFO}->{SubjectName};

    # SubjectAltName: format is 'DNS:foo.example.com DNS:bar.example.com'
    my $SAN = $self->{CERT}->{INFO}->{SubjectAlternativeName}; # may be undef

    # generate a PKCS#10 PEM encoded request file
    my $requestfile;  # ...

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

    if (1) {   # if any error happened
	$self->seterror("Could not install new keystore");
	return;
    }
    
    # only on success:
    return 1;
}

1;
