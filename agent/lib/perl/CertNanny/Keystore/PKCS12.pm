#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005 - 2007 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::PKCS12;

use base qw( Exporter CertNanny::Keystore::OpenSSL );

use strict;
use vars qw($VERSION);
use Exporter;
use Carp;
use English;


$VERSION = 0.10;

###########################################################################

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


    my $pin = $self->{OPTIONS}->{ENTRY}->{pin};

    # export the pin to this instance
    $self->{PIN} = $self->{OPTIONS}->{ENTRY}->{pin};

    # sample sanity checks for configuration settings
    foreach my $entry (qw( location )) {
 	if (! defined $self->{OPTIONS}->{ENTRY}->{$entry} ||
 	    (! -r $self->{OPTIONS}->{ENTRY}->{$entry})) {
 	    croak("keystore.$entry $self->{OPTIONS}->{ENTRY}->{$entry} not defined, does not exist or unreadable");
 	    return;
 	}
    }


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

# returns filename with all PKCS#12 data
sub get_pkcs12_file {
    my $self = shift;
    return $self->{OPTIONS}->{ENTRY}->{location};
}

sub get_pin {
    my $self;
    return $self->{PIN};
}


# extract certificate
sub getcert {
    my $self = shift;

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	CertNanny::Logging->error("No openssl shell specified");
	return;
    }
    
    my $filename = $self->get_pkcs12_file();
    my $pin = $self->get_pin();

    my @passin = ();
    if (defined $pin) {
	@passin = ('-password',
		   'env:PIN');
	$ENV{PIN} = $pin;
    }

    my @cmd;

    @cmd = (qq("$openssl"),
	    'pkcs12',
	    '-in',
	    qq("$filename"),
	    '-nokeys',
	    '-clcerts',
	    @passin,
	);

    my $cmd = join(' ', @cmd);
    my $handle;
    if (! open $handle, "$cmd |") {
	CertNanny::Logging->error("could not run OpenSSL shell");
	delete $ENV{PIN};
	return;
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

    return (
	{
	    LABEL      => $label,
	    CERTDATA   => $certdata,
	    CERTFORMAT => 'PEM',
	});
}



# This returns the keystore's private key.
# KEYFILE => file containing the key data
# KEYFORMAT => 'PEM'
# KEYTYPE => 'OpenSSL'
# KEYPASS => key pass phrase (only if protected by pass phrase)
# or undef on error
sub getkey {
    my $self = shift;

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	CertNanny::Logging->error("No openssl shell specified");
	return;
    }
    
    my $filename = $self->get_pkcs12_file();
    my $pin = $self->get_pin();

    my @passin = ();
    if (defined $pin) {
	@passin = (
	    '-password',
	    'env:PIN',
	    '-passout',
	    'env:PIN',
	    );
	$ENV{PIN} = $pin;
    }

    my @cmd;

    @cmd = (qq("$openssl"),
	    'pkcs12',
	    '-in',
	    qq("$filename"),
	    '-nocerts',
	    @passin,
	);

    my $cmd = join(' ', @cmd);
    my $handle;
    if (! open $handle, "$cmd |") {
	CertNanny::Logging->error("could not run OpenSSL shell");
	delete $ENV{PIN};
	return;
    }
    
    local $INPUT_RECORD_SEPARATOR;
    my $keydata = <$handle>;
    close $handle;
    delete $ENV{PIN};

    $keydata =~ s{ \A .* (?=-----BEGIN) }{}xms;

    return (
	{
	    KEYDATA => $keydata,
	    KEYTYPE => 'OpenSSL',
	    KEYPASS => $pin,
	    KEYFORMAT => 'PEM',
	});
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
    return $self->SUPER::createrequest() 
	if $self->can("SUPER::createrequest");
    return;
}

sub get_new_pkcs12_data {
    my $self = shift;
    my %args = ( 
		 @_,         # argument pair list
		 );
    # create prototype PKCS#12 file
    my $keyfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
    my $certfile = $args{CERTFILE}; 
    my $label = $self->{CERT}->{LABEL};
    
    CertNanny::Logging->info("Creating prototype PKCS#12 from certfile $certfile, keyfile $keyfile, label $label");

    # all trusted Root CA certificates...
    my @cachain = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};
    
    # ... plus all certificates from the CA key chain minus its root cert
    push(@cachain,
	 @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1..$#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);

    
    # pkcs12file must be an absolute filename (see below, gsk6cmd bug)
    my $pkcs12file = $self->createpkcs12(
	FILENAME => $self->gettmpfile(),
	FRIENDLYNAME => $label,
	EXPORTPIN => $self->get_pin(),
	CACHAIN => \@cachain);
    
    
    if (! defined $pkcs12file) {
	CertNanny::Logging->error("Could not create prototype PKCS#12 from received certificate");
	return;
    }
    CertNanny::Logging->info("Created prototype PKCS#12 file $pkcs12file");


    my $data = CertNanny::Util->read_file($pkcs12file);
    unlink $pkcs12file;
    if (! defined $data) {
	CertNanny::Logging->error("Could read new keystore file " . $pkcs12file);
	return;
    }
    
    return $data;
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

    my $data = $self->get_new_pkcs12_data(%args);
    return unless $data;

    my @newkeystore;
    # schedule for installation
    push(@newkeystore,
	 {
	     DESCRIPTION => "PKCS#12 file",
	     FILENAME    => $self->{OPTIONS}->{ENTRY}->{location},
	     CONTENT     => $data,
	 });
    

    if (! $self->installfile(@newkeystore)) {   # if any error happened
	CertNanny::Logging->error("Could not install new keystore");
	return;
    }
    
    # only on success:
    return 1;
}

1;
