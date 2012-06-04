#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005, 2006 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::Java;

use base qw(Exporter CertNanny::Keystore);

use strict;
use vars qw($VERSION);
use Exporter;
use Carp;
use Data::Dumper;

$VERSION = 0.10;

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

    my $entry = $self->{OPTIONS}->{ENTRY};
    my $entryname = $self->{OPTIONS}->{ENTRYNAME};
    my $options = $self->{OPTIONS};

#print Dumper($self);
    
    $options->{keytool} =
        $args{CONFIG}->get('cmd.keytool', 'FILE');
    croak "cmd.keytool not found" unless (defined $options->{keytool} and
                                      -x $options->{keytool});
    $options->{java} = $args{CONFIG}->get('cmd.java', 'FILE');
    $options->{java} ||= 
    	File::Spec->catfile($ENV{JAVA_HOME}, 'bin', 'java')
		if (defined $ENV{JAVA_HOME});
    croak "cmd.java not found in config and JAVA_HOME not set" 
    	unless (defined $options->{java} && -x $options->{java});

    if (!defined $entry->{location}) {
    	croak("keystore.$entryname.location not defined");
	return;
    }
    if (!-r $entry->{location}) {
    	croak("keystore file $entry->{location} not readable");
	return;
    }
    if (!defined $entry->{pin}) {
    	croak("keystore.$entryname.pin not defined");
	return;
    }
    if (!defined $entry->{keypin}) {
    	$entry->{keypin} = $entry->{pin};
	$self->info("keystore.$entryname.keypin not defined, defaulting to keystore.$entryname.pin");
	# TODO check that keypin works if we are doing "renew"
    }
    if (!defined $entry->{alias}) {
    	my @cmd = $self->keytoolcmd($entry->{location},'-list');
	$self->log({MSG => "Execute: " . join(' ',hidepin(@cmd)), PRIO => 'debug'});
    	my @keys = `@cmd`;
    	@keys = grep m{, keyEntry,$},@keys;
	if ($?) {
	    croak("keystore $entry->{location} cannot be listed");
	    return;
	}
	if (@keys == 0) {
	    croak("keystore $entry->{location} does not contain a key");
	    return;
	}
	if (@keys > 1) {
	    croak("keystore $entry->{location} contains muliple keys, cannot determine alias. Please configure keystore.$entryname.alias.");
	    return;
	}
	($entry->{alias}) = $keys[0] =~ m{^([^,]*)};
	$self->info("Using $entry->{alias} as default for keystore.$entryname.alias.");
	if (!defined $entry->{keyalg}) {
	    $entry->{keyalg} = 'RSA';
	    $self->info("Using $entry->{keyalg} as default for keystore.$entryname.keyalg");
	}
	if (!defined $entry->{sigalg} && uc($entry->{keyalg}) eq 'RSA') {
	    $entry->{sigalg} = 'SHA1withRSA';
	    $self->info("Using $entry->{sigalg} as default for keystore.$entryname.sigalg");
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


# build a keytool command (as an array) containing all common options, the 
# location (if provided as an argument) and further arguments (if provided)
# the common options are: -storepass -provider -storetype
sub keytoolcmd {
    my $self = shift;
    my $location = shift;

    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};

    my @cmd = ($options->{keytool}, -storepass => qq{'$entry->{pin}'});
    push(@cmd, -provider => qq{'$entry->{provider}'}) if ($entry->{provider});
    push(@cmd, -storetype => qq{'$entry->{format}'}) if ($entry->{format});
    push(@cmd, -keystore => qq{'$location'}) if ($location);
    push(@cmd, @_);
    @cmd;
}

# arg: array
# return: array with pins replaced
sub hidepin {
    my @args = @_;
    for (my $ii = 0; $ii < $#args; $ii++) {
	$args[$ii + 1] = "*HIDDEN*" if ($args[$ii] =~ /(-pw|-target_pw|-storepass|-keypass)/);
    }
    @args;
}

#
# This method should extract the certificate from the instance keystore
# and return a hash ref:
# CERTFILE => file containing the cert **OR**
# CERTDATA => string containg the cert data
# CERTFORMAT => 'PEM' or 'DER'
# or undef on error
sub getcert {
    my $self = shift;
    
    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};

    my @cmd = $self->keytoolcmd($entry->{location},
    	'-export', '-rfc', -alias => qq{'$entry->{alias}'});
    $self->log({MSG => "Execute: " . join(' ',hidepin(@cmd)), PRIO => 'debug'});
    my $certdata = `@cmd`;
    if ($?) {
    	chomp($certdata);
	$self->seterror("getcert(): keytool -export failed ($certdata)");
	return;
    }

    return {
 	CERTDATA   => $certdata,     # if the cert is available in a scalar
 	CERTFORMAT => 'PEM',         # or 'DER'...
     }
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
    my $keystore = shift; # defaults to $entry->{location}, see below

    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};
    my $config = $options->{CONFIG};

    $keystore ||= $entry->{location};

    my $pathjavalib = $config->get("path.libjava", "FILE");
    my $extractkey_jar = File::Spec->catfile($pathjavalib,'ExtractKey.jar');
    if (! -r $extractkey_jar) {
	$self->seterror("getkey(): could not locate ExtractKey.jar file");
	return;
    }

    my $classpath = $extractkey_jar;
    if (defined($ENV{CLASSPATH})) {
    	my $sep = $^O eq 'MSWin32' ? ';' : ':';
    	$classpath = "$ENV{CLASSPATH}$sep$classpath";
    }

    $self->info("Extracting key $entry->{alias} from $keystore");
    my @cmd = $self->keytoolcmd($keystore,
    	-keypass => qq{'$entry->{keypin}'},
	-key => qq{'$entry->{alias}'});
    shift @cmd; # remove keytool
    unshift @cmd, qq{'$options->{java}'}, -cp => qq{'$classpath'}, 
    	'de.cynops.java.crypto.keystore.ExtractKey';

    $self->log({MSG => "Execute: " . join(' ',hidepin(@cmd)), PRIO => 'debug'});
    my $data = `@cmd`;
    if ($?) {
    	chomp($data);
	$self->seterror("getkey(): keytool -export failed ($data)");
	return;
    }

    return {
	KEYDATA => $data,
	KEYTYPE => 'PKCS8',
	KEYFORMAT => 'DER',
	KEYPASS => ''
    };
}

sub tmpkeystorename {
    my $self = shift;

    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};
    File::Spec->catfile($entry->{statedir},
    	"$self->{OPTIONS}->{ENTRYNAME}-tmpkeystore");
}

sub createrequest {
    my $self = shift;

    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};
    my $entryname = $options->{ENTRYNAME};
    my $config = $options->{CONFIG};

    # step 1: generate private key or new keystore
    my $DN  = $self->{CERT}->{INFO}->{SubjectName};

    # SubjectAltName: format is 'DNS:foo.example.com DNS:bar.example.com'
    #my $SAN = $self->{CERT}->{INFO}->{SubjectAlternativeName}; # may be undef

    my $tmpkeystore = $self->tmpkeystorename();
	;
    
    # clean up
    unlink $tmpkeystore;
    $self->info("Creating keystore $tmpkeystore");
    $self->info("Generating new key with alias $entry->{alias} for $DN");
    my @cmd = $self->keytoolcmd($tmpkeystore, '-genkey',
    	-keypass => qq{'$entry->{keypin}'},
	-alias => qq{'$entry->{alias}'},
	-dname => qq{'$DN'},
	);
    push(@cmd, -keyalg => $entry->{keyalg}) if ($entry->{keyalg});
    push(@cmd, -sigalg => $entry->{sigalg}) if ($entry->{sigalg});
    push(@cmd, -keysize => $entry->{keysize}) if ($entry->{keysize});
    $self->log({MSG => "Execute: " . join(' ',hidepin(@cmd)), PRIO => 'debug'});
    my $data = `@cmd`;
    if ($?) {
    	chomp($data);
	$self->seterror("createrequest(): keytool -genkey failed ($data)");
	return;
    }
    my $key = $self->getkey($tmpkeystore) or return;
    $key->{OUTTYPE} = 'OpenSSL';
    $key->{OUTFORMAT} = 'PEM';
    #$key->{OUTPASS} = $entry->{keypin}; # cannot PKCS#8 plain -> OpenSSL encrypted not supported by convertkey/openssl -> do it in 2 steps
    $key = $self->convertkey(%$key);
    if (!$key) {
    	$self->seterror("createrequest(): Could not convert key");
	return;
    }
    $key->{OUTTYPE} = 'OpenSSL';
    $key->{OUTFORMAT} = 'PEM';
    $key->{OUTPASS} = $entry->{keypin};
    $key = $self->convertkey(%$key);
    if (!$key) {
    	$self->seterror("createrequest(): Could not convert key");
	return;
    }
    my $keyfile = 
	File::Spec->catfile($entry->{statedir}, $entryname . "-key.pem");
    if (!$self->write_file(FILENAME => $keyfile, CONTENT => $key->{KEYDATA}, 
    		FORCE => 1)) {
	$self->seterror("createreqest(): Could not write key file");
	return;
    }
    chmod 0600, $keyfile;

    # step 2: generate certificate request for existing DN (and SubjectAltName)
    # generate a PKCS#10 PEM encoded request file
    my $requestfile = 
	File::Spec->catfile($entry->{statedir}, $entryname . "-csr.pem");
    $self->info("Creating certificate request $requestfile");
    @cmd = $self->keytoolcmd($tmpkeystore, '-certreq',
        -keypass => qq{'$entry->{keypin}'},
	-alias => qq{'$entry->{alias}'},
	-file => qq{'$requestfile'},
	);
    push(@cmd, -sigalg => $entry->{sigalg}) if ($entry->{sigalg});
    $self->log({MSG => "Execute: " . join(' ',hidepin(@cmd)), PRIO => 'debug'});
    $data = `@cmd`;
    if ($?) {
    	chomp($data);
	$self->seterror("createrequest(): keytool -certreq failed ($data)");
	return;
    }

    return { REQUESTFILE => $requestfile,
	     KEYFILE     => $keyfile,
	   };
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
    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};
    my $config = $options->{CONFIG};
    my $tmpkeystore = $self->tmpkeystorename();

    # all trusted root ca certificates...
    my @trustedcerts = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};
    
    # ... plus all certificates from the ca key chain minus its root cert
    push(@trustedcerts, 
         @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1..$#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);
    my @cmd;
    foreach my $caentry (@trustedcerts) {
        my @rdn = split(/(?<!\\),\s*/, $caentry->{CERTINFO}->{SubjectName});
        my $cn = $rdn[0];
        $cn =~ s/^CN=//;
    
    
        $self->info("Adding certificate '$caentry->{CERTINFO}->{SubjectName}' from file $caentry->{CERTFILE}");
    
        # rewrite certificate into pem format
        my $cacert = $self->convertcert(OUTFORMAT => 'PEM',
    				    CERTFILE => $caentry->{CERTFILE},
    				    CERTFORMAT => 'PEM',
    	);
        
        if (! defined $cacert)
        {
    	    $self->seterror("installcert(): Could not convert certificate $caentry->{CERTFILE}");
    	return;
        }
    
        my $cacertfile = $self->gettmpfile();
        if (! $self->write_file(FILENAME => $cacertfile,
    			    CONTENT  => $cacert->{CERTDATA})) {
    	    $self->seterror("installcert(): Could not write temporary ca file");
    	    return;
        }
    
    
        @cmd = $self->keytoolcmd($tmpkeystore,
		'-import','-noprompt',
		-file => qq('$cacertfile'),
		-alias => qq('$cn'));
    
        $self->log({MSG => "execute: " . join(" ", hidepin(@cmd)), PRIO => 'debug' });
        
        if (system(join(' ', @cmd)) != 0) {
    	    unlink $cacertfile;
    	    $self->seterror("could not add certificate to keystore");
    	    return;
        }
        unlink $cacertfile;
    }
    $self->info("Adding $self->{CERT}->{INFO}->{SubjectName}");
    @cmd = $self->keytoolcmd($tmpkeystore,
		'-import','-noprompt',
		-alias => qq{'$entry->{alias}'},
		-file => qq('$args{CERTFILE}'));
    $self->log({MSG => "execute: " . join(" ", hidepin(@cmd)), PRIO => 'debug' });
    if (system(join(' ', @cmd)) != 0) {
        $self->seterror("could not add certificate to keystore");
        return;
    }

    # now replace the old keystore with the new one
    if (! -r $tmpkeystore) {
	$self->seterror("Could not access new prototype keystore file $tmpkeystore");
	return;
    }

    $self->info("Installing Java keystore");
    my $data = $self->read_file($tmpkeystore);
    if (!defined($data)) {
    	 $self->seterror("Could read new keystore file $tmpkeystore");
	 return;
    }
	
    my @newkeystore = (
	     {
		 DESCRIPTION => "Java keystore",
		 FILENAME    => $entry->{location},
		 CONTENT     => $data,
	     });

    ######################################################################
    # try to write the new keystore 

    if (! $self->installfile(@newkeystore)) {
	$self->seterror("Could not install new keystore");
	return;
    }

    unlink $tmpkeystore;
    
    return 1;
}

1;
