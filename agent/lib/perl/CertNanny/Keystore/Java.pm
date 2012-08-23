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
use CertNanny::Util;
use Cwd;

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
	CertNanny::Logging->info("keystore.$entryname.keypin not defined, defaulting to keystore.$entryname.pin");
	# TODO check that keypin works if we are doing "renew"
    }
    if (!defined $entry->{alias}) {
    	my @cmd = $self->keytoolcmd($entry->{location},'-list');
	CertNanny::Logging->debug("Execute: " . join(' ',hidepin(@cmd)));
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
    	CertNanny::Logging->info("Using $entry->{alias} as default for keystore.$entryname.alias.");
    }
    
	if (!defined $entry->{keyalg}) {
	    $entry->{keyalg} = 'RSA';
	    CertNanny::Logging->info("Using $entry->{keyalg} as default for keystore.$entryname.keyalg");
	}
	if (!defined $entry->{sigalg} && uc($entry->{keyalg}) eq 'RSA') {
	    $entry->{sigalg} = 'SHA1withRSA';
	    CertNanny::Logging->info("Using $entry->{sigalg} as default for keystore.$entryname.sigalg");
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

    my @cmd = (qq("$options->{keytool}"), -storepass => qq{$entry->{pin}});
    push(@cmd, -provider => qq{"$entry->{provider}"}) if ($entry->{provider});
    push(@cmd, -storetype => qq{"$entry->{format}"}) if ($entry->{format});
    push(@cmd, -keystore => qq{"$location"}) if ($location);
    push(@cmd, -keypass => qq($entry->{keypin})) if ($entry->{keypin});
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
    	'-export', '-rfc', -alias => qq{"$entry->{alias}"});
    CertNanny::Logging->debug("Execute: " . join(' ',hidepin(@cmd)));
    my $certdata = `@cmd`;
    if ($?) {
    	chomp($certdata);
    	CertNanny::Logging->error("getcert(): keytool -export failed ($certdata)");
	    return;
    }

    return {
 	CERTDATA   => $certdata,     # if the cert is available in a scalar
 	CERTFORMAT => 'PEM',         # or 'DER'...
     }
}



# This method should return the keystore's private key.
# It is expected to return a hash ref containing the unencrypted 
# Only called WITHOUT engine
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
    my $alias = shift; # defaults to $entry->{alias}, see below

    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};
    my $config = $options->{CONFIG};

    $keystore ||= $entry->{location};
    $alias ||= $entry->{alias};

    my $pathjavalib = $config->get("path.libjava", "FILE");
    my $extractkey_jar = File::Spec->catfile($pathjavalib,'ExtractKey.jar');
    if (! -r $extractkey_jar) {
	CertNanny::Logging->error("getkey(): could not locate ExtractKey.jar file");
	return;
    }

    my $classpath = $extractkey_jar;
    if (defined($ENV{CLASSPATH})) {
    	my $sep = $^O eq 'MSWin32' ? ';' : ':';
    	$classpath = "$ENV{CLASSPATH}$sep$classpath";
    }

    CertNanny::Logging->info("Extracting key $alias from $keystore");
    my @cmd = $self->keytoolcmd($keystore,
	-key => qq{"$alias"});
    shift @cmd; # remove keytool
    unshift @cmd, qq{"$options->{java}"}, -cp => qq{"$classpath"}, 
    	'de.cynops.java.crypto.keystore.ExtractKey';

    CertNanny::Logging->debug("Execute: " . join(' ',hidepin(@cmd)));
    my $data = `@cmd`;
    if ($?) {
    	chomp($data);
	CertNanny::Logging->error("getkey(): keytool -export failed ($data)");
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
    my $location = $entry->{location};
    # get a new key (it's either created or the alias is just returned) 
    my $newalias = $self->getnewkey();
    my @cmd;
    
    # okay, we have a new key, let's create a request for it
    my $requestfile = File::Spec->catfile($entry->{statedir}, $entryname . "-csr.pem");
    CertNanny::Logging->info("Creating certificate request $requestfile");
    @cmd = $self->keytoolcmd($location, '-certreq', -alias => qq{"$newalias"}, -file => qq{"$requestfile"});
    CertNanny::Logging->debug("Execute: " . join(' ', (@cmd)));
    if(run_command(join(' ', @cmd)) != 0) {
        CertNanny::Logging->error("createrequest(): keytool -certreq failed. See above output for details");
        return;
    }
    
    # decide whether we need to export the key (and do that if it's required)
    my $keyfile;
    unless($self->hasEngine()) {
        # okay no engine, export the key
        my $key = $self->getkey($location, $newalias) or return;
        $key->{OUTTYPE} = 'OpenSSL';
        $key->{OUTFORMAT} = 'PEM';
        $key = $self->convertkey(%$key);
        if(!$key) {
            CertNanny::Logging->error("createrequest(): Could not convert key.");
            return;
        }
        
        $key->{OUTTYPE} = 'OpenSSL';
        $key->{OUTFORMAT} = 'PEM';
        $key->{OUTPASS} = $entry->{keypin};
        $key = $self->convertkey(%$key);
        if(!$key) {
            CertNanny::Logging->error("createrequest(): Could not convert key");
            return;
        }
        $keyfile = File::Spec->catfile($entry->{statedir}, $entryname . "-key.pem");
        if(!CertNanny::Util->write_file(FILENAME => $keyfile, CONTENT => $key->{KEYDATA}, FORCE => 1)) {
            CertNanny::Logging->error("createreqest(): Could not write key file");
            return;
        }        
        chmod 0600, $keyfile;
        
    } else {
        # okay we have an engine, create the correct keyfile variable
        $keyfile = "${location}?alias=${newalias}";
    }
    my $ret ={ 
        REQUESTFILE => $requestfile, 
        KEYFILE => $keyfile,
    }; 
    
    return $ret; 
    
}

# Generates a new key in the current keystore,
# but only if it has not already done that, i.e. a key
# from a previous run is reused!
sub getnewkey {
    my $self = shift;
    my $entry = $self->{OPTIONS}->{ENTRY};
    my $alias = $entry->{alias};
    my $newalias = "${alias}-new";
    my $location = $entry->{location};
    my @cmd;
    
    #first check if key  already exists
    push(@cmd, '-alias');
    push(@cmd, qq{"$newalias"});
    push(@cmd, '-list');
    @cmd = $self->keytoolcmd($location, @cmd);
    CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
    if(run_command(join(" ", @cmd)) != 0) {
        # we need to generate a new one since we don't already have one
        CertNanny::Logging->info("getnewkey(): Creating new key with alias $newalias");
        @cmd = ('-genkeypair', );
        push(@cmd, '-alias');
        push(@cmd, qq{"$newalias"});
        my $DN  = $self->{CERT}->{INFO}->{SubjectName};
        push(@cmd, '-dname');
        push(@cmd, qq{"$DN"});
        push(@cmd, '-keyalg');
        push(@cmd, "$entry->{keyalg}");
        push(@cmd, '-sigalg');
        push(@cmd, "$entry->{sigalg}");
        @cmd = $self->keytoolcmd($location, @cmd);
        CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
        if(run_command(join(' ', @cmd)) != 0) {
            CertNanny::Logging->error("getnewkey(): Could not create the new key, see above output for details");
            return;  
        }
    }
    
    return $newalias;
       
}

# This method is called once the new certificate has been received from
# the SCEP server. Its responsibility is to create a new keystore containing
# the new key, certificate, CA certificate keychain and collection of Root
# certificates configured for CertNanny.
# A true return code indicates that the keystore was installed properly.
sub installcert {
    my $self = shift;
    my %args = ( @_,);
    my $options = $self->{OPTIONS};
    my $entry = $options->{ENTRY};
    my $location = $entry->{location};
    my @cmd;
    # change old key's alias to something meaningful
    my $alias = $entry->{alias};
    my $timestamp = time();
    my $backupalias = "old-${alias}-${timestamp}";
    if(!$self->changealias($alias, $backupalias)) {
        CertNanny::Logging->error("Could not change old key's alias from $alias to $backupalias. Cannot proceed with certificate installation.");
        return;
    }
    
    # check that all root certificates that exist are in the keystore
    # all trusted root ca certificates...
    my @trustedcerts = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};
    
    # ... plus all certificates from the ca key chain minus its root cert
    push(@trustedcerts, @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1..$#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);
    my $olddir = getcwd();
	chdir ($args{TARGETDIR} ||$self->{OPTIONS}->{ENTRY}->{statedir});
    foreach my $caentry (@trustedcerts) {
        my @rdn = split(/(?<!\\),\s*/, $caentry->{CERTINFO}->{SubjectName});
        my $cn = $rdn[0];
        $cn =~ s/^CN=//;
    
    
        CertNanny::Logging->info("Adding certificate '$caentry->{CERTINFO}->{SubjectName}' from file $caentry->{CERTFILE}");
    
        # rewrite certificate into pem format
        my $cacert = $self->convertcert(OUTFORMAT => 'PEM',
    				    CERTFILE => $caentry->{CERTFILE},
    				    CERTFORMAT => 'PEM',
    	);
        
        if (! defined $cacert)
        {
    	    CertNanny::Logging->error("installcert(): Could not convert certificate $caentry->{CERTFILE}");
    	return;
        }
    
        my $cacertfile = $self->gettmpfile();
        if (! CertNanny::Util->write_file(FILENAME => $cacertfile,
    			    CONTENT  => $cacert->{CERTDATA})) {
    	    CertNanny::Logging->error("installcert(): Could not write temporary ca file");
    	    return;
        }
        
        if(!$self->importcert($cacertfile, $cn)) {
            CertNanny::Logging->info("Could not install certificate '$cn', probably already present. Not critical");
        }
    }
    chdir $olddir;
    
         
         
    
    # rename the new key to the old key's alias
    my $newkeyalias = $self->getnewkey();
    if(!$self->changealias($newkeyalias, $alias)) {
        CertNanny::Logging->error("Could not rename new key to old key's alias from $newkeyalias to $alias. Rolling back previous renaming to get back the old store");
        if(!$self->changealias($backupalias, $alias)) {
            CertNanny::Logging->error("Could not even rename the old key back to its previous name. Something is seriously wrong. Keystore might be broken, please investigate!");
            return;
        }
    }
    
    # install the new cert with the old alias
    if(!$self->importcert($args{CERTFILE}, $alias)) {
        CertNanny::Logging->error("Could not import the new certificate. Currently active key has no valid certificate. Rolling back previous renaming to get back working store.");
        if(!$self->changealias($alias, $newkeyalias)) {
            CertNanny::Logging->error("Could not rename the new key back to its previous alias. Thus cannot restore old key's alias. Keystore might be broken, please investigate!");
            return;
        }
        if(!$self->changealias($backupalias, $alias)) {
            CertNanny::Logging->error("Could not rename the old key back to its previous name. Keystore might be broken, please investigate!");
            return;
        }
    }
    
    return 1;
}

# Imports certificate to keystore
# first argument is the file to import
# second argument is the alias with which to import
sub importcert {
    my $self = shift;
    my $certfile = shift;
    my $alias = shift;
    my $location = $self->{OPTIONS}->{ENTRY}->{location};
    
    my @cmd = $self->keytoolcmd($location, '-import', '-noprompt', -alias => qq{"$alias"}, -file => qq{"$certfile"});
    CertNanny::Logging->info("Importing certificate with alias $alias");
    CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
    if(run_command(join(' ', @cmd)) == 0) {
        return 1;
    } else {
        return 0;
    }
}

sub changealias {
    my $self = shift;
    my $alias = shift;
    my $destalias = shift;
    my $location = $self->{OPTIONS}->{ENTRY}->{location};
    my @cmd = ('-changealias', );
    push(@cmd, '-alias');
    push(@cmd, qq{"$alias"});
    push(@cmd, '-destalias');
    push(@cmd, qq{"$destalias"});
    @cmd = $self->keytoolcmd($location, @cmd);
    CertNanny::Logging->debug("Execute: " . join(' ', hidepin(@cmd)));
    if(run_command(join(' ', @cmd)) != 0) {
        CertNanny::Logging->error("Could not change alias from $alias to $destalias");
        return;
    } else {
        return 1;
    }
    
}

1;
