#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::OpenSSL;

use base qw(Exporter CertNanny::Keystore);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

use IO::File;
use File::Spec;
use File::Copy;
use Data::Dumper;
use CertNanny::Util;
use Net::Domain;

$VERSION = 0.10;


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

    # propagate PIN to class options
    $self->{PIN} = $self->{OPTIONS}->{ENTRY}->{pin};

	if(defined $self->{OPTIONS}->{CONFIG}->{INITIALENROLLEMNT} and $self->{OPTIONS}->{CONFIG}->{INITIALENROLLEMNT} eq 'yes' ){
 		CertNanny::Logging->info("Initial enrollment mode, skip check for key and cert file");

	}else{
				
		if (! defined $self->{OPTIONS}->{ENTRY}->{keyfile} ||
	    (! -r $self->{OPTIONS}->{ENTRY}->{keyfile})
	    && !defined $self->{OPTIONS}->{ENTRY}->{hsm}) {
		    croak("keystore.keyfile $self->{OPTIONS}->{ENTRY}->{keyfile} not defined, does not exist or unreadable");
		    return;
		}
	
		if (! defined $self->{OPTIONS}->{ENTRY}->{location} ||
		    (! -r $self->{OPTIONS}->{ENTRY}->{location})) {
		    croak("keystore.location $self->{OPTIONS}->{ENTRY}->{location} not defined, does not exist or unreadable");
		    return;
		}	
	}


    # desired target formats
    foreach my $format (qw( FORMAT KEYFORMAT CACERTFORMAT ROOTCACERTFORMAT )) {
	# assign format if explicitly defined in config
	if (defined $self->{OPTIONS}->{ENTRY}->{ lc($format) }) {
	    $self->{ uc($format) } = $self->{OPTIONS}->{ENTRY}->{ lc($format) };
	}

	# assign default otherwise
	if (! defined $self->{ uc($format) }) {
	    $self->{ uc($format) } 
	      = uc($format) eq 'FORMAT' 
		  ? 'PEM'              # default for .format
		  : $self->{FORMAT};   # default for the rest
	}

	if ($self->{ uc($format) } !~ m{ \A (?: DER | PEM ) \z }xms) {
	    croak("Incorrect ." 
		  . lc($format) . " specification '" . $self->{ uc($format) } . "'");
	    return;
	}
    }


    $self->{KEYTYPE} = $self->{OPTIONS}->{ENTRY}->{keytype};
    $self->{KEYTYPE} ||= 'OpenSSL';

    if ($self->{KEYTYPE} !~ m{ \A (?: OpenSSL | PKCS8 ) \z }xms) {
	croak("Incorrect keystore type $self->{KEYTYPE}");
	return;
    }
    
    # sanity check: DER encoded OpenSSL keys cannot be encrypted
    if (defined $self->{PIN} &&
	($self->{PIN} ne "") &&
	($self->{KEYTYPE} eq 'OpenSSL') &&
	($self->{KEYFORMAT} eq 'DER')) {
	croak("DER encoded OpenSSL keystores cannot be encrypted");
	return;
    }


    # sanity check: Root CA bundle in DER format does not make sense
    if (($self->{ROOTCACERTFORMAT} eq 'DER')
	&& defined $self->{OPTIONS}->{ENTRY}->{rootcacertbundle}) {
	croak("DER encoded Root CA bundles are not supported. Fix .format and/or .rootcacertformat and/or .rootcabundle config settings");
	return;
    }

    # if we want to use an HSM    
    if($self->{OPTIONS}->{ENTRY}->{hsm}->{type}) {
        my $hsmtype = $self->{OPTIONS}->{ENTRY}->{hsm}->{type};
        my $entry_options = $self->{OPTIONS}->{ENTRY};
        my $config = $self->{OPTIONS}->{CONFIG};
        my $entryname = $self->{OPTIONS}->{ENTRYNAME};
        CertNanny::Logging->debug("Using HSM $hsmtype");
        eval "use CertNanny::HSM::$hsmtype";
        if ($@) {
            print STDERR $@;
            return;
        }
        eval "\$self->{HSM} = CertNanny::HSM::$hsmtype->new(\$entry_options, \$config, \$entryname)";
        if ($@ or not $self->{HSM}) {
        	CertNanny::Logging->error("Could not instantiate HSM: ".$@);
        	return;
        }
        
        my $hsm = $self->{HSM};
        unless($hsm->can('createrequest') and $hsm->can('genkey')) {
            unless($hsm->can('engineid')) {
    	        croak("HSM does not provide function engineid(), can not continue.");
    	    }
    	    
    	    unless($hsm->can('keyform')) {
    	        croak("HSM does not provide function keyform(), can not continue.");
    	    }
        }
    }

    # get previous renewal status
    $self->retrieve_state() || return;

    # check if we can write to the file
    $self->store_state() || croak "Could not write state file $self->{STATE}->{FILE}";

    # instantiate keystore
    return ($self);
}


sub DESTROY {
    my $self = shift;
    # call parent destructor
    $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}



###########################################################################
# mandatory functions
# export certificate in DER or PEM format
sub getcert {
    my $self = shift;
    my $filename = $self->{OPTIONS}->{ENTRY}->{location};

    my $certdata = CertNanny::Util->read_file($filename);
    if (! defined $certdata) {
    	CertNanny::Logging->error("getcert(): Could not read instance certificate file $filename");
	return;
    }
    
    my $format = 'DER';
    if ($certdata =~ m{ -----.*CERTIFICATE.*----- }xms) {
	$format = 'PEM';
    }

    return ({ CERTDATA => $certdata,
	      CERTFORMAT => $format });
}


sub getkey {
    my $self = shift;
    my $filename = $self->{OPTIONS}->{ENTRY}->{keyfile};
    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	CertNanny::Logging->error("No openssl shell specified");
	return;
    }
    
    unless($self->hasEngine()) {
        my $keydata = CertNanny::Util->read_file($filename);
        if (! defined $keydata || ($keydata eq "")) {
    	CertNanny::Logging->error("getkey(): Could not read private key");
    	return;
        }
        
        my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin};
        
        my $keyformat = 'DER';
        if ($keydata =~ m{ -----BEGIN.*KEY----- }xms) {
    	$keyformat = 'PEM';
        }
    
        return (
    	{ 
    	    KEYDATA => $keydata,
    	    KEYTYPE => $self->{KEYTYPE},
    	    KEYFORMAT => $keyformat,
    	    KEYPASS => $pin,
    	});        
    } else {
        if($self->{HSM}->can('getkey')) {
            return $self->{HSM}->getkey();
        } else{
            return $filename;    
        }
    }

    
}

# create pkcs12 file
# in:
# FILENAME => pkcs12 file to create
# FRIENDLYNAME => cert label to be used in pkcs#12 structure
# EXPORTPIN => PIN to be set for pkcs#12 structure
# CERTFILE => certificate to include in the pkcs#12 file, instance certificate
#             if not specified
# CERTFORMAT => PEM|DER, instance cert format if not specified
# KEYFILE => keyfile, instance key if not specified
# PIN => keyfile pin
# CACHAIN => arrayref containing the certificate info structure of 
#            CA certificate files to be included in the PKCS#12
#            Required keys for entries: CERTFILE, CERTFORMAT, CERTINFO

sub createpkcs12 {
    my $self = shift;
    my %args = (FILENAME => undef,
		FRIENDLYNAME => undef,
		EXPORTPIN => undef,
		CACHAIN => undef,
		CERTFILE => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE},
		CERTFORMAT => 'PEM',
		KEYFILE => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE},
		PIN => $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin},
		@_);

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	CertNanny::Logging->error("No openssl shell specified");
	return;
    }

    if (! defined $args{FILENAME}) {
	CertNanny::Logging->error("createpks12(): No output file name specified");
	return;
    }

    if (! defined $args{CERTFILE}) {
	CertNanny::Logging->error("createpks12(): No certificate file specified");
	return;
    }

    if (! defined $args{KEYFILE}) {
	CertNanny::Logging->error("createpks12(): No key file specified");
	return;
    }

    CertNanny::Logging->debug("Certformat: $args{CERTFORMAT}");

    if (! defined $args{CERTFORMAT} or $args{CERTFORMAT} !~ /^(PEM|DER)$/) {
	CertNanny::Logging->error("createpks12(): Illegal certificate format specified");
	return;
    }

    if (! defined $args{EXPORTPIN}) {
	CertNanny::Logging->error("createpks12(): No export PIN specified");
	return;
    }

    my @cmd;

    my $certfile = $args{CERTFILE};

    # openssl pkcs12 command does not support DER input format, so
    # convert it to PEM first
    # FIXME: use SUPER::convertcert?
    if ($args{CERTFORMAT} eq "DER") {
	$certfile = $self->gettmpfile();

	@cmd = (qq("$openssl"),
		'x509',
		'-in',
		qq("$args{CERTFILE}"),
		'-inform',
		qq("$args{CERTFORMAT}"),
		'-out',
		qq("$certfile"),
		'-outform',
		'PEM',
		);

	CertNanny::Logging->log({ MSG => "Execute: " . join(" ", @cmd),
		     PRIO => 'debug' });
	
	if (run_command(join(' ', @cmd)) != 0) {
	    CertNanny::Logging->error("Certificate format conversion failed");
	    return;
	}
    }

    my @passin = ();
    if (defined $args{PIN} and $args{PIN} ne "") {
	@passin = ('-passin',
		   'env:PIN');
	$ENV{PIN} = $args{PIN};
    }

    my @passout = ();
    if (defined $args{EXPORTPIN} and $args{EXPORTPIN} ne "") {
	@passout = ('-password',
		    'env:EXPORTPIN');
	$ENV{EXPORTPIN} = $args{EXPORTPIN};
    }

    my @name = ();
    if (defined $args{FRIENDLYNAME} and $args{FRIENDLYNAME} ne "") {
	@name = ('-name',
		 qq("$args{FRIENDLYNAME}"));
    }

    my $cachainfile;
    my @cachain = ();
    if (defined $args{CACHAIN} and ref $args{CACHAIN} eq "ARRAY") {
	$cachainfile = $self->gettmpfile;
	my $fh = new IO::File(">$cachainfile");
	if (! $fh)
	{
	    CertNanny::Logging->error("createpkcs12(): Could not create temporary CA chain file");
	    return;
	}
	
	# add this temp file
	push (@cachain, '-certfile');
	push (@cachain, qq("$cachainfile"));
	
	foreach my $entry (@{$args{CACHAIN}}) {
	    my $file = $entry->{CERTFILE};
	    my @RDN = split(/(?<!\\),\s*/, $entry->{CERTINFO}->{SubjectName});
	    my $CN = $RDN[0];
	    $CN =~ s/^CN=//;
	    CertNanny::Logging->debug("Adding CA certificate '$CN' in $file");

	    my $content = CertNanny::Util->read_file($file);
	    if (! defined $content) {
		CertNanny::Logging->error("createpkcs12(): Could not read CA chain entry");
		$fh->close;
		unlink $cachainfile if (defined $cachainfile);
		return;
	    }

	    print $fh $content;
	    push(@cachain, '-caname');
	    push(@cachain, qq("$CN"));
	}
	$fh->close;
    }

    @cmd = (qq("$openssl"),
	    'pkcs12',
	    '-export',
	    '-out',
	    qq("$args{FILENAME}"),
	    @passout,
	    '-in',
	    qq("$certfile"),
	    '-inkey',
	    qq("$args{KEYFILE}"),
	    @passin,
	    @name,
	    @cachain,
	    );


    CertNanny::Logging->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });

    if (run_command(join(' ', @cmd)) != 0) {
	CertNanny::Logging->error("PKCS#12 export failed");
	delete $ENV{PIN};
	delete $ENV{EXPORTPIN};
	unlink $certfile if ($args{CERTFORMAT} eq "DER");
	unlink $cachainfile if (defined $cachainfile);
	return;
    }

    delete $ENV{PIN};
    delete $ENV{EXPORTPIN};
    unlink $certfile if ($args{CERTFORMAT} eq "DER");
    unlink $cachainfile if (defined $cachainfile);

    return $args{FILENAME};
}


sub generatekey {
    my $self = shift;

    my $keyfile = $self->{OPTIONS}->{ENTRYNAME} . "-key.pem";
    my $outfile = File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
				      $keyfile);
				      	
    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";
	my $bits = $self->{SIZE} || $self->{OPTIONS}->{ENTRY}->{size} ||'2048';
	my $engine = $self->{ENGINE} || $self->{OPTIONS}->{ENTRY}->{engine} ||'no';
	my $enginetype = $self->{ENGINETYPE} || $self->{OPTIONS}->{ENTRY}->{enginetype} ||'none';
	my $enginename = $self->{ENGINENAME} || $self->{OPTIONS}->{ENTRY}->{enginename} ||'none';
	#TODO Doku!
	if ($self->hasEngine() and $self->{HSM}->can('genkey')){
	    my $hsm = $self->{HSM};
	    CertNanny::Logging->debug("Generating a new key using the configured HSM.");
	    $outfile = $hsm->genkey();
	    unless($outfile) {
	        CertNanny::Logging->error("HSM could not generate new key.");
	        return;
	    }
    } else{
        CertNanny::Logging->debug("Generating a new key using native OpenSSL functionality.");
    	my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    	if (! defined $openssl) {
		CertNanny::Logging->error("No openssl shell specified");
		return;
    	}

	    my @passout = ();
    	if (defined $pin and $pin ne "") {
		@passout = ('-des3',
			    '-passout',
			    'env:PIN');
	   	 }	

        my @engine_cmd;
         if($self->hasEngine()) {
             my $hsm = $self->{HSM};
             CertNanny::Logging->debug("Since an engine is used, setting required command line parameters.");
             push(@engine_cmd, '-engine', $hsm->engineid());
             push(@engine_cmd, '-keyform', $hsm->keyform()) if $hsm->keyform();
         }

    	# generate key
    	my @cmd = (qq("$openssl"),
	    	'genrsa',
		   	'-out',
	       	qq("$outfile"),
	       	@passout,
            @engine_cmd,
	       	$bits);

	    CertNanny::Logging->log({ MSG => "Execute: " . join(" ", @cmd),
			 PRIO => 'debug' });

	    $ENV{PIN} = $pin;
	    if (run_command(join(' ', @cmd)) != 0) {
		CertNanny::Logging->error("RSA key generation failed");
		delete $ENV{PIN};
		return;
   		}
	}
    chmod 0600, $outfile;
    delete $ENV{PIN};
    
    return ({ KEYFILE => $outfile });
}

sub createrequest {
    my $self = shift;
    CertNanny::Logging->info("Creating request");
	
	my $result = undef; 
    #print Dumper $self;
    if($self->{INITIALENROLLEMNT} eq 'yes'  and  ($self->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{mode} eq 'password'
     or $self->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{mode} eq 'anonymous' ))
    {
    	my $keyfile = $self->{OPTIONS}->{ENTRYNAME} . "-key.pem";
    	my $outfile = File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},$keyfile);
    	$result = { KEYFILE => $outfile };
      	CertNanny::Logging->debug("Skip key generation in initialenrollment its already generated for selfsign certificate");
	
    }else{
    	 $result = $self->generatekey();
    }
   
    
    if (! defined $result) {
	CertNanny::Logging->error("Key generation failed");
	return;
    }    
    
    my $requestfile = $self->{OPTIONS}->{ENTRYNAME} . ".csr";
    $result->{REQUESTFILE} = 
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $requestfile);
    
    if($self->hasEngine() and $self->{HSM}->can('createrequest')) {
        CertNanny::Logging->debug("Creating new CSR with HSM.");
        $result = $self->{HSM}->createrequest($result);
    } else {
        my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";
        CertNanny::Logging->debug("Creating new CSR with native OpenSSL functionality.");
    
        my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
        if (! defined $openssl) {
    	CertNanny::Logging->error("No openssl shell specified");
    	return;
        }
    
    	my $DN ;
    	#for inital enrollment we override the DN to use the configured desiered DN rather then the preset enrollment certificates DN
        if($self->{INITIALENROLLEMNT} eq 'yes')
        {
      		 $DN = $self->{OPTIONS}->{ENTRY}->{initialenroll}->{subject};
        }else{
        	 $DN = $self->{CERT}->{INFO}->{SubjectName};
        }
      		
    
        CertNanny::Logging->debug("DN: $DN");
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
        map { delete $RDN_Count{$_} if ($RDN_Count{$_} == 1); } keys %RDN_Count;
    
        
        # create OpenSSL config file
        my $config_options = CertNanny::Util->getDefaultOpenSSLConfig();
        $config_options->{req} = [];
        push(@{$config_options->{req}}, {prompt => "no"});
        push(@{$config_options->{req}}, {distinguished_name => "req_distinguished_name"});
              
        # handle subject alt names from inital configuration information 
		my $newsans = '';
        
        if($self->{INITIALENROLLEMNT} eq 'yes')
        {  	
        	CertNanny::Logging->debug("Add SANs for initial enrollment");
        	if (exists $self->{OPTIONS}->{ENTRY}->{initialenroll}->{san}){
        		push(@{$config_options->{req}}, {req_extensions => "v3_ext"});
          	SANS:	 	
        		 foreach my $key ( keys %{$self->{OPTIONS}->{ENTRY}->{initialenroll}->{san}} ){
        		 	next SANS if($key eq 'INHERIT'); 
        		 	$newsans .= $self->{OPTIONS}->{ENTRY}->{initialenroll}->{san}->{$key}.','; 
        		 	
        		 }
        		##write inittal enrollment SANs into the cert information without last ','
      			$self->{CERT}->{INFO}->{SubjectAlternativeName} = substr($newsans , 0 , -1) ;      		 
        	}	 
           	
        }else{
        	 if (exists $self->{CERT}->{INFO}->{SubjectAlternativeName}) {
    	   		push(@{$config_options->{req}}, {req_extensions => "v3_ext"});
        }
        }
        
        $config_options->{req_distinguished_name} = [];
        foreach (reverse @RDN) {
            my $rdnstr = "";
        	my ($key, $value) = (/(.*?)=(.*)/);
        	if (exists $RDN_Count{$key}) {
        	    $rdnstr = $RDN_Count{$key} . ".";
        	    $RDN_Count{$key}--;
        	}
        	
        	$rdnstr .= $key; 
        	push(@{$config_options->{req_distinguished_name}}, {$rdnstr => $value});
        }
        
        if (exists $self->{CERT}->{INFO}->{SubjectAlternativeName}) {
        	my $san = $self->{CERT}->{INFO}->{SubjectAlternativeName};
        	$san =~ s{ IP\ Address: }{IP:}xmsg;
        	$config_options->{v3_ext} = [];
        	push(@{$config_options->{v3_ext}}, {subjectAltName => $san});
        }
        
        if($self->{INITIALENROLLEMNT} eq 'yes')
        {
        	CertNanny::Logging->debug("Enter initial enrollment section");
        	
        	if(exists $self->{OPTIONS}->{ENTRY}->{initialenroll}->{profile} && $self->{OPTIONS}->{ENTRY}->{initialenroll}->{profile} ne ''){
        	
        		CertNanny::Logging->debug("Found initial enroll profile: " . $self->{OPTIONS}->{ENTRY}->{initialenroll}->{profile} );
        		push(@{$config_options->{v3_ext}}, { '1.3.6.1.4.1.311.20.2' => 'DER:'.CertNanny::Util->encodeBMPString($self->{OPTIONS}->{ENTRY}->{initialenroll}->{profile}) });
        	}
        	
        	if(exists $self->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword} && $self->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword} ne ''){
        		CertNanny::Logging->debug("Add challenge Password to CSR"); 
        		push(@{$config_options->{req}}, {attributes  => "req_attributes"});   		
         		push(@{$config_options->{req_attributes}}, { 'challengePassword' => $self->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword} } );        			
        	}
        	     	
        }
        
        
        my @engine_cmd;
        if($self->hasEngine()) {
    	    my $hsm = $self->{HSM};
    	    CertNanny::Logging->debug("Setting required engine parameters for HSM.");
    	    my $engine_id = $hsm->engineid();
    	    push(@engine_cmd, '-engine', $engine_id);
    	    
    	    if($hsm->keyform()) {
    	        push(@engine_cmd, '-keyform', $hsm->keyform());
    	    }
    	    
    	    my $engine_config = $self->{HSM}->getEngineConfiguration();
    	    if($engine_config) {
    	        my $engine_section = "${engine_id}_section";
                $config_options->{engine_section} = [];
                push(@{$config_options->{engine_section}}, {$engine_id => "${engine_id}_section"});
                $config_options->{$engine_section} = $engine_config;
    	    }
    	}
        CertNanny::Logging->debug("config_options ");
        my $tmpconfigfile = CertNanny::Util->writeOpenSSLConfig($config_options);
        #CertNanny::Logging->debug("The following configuration was written to $tmpconfigfile:\n" . CertNanny::Util->read_file($tmpconfigfile));
    
        # generate request
        my @cmd = (qq("$openssl"),
    	       'req',
    	       '-config',
    	       qq("$tmpconfigfile"),
    	       '-new',
    	       '-sha1',
    	       '-out',
    	       qq("$result->{REQUESTFILE}"),
    	       '-key',
    	       qq("$result->{KEYFILE}"),
    	);
        push (@cmd, ('-passin', 'env:PIN')) unless $pin eq "";
        push (@cmd, @engine_cmd);
    
        CertNanny::Logging->log({ MSG => "Execute: " . join(" ", @cmd),
    		 PRIO => 'debug' });
    
        $ENV{PIN} = $pin;
        if (run_command(join(' ', @cmd)) != 0) {
    	CertNanny::Logging->error("Request creation failed");
    	delete $ENV{PIN};
    	unlink $tmpconfigfile;
    	return;
        }
        delete $ENV{PIN};
        unlink $tmpconfigfile;
    }

    return $result;
}

sub installcert {
    my $self = shift;
    my %args = ( 
        @_,         # argument pair list
    );
    my $keyfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";

    #print Dumper $self;


    # data structure representing the new keystore (containing all 
    # new file contents to write)
    my @newkeystore = ();

    ######################################################################
    ### private key...
    my $newkey;
    unless($self->hasEngine() and $self->{HSM}->keyform() ne "file") {
        unless($self->hasEngine()) {
            $newkey = $self->convertkey(
        	KEYFILE => $keyfile,
        	KEYFORMAT => 'PEM',
        	KEYTYPE   => 'OpenSSL',
        	KEYPASS   => $pin,
        	OUTFORMAT => $self->{KEYFORMAT},
        	OUTTYPE   => $self->{KEYTYPE},
        	OUTPASS   => $pin,
        	);
        } else {
            my $keydata = CertNanny::Util->read_file($keyfile);
            $newkey->{KEYDATA} = $keydata;
            # the following data is probably not necessary, but we emulate convertkey here
            $newkey->{KEYFORMAT} = $self->{KEYFORMAT};
            $newkey->{KEYTYPE} = $self->{KEYTYPE};
            $newkey->{KEYPASS} = $pin;
        }
    
        if (! defined $newkey) {
    	CertNanny::Logging->error("Could not read/convert new key");
    	return;
        }
    
        push(@newkeystore, 
    	 {
    	     DESCRIPTION => "End entity private key",
    	     FILENAME    => $self->{OPTIONS}->{ENTRY}->{keyfile},
    	     CONTENT     => $newkey->{KEYDATA},
    	 });
    }
    
    
    ######################################################################
    ### certificate...
    my $newcert = $self->convertcert(
	CERTFILE => $args{CERTFILE},
	CERTFORMAT => 'PEM',
	OUTFORMAT => $self->{FORMAT},
	);

    if (! defined $newcert) {
	CertNanny::Logging->error("Could not read/convert new certificate");
	return;
    }

    push(@newkeystore, 
	 {
	     DESCRIPTION => "End entity certificate",
	     FILENAME    => $self->{OPTIONS}->{ENTRY}->{location},
	     CONTENT     => $newcert->{CERTDATA},
	 });
    

    ######################################################################
    ### CA certificates...
    my $ii = 0;
    if (! exists $self->{OPTIONS}->{ENTRY}->{cacert}->{$ii}) {
	# cacert.0 does not exist, start with .1
	$ii = 1;
    }
    while (exists $self->{OPTIONS}->{ENTRY}->{cacert}->{$ii}
	   && defined $self->{STATE}->{DATA}->{CERTCHAIN}[$ii]) {

	# determine CA certificate for this level
	my $entry = $self->{STATE}->{DATA}->{CERTCHAIN}[$ii];
	### $entry

	my $destfile = $self->{OPTIONS}->{ENTRY}->{cacert}->{$ii};
	### $destfile

	my $cacert = $self->convertcert(
	    CERTFILE => $entry->{CERTFILE},
	    CERTFORMAT => 'PEM',
	    OUTFORMAT => $self->{CACERTFORMAT},
	    );
	
	if (defined $cacert) {
	    push(@newkeystore, 
		 {
		     DESCRIPTION => "CA certificate level $ii",
		     FILENAME    => $destfile,
		     CONTENT     => $cacert->{CERTDATA},
		 });
	} else {
	    CertNanny::Logging->error("Could not convert CA certificate for level $ii");
	    return;
	}
	$ii++;
    }

    ######################################################################
    # try to write root certificates
    
    if (exists $self->{OPTIONS}->{ENTRY}->{rootcacertbundle}) {
	my $fh = new IO::File(">" . $self->{OPTIONS}->{ENTRY}->{rootcacertbundle});
	if (! $fh)
	{
	    CertNanny::Logging->error("installcert(): Could not create Root CA certificate bundle file");
	    return;
	}

	foreach my $entry (@{$self->{STATE}->{DATA}->{ROOTCACERTS}}) {
	    my $cert = $self->convertcert(OUTFORMAT => 'PEM',
					  CERTFILE => $entry->{CERTFILE},
					  CERTFORMAT => 'PEM',
		);
	    
	    if (! defined $cert)
	    {
		CertNanny::Logging->error("installcert(): Could not convert root certificate $entry->{CERTFILE}");
		return;
	    }

	    my $data = $cert->{CERTDATA};
	    chomp $data;
	    print $fh $data;
	    print $fh "\n";
	}

	$fh->close();
    }


    if (exists $self->{OPTIONS}->{ENTRY}->{rootcacertdir}) {
	# write root certs to specified directory, possibly with the 
	# template name used here.

	my $path = $self->{OPTIONS}->{ENTRY}->{rootcacertdir};
	my $rootcacertformat = $self->{ROOTCACERTFORMAT};

	# prepare default template
	my ($volume, $dir, $template) = ('', $path, 'root-%i.' . lc($rootcacertformat));

	# overwrite template if explicitly defined
	if (! -d $path) {
	    ($volume, $dir, $template) 
		= File::Spec->splitpath($path);
	}

	# reconstruct target directory
	$dir = File::Spec->catpath($volume, $dir);

	# sanity check
	if (! -d $dir || ! -w $dir) {
	    CertNanny::Logging->error("installcert(): Root CA certificate target directory $dir does not exist or is not writable");
	    return;
	}

	my $ii = 1;
	foreach my $entry (@{$self->{STATE}->{DATA}->{ROOTCACERTS}}) {
	    my $cert = $self->convertcert(CERTFORMAT => 'PEM',
					  CERTFILE => $entry->{CERTFILE},
					  OUTFORMAT => $rootcacertformat,
		);
	    
	    if (! defined $cert)
	    {
		CertNanny::Logging->error("installcert(): Could not convert root certificate $entry->{CERTFILE}");
		return;
	    }

	    my $filename = $template;

	    # replace tags
	    $filename =~ s{%i}{$ii}xmsg;

	    $filename = File::Spec->catfile(
		$dir,
		$filename);
	    
	    if (! CertNanny::Util->write_file(
		      FILENAME => $filename,
		      CONTENT  => $cert->{CERTDATA},
		      FORCE    => 1,
		)) {
		CertNanny::Logging->error("installcert(): Could not write root certificate $filename");
		return;
	    }

	    $ii++;
	}
    }
    
    ######################################################################
    # try to write the new keystore 

    if (! $self->installfile(@newkeystore)) {
	CertNanny::Logging->error("Could not install new keystore");
	return;
    }
	   
    return 1;
}

sub hasEngine {
    my $self = shift;
    return defined $self->{HSM};
}

sub selfsign {
    my $self = shift;

 	my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    my $selfsigncert = $self->{OPTIONS}->{ENTRYNAME} . "-selfcert.pem";
    my $outfile = File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
				      $selfsigncert);
    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";
    
    ######prepere openssl config file##########
    my $DN ;
    	#for inital enrollment we override the DN to use the configured desiered DN rather then the preset enrollment certificates DN
        if($self->{INITIALENROLLEMNT} eq 'yes')
        {
      		 $DN = $self->{OPTIONS}->{ENTRY}->{initialenroll}->{subject};
        }else{
        	 $DN = Net::Domain::hostfqdn();
        }
      		
    
        CertNanny::Logging->debug("DN: $DN");
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
        map { delete $RDN_Count{$_} if ($RDN_Count{$_} == 1); } keys %RDN_Count;
    
    
        
     my $config_options = CertNanny::Util->getDefaultOpenSSLConfig();
     $config_options->{req} = [];
     push(@{$config_options->{req}}, {prompt => "no"});
     push(@{$config_options->{req}}, {distinguished_name => "req_distinguished_name"});
       
        $config_options->{req_distinguished_name} = [];
        foreach (reverse @RDN) {
            my $rdnstr = "";
        	my ($key, $value) = (/(.*?)=(.*)/);
        	if (exists $RDN_Count{$key}) {
        	    $rdnstr = $RDN_Count{$key} . ".";
        	    $RDN_Count{$key}--;
        	}
        	
        	$rdnstr .= $key; 
        	push(@{$config_options->{req_distinguished_name}}, {$rdnstr => $value});
        }
        


        my $tmpconfigfile = CertNanny::Util->writeOpenSSLConfig($config_options);
        CertNanny::Logging->debug("The following configuration was written to $tmpconfigfile:\n" . CertNanny::Util->read_file($tmpconfigfile));
        
    
            # generate request
        my @cmd = (qq("$openssl"),
    	       'req',
    	       '-config',
    	       qq("$tmpconfigfile"),
    	       '-x509',
    	       '-new',
    	       '-sha1',
    	       '-out',
    	       qq("$outfile"),
    	       '-key',
    	       qq("$self->{OPTIONS}->{ENTRY}->{keyfile}"),
    	);
 
    
		push (@cmd, ('-passin', 'env:PIN')) unless $pin eq "";
    
        CertNanny::Logging->log({ MSG => "Execute: " . join(" ", @cmd),
    		 PRIO => 'debug' });
    
        $ENV{PIN} = $pin;
        if (run_command(join(' ', @cmd)) != 0) {
    		CertNanny::Logging->error("Selfsign certifcate creation failed!");
         	delete $ENV{PIN};
        }
    
			#    openssl req -x509 -days 365 -new -out self-signed-certificate.pem
			#	-key pub-sec-key.pem

    
    return ({ CERT => $outfile });
}


1;
