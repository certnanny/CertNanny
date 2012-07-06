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

    foreach my $entry (qw( keyfile location )) {
	if (! defined $self->{OPTIONS}->{ENTRY}->{$entry} ||
	    (! -r $self->{OPTIONS}->{ENTRY}->{$entry})) {
	    croak("keystore.$entry $self->{OPTIONS}->{ENTRY}->{$entry} not defined, does not exist or unreadable");
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

    my $certdata = $self->read_file($filename);
    if (! defined $certdata) {
    	$self->seterror("getcert(): Could not read instance certificate file $filename");
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
	$self->seterror("No openssl shell specified");
	return;
    }

    my $keydata = $self->read_file($filename);
    if (! defined $keydata || ($keydata eq "")) {
	$self->seterror("getkey(): Could not read private key");
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
	$self->seterror("No openssl shell specified");
	return;
    }

    if (! defined $args{FILENAME}) {
	$self->seterror("createpks12(): No output file name specified");
	return;
    }

    if (! defined $args{CERTFILE}) {
	$self->seterror("createpks12(): No certificate file specified");
	return;
    }

    if (! defined $args{KEYFILE}) {
	$self->seterror("createpks12(): No key file specified");
	return;
    }

    $self->debug("Certformat: $args{CERTFORMAT}");

    if (! defined $args{CERTFORMAT} or $args{CERTFORMAT} !~ /^(PEM|DER)$/) {
	$self->seterror("createpks12(): Illegal certificate format specified");
	return;
    }

    if (! defined $args{EXPORTPIN}) {
	$self->seterror("createpks12(): No export PIN specified");
	return;
    }

    my @cmd;

    my $certfile = $args{CERTFILE};

    # openssl pkcs12 command does not support DER input format, so
    # convert it to PEM first
    # FIXME: use SUPER::convertcert?
    if ($args{CERTFORMAT} eq "DER") {
	$certfile = $self->gettmpfile();

	@cmd = (qq('$openssl'),
		'x509',
		'-in',
		qq('$args{CERTFILE}'),
		'-inform',
		qq('$args{CERTFORMAT}'),
		'-out',
		qq('$certfile'),
		'-outform',
		'PEM',
		);

	$self->log({ MSG => "Execute: " . join(" ", @cmd),
		     PRIO => 'debug' });
	
	if (run_command(join(' ', @cmd)) != 0) {
	    $self->seterror("Certificate format conversion failed");
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
		 qq('$args{FRIENDLYNAME}'));
    }

    my $cachainfile;
    my @cachain = ();
    if (defined $args{CACHAIN} and ref $args{CACHAIN} eq "ARRAY") {
	$cachainfile = $self->gettmpfile;
	my $fh = new IO::File(">$cachainfile");
	if (! $fh)
	{
	    $self->seterror("createpkcs12(): Could not create temporary CA chain file");
	    return;
	}
	
	# add this temp file
	push (@cachain, '-certfile');
	push (@cachain, qq('$cachainfile'));
	
	foreach my $entry (@{$args{CACHAIN}}) {
	    my $file = $entry->{CERTFILE};
	    my @RDN = split(/(?<!\\),\s*/, $entry->{CERTINFO}->{SubjectName});
	    my $CN = $RDN[0];
	    $CN =~ s/^CN=//;
	    $self->debug("Adding CA certificate '$CN' in $file");

	    my $content = $self->read_file($file);
	    if (! defined $content) {
		$self->seterror("createpkcs12(): Could not read CA chain entry");
		$fh->close;
		unlink $cachainfile if (defined $cachainfile);
		return;
	    }

	    print $fh $content;
	    push(@cachain, '-caname');
	    push(@cachain, qq('$CN'));
	}
	$fh->close;
    }

    @cmd = (qq('$openssl'),
	    'pkcs12',
	    '-export',
	    '-out',
	    qq('$args{FILENAME}'),
	    @passout,
	    '-in',
	    qq('$certfile'),
	    '-inkey',
	    qq('$args{KEYFILE}'),
	    @passin,
	    @name,
	    @cachain,
	    );


    $self->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });

    if (run_command(join(' ', @cmd)) != 0) {
	$self->seterror("PKCS#12 export failed");
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

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return;
    }

    my $bits = '1024';

    my @passout = ();
    if (defined $pin and $pin ne "") {
	@passout = ('-des3',
		    '-passout',
		    'env:PIN');
    }

    # generate key
    my @cmd = (qq('$openssl'),
	       'genrsa',
	       '-out',
	       qq('$outfile'),
	       @passout,
	       $bits);

    $self->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });

    $ENV{PIN} = $pin;
    if (run_command(join(' ', @cmd)) != 0) {
	$self->seterror("RSA key generation failed");
	delete $ENV{PIN};
	return;
    }
    chmod 0600, $outfile;
    delete $ENV{PIN};
    
    return ({ KEYFILE => $outfile });
}

sub createrequest {
    my $self = shift;
    $self->info("Creating request");

    #print Dumper $self;
    my $result = $self->generatekey();
    
    if (! defined $result) {
	$self->seterror("Key generation failed");
	return;
    }    

    my $requestfile = $self->{OPTIONS}->{ENTRYNAME} . ".csr";
    $result->{REQUESTFILE} = 
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $requestfile);

    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return;
    }

    my $DN = $self->{CERT}->{INFO}->{SubjectName};

    $self->debug("DN: $DN");
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
    my $tmpconfigfile = $self->gettmpfile();
    my $fh = new IO::File(">$tmpconfigfile");
    if (! $fh)
    {
    	$self->seterror("createrequest(): Could not create temporary OpenSSL config file");
    	return;
    }
    print $fh "[ req ]\n";
    print $fh "prompt = no\n";
    print $fh "distinguished_name = req_distinguished_name\n";
    
    # handle subject alt name
    if (exists $self->{CERT}->{INFO}->{SubjectAlternativeName}) {
	print $fh "req_extensions = v3_ext\n";
    }
    
    print $fh "[ req_distinguished_name ]\n";
    foreach (reverse @RDN) {
	my ($key, $value) = (/(.*?)=(.*)/);
	if (exists $RDN_Count{$key}) {
	    print $fh $RDN_Count{$key} . ".";
	    $RDN_Count{$key}--;
	}
	print $fh $_ . "\n";
    }
    
    if (exists $self->{CERT}->{INFO}->{SubjectAlternativeName}) {
	my $san = $self->{CERT}->{INFO}->{SubjectAlternativeName};
	$san =~ s{ IP\ Address: }{IP:}xmsg;
	print $fh "[ v3_ext ]\n";
	print $fh "subjectAltName = $san\n";
    }
    
    $fh->close();

    # generate request
    my @cmd = (qq('$openssl'),
	       'req',
	       '-config',
	       qq('$tmpconfigfile'),
	       '-new',
	       '-sha1',
	       '-out',
	       qq('$result->{REQUESTFILE}'),
	       '-key',
	       qq('$result->{KEYFILE}'),
	);

    push (@cmd, ('-passin', 'env:PIN')) unless $pin eq "";

    $self->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });

    $ENV{PIN} = $pin;
    if (run_command(join(' ', @cmd)) != 0) {
	$self->seterror("Request creation failed");
	delete $ENV{PIN};
	unlink $tmpconfigfile;
	return;
    }
    delete $ENV{PIN};
    unlink $tmpconfigfile;

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
    my $newkey = $self->convertkey(
	KEYFILE => $keyfile,
	KEYFORMAT => 'PEM',
	KEYTYPE   => 'OpenSSL',
	KEYPASS   => $pin,
	OUTFORMAT => $self->{KEYFORMAT},
	OUTTYPE   => $self->{KEYTYPE},
	OUTPASS   => $pin,
	);

    if (! defined $newkey) {
	$self->seterror("Could not read/convert new key");
	return;
    }

    push(@newkeystore, 
	 {
	     DESCRIPTION => "End entity private key",
	     FILENAME    => $self->{OPTIONS}->{ENTRY}->{keyfile},
	     CONTENT     => $newkey->{KEYDATA},
	 });
    
    
    ######################################################################
    ### certificate...
    my $newcert = $self->convertcert(
	CERTFILE => $args{CERTFILE},
	CERTFORMAT => 'PEM',
	OUTFORMAT => $self->{FORMAT},
	);

    if (! defined $newcert) {
	$self->seterror("Could not read/convert new certificate");
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
	    $self->seterror("Could not convert CA certificate for level $ii");
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
	    $self->seterror("installcert(): Could not create Root CA certificate bundle file");
	    return;
	}

	foreach my $entry (@{$self->{STATE}->{DATA}->{ROOTCACERTS}}) {
	    my $cert = $self->convertcert(OUTFORMAT => 'PEM',
					  CERTFILE => $entry->{CERTFILE},
					  CERTFORMAT => 'PEM',
		);
	    
	    if (! defined $cert)
	    {
		$self->seterror("installcert(): Could not convert root certificate $entry->{CERTFILE}");
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
	    $self->seterror("installcert(): Root CA certificate target directory $dir does not exist or is not writable");
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
		$self->seterror("installcert(): Could not convert root certificate $entry->{CERTFILE}");
		return;
	    }

	    my $filename = $template;

	    # replace tags
	    $filename =~ s{%i}{$ii}xmsg;

	    $filename = File::Spec->catfile(
		$dir,
		$filename);
	    
	    if (! $self->write_file(
		      FILENAME => $filename,
		      CONTENT  => $cert->{CERTDATA},
		      FORCE    => 1,
		)) {
		$self->seterror("installcert(): Could not write root certificate $filename");
		return;
	    }

	    $ii++;
	}
    }
    
    ######################################################################
    # try to write the new keystore 

    if (! $self->installfile(@newkeystore)) {
	$self->seterror("Could not install new keystore");
	return;
    }
	   
    return 1;
}


1;
