#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny;

use base qw(Exporter);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION $AUTOLOAD);
use Exporter;
use Carp;

use FindBin;
use File::Spec;

use CertNanny::Config;
use CertNanny::Keystore;
use CertNanny::Logging;
use CertNanny::Enroll;
use CertNanny::Enroll::Sscep;
use Data::Dumper;
use POSIX ;

use IPC::Open3;

$VERSION = 0.12;

my $INSTANCE;


sub new 
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = ( 
        @_,         # argument pair list
    );

    my $self = {};
    bless $self, $class;

    $self->{CONFIG} = CertNanny::Config->getInstance($args{CONFIG});
    return unless defined $self->{CONFIG};
    CertNanny::Logging->new(CONFIG => $self->{CONFIG});
    
    # set default library path
    my @dirs = File::Spec->splitdir($FindBin::Bin);
    pop @dirs;
    if (!$self->{CONFIG}->get("path.lib", "FILE")) {
	$self->{CONFIG}->set("path.lib", File::Spec->catdir(@dirs, 'lib'));
    }
    CertNanny::Logging->debug("set perl path lib to:".File::Spec->catdir(@dirs, 'lib'));
    if (!$self->{CONFIG}->get("path.libjava", "FILE")) {
	$self->{CONFIG}->set("path.libjava", File::Spec->catdir($self->{CONFIG}->get("path.lib", "FILE"), 'java'));
    }

    
    $self->{ITEMS} = ${$self->{CONFIG}->get_ref("keystore", 'ref')};

    if (! defined $self->{ITEMS}) {
	# fall back to legacy configuration (backward compatibility to
	# CertMonitor)
	$self->{ITEMS} = ${$self->{CONFIG}->get_ref("certmonitor", 'ref')};
    }
    delete $self->{ITEMS}->{DEFAULT};

    return ($self);
}

sub getInstance() {
	unless(defined $INSTANCE) {
		my $proto = shift;
		my %args = (
			@_,	#argument pair list
		);
		$INSTANCE = CertNanny->new(%args);
	}
	
	return $INSTANCE;
}

sub DESTROY {
	# Windows apparently flushes file handles on close() and ignores autoflush...
	close STDOUT;
	close STDERR;
	$INSTANCE=undef;
}


sub AUTOLOAD
{
    my $self = shift;
    my $attr = $AUTOLOAD;
    $attr =~ s/.*:://;
    return if $attr eq 'DESTROY';   

    # automagically call
    if ($attr =~ /(?:info|check|renew|enroll)/) {
	return $self->iterate_entries("do_$attr");
    }

}

sub get_config_value
{
    my $self = shift;
    return $self->{CONFIG}->get(@_);
}

sub iterate_entries
{
    my $self = shift;
    my $action = shift;
    
    my $loglevel = $self->{CONFIG}->get('loglevel') || 3;

    my $rc = 1;
    foreach my $entry (keys %{$self->{ITEMS}}) {
	CertNanny::Logging->debug("Checking keystore $entry\n");
	my $keystore = 
	    CertNanny::Keystore->new(CONFIG => $self->{CONFIG},
				     ENTRY =>  $self->{ITEMS}->{$entry},
				     ENTRYNAME => $entry);
	if ($keystore) {
	    $self->$action(ENTRY => $entry,
			   KEYSTORE => $keystore);
	}
	else 
	{
		CertNanny::Logging->log({MSG => "Could not instantiate keystore $entry\n", PRIO => 'error'});
		if($action eq 'do_renew' or $action eq 'do_enroll'){
			CertNanny::Logging->log({MSG => "Check for initial enrollment configuration.", PRIO => 'info'});
			if ($self->{ITEMS}->{$entry}->{initialenroll}->{auth}){
				CertNanny::Logging->log({MSG => "Fund initial enrollment configuration for ". $self->{ITEMS}->{$entry}->{initialenroll}->{subject}, PRIO => 'info'});
					    $self->do_enroll(ENTRY => $self->{ITEMS}->{$entry} ,
					    				ENTRYNAME => $entry);		
			}
		}
	}
		print "\n\n";
    }

    return $rc;
}


sub do_info
{
    my $self = shift;
    my %args = ( @_ );

    my $keystore = $args{KEYSTORE};
    
    my $info = $keystore->getinfo("SubjectName", "NotAfter");
    print Dumper $info;

    return 1;
}


sub do_check
{
    my $self = shift;
    my %args = ( @_ );

    my $keystore = $args{KEYSTORE};
    $keystore->{CERT} = $keystore->{INSTANCE}->getcert(); 
    #CertNanny::Logging->debug(Dumper($keystore));

    my $autorenew = $self->{ITEMS}->{$args{ENTRY}}->{autorenew_days};
    my $warnexpiry = $self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days};
    
    my $rc;
   
    $keystore->{CERT} = $keystore->{INSTANCE}->getcert();
    $keystore->{CERT}->{INFO} = $keystore->getcertinfo(%{$keystore->{CERT}});
    $rc = $keystore->checkvalidity(0);
     
    #CertNanny::Logging->debug("Get cert: $rc : ". Dumper($keystore));
    if (! $rc) {
	CertNanny::Logging->log({MSG => "Certificate has expired. No automatic renewal can be performed.", PRIO => 'error'});
	return 1;
    }

    $rc = $keystore->checkvalidity($autorenew);
    if (! $rc) {
	CertNanny::Logging->log({MSG => "Certificate is to be scheduled for automatic renewal ($autorenew days prior to expiry)"});
    }
    $rc = $keystore->checkvalidity($warnexpiry);
    if (! $rc) {
	CertNanny::Logging->log({MSG => "Certificate is valid for less than $warnexpiry days",PRIO => 'notice'});
	$keystore->warnexpiry();
    }
    return 1;
}

sub do_enroll{
	my $self = shift;
	
    my %args = ( @_ );
    my $entry = $args{ENTRY};
    my $entryname = $args{ENTRYNAME};
    my $rc;
    my $autorenew = $self->{ITEMS}->{$args{ENTRY}}->{autorenew_days};
    my $warnexpiry = $self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days};
       
    CertNanny::Util::backoffTime( $self->{CONFIG} ); 
    
	if( $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'certificate'){			
		CertNanny::Logging->log({MSG => "Start initial enrollment with authentication method certificate.", PRIO => 'info'});
			
		my $keystore ;	    		   
		##Change keystore attributes to instantitae a openSSL keystore with the entrollment certificate
		$entry->{initialenroll}->{targetType}=  $entry->{type} ;  
		$entry->{type}= 'OpenSSL';    
		$entry->{location}= $entry->{initialenroll}->{auth}->{cert};      
		$entry->{format}= 'PEM';  
		$entry->{keyfile}= $entry->{initialenroll}->{auth}->{key};
		$entry->{pin} = $entry->{initialenroll}->{auth}->{pin};
		    	
		if(exists $self->{ITEMS}->{$entryname}->{hsm})
		{
			$self->{ITEMS}->{$entryname}->{hsm} = undef;
		}
		if(exists $self->{ITEMS}->{$entryname}->{certreqinf})
		{
			$self->{ITEMS}->{$entryname}->{certreqinf} = undef;
		}
		if(exists $self->{ITEMS}->{$entryname}->{certreq})
		{
			$self->{ITEMS}->{$entryname}->{certreq} = undef;
		}

		$keystore = 
	    		CertNanny::Keystore->new(CONFIG => $self->{CONFIG},
				     ENTRY =>  $self->{ITEMS}->{$entryname},
				     ENTRYNAME => $entryname);
			
			
		$keystore->{INSTANCE}->{INITIALENROLLEMNT} = 'yes'; 
		#disable engine specific configuration 
		$keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{engine_section} = undef; 
		$keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine} = undef; 
	
		#Start the initial enrollment runining an native openSSL keystore renewal 
		my $ret = $keystore->{INSTANCE}->renew();
	
		my $conf  =  CertNanny::Config->new($self->{CONFIG}->{CONFIGFILE});
			
		#reset the keystore configuration after the inital enrollment back to the .cfg file specified settings including engine 
		$self->{ITEMS}->{$entryname} = $conf->{CONFIG}->{certmonitor}->{$entryname}; 
			
		$conf->{CONFIG}->{INITIALENROLLEMNT} = 'yes'; 			
			
		my $newkeystore = 
	    		CertNanny::Keystore->new(CONFIG => $self->{CONFIG},
				     ENTRY =>  $self->{ITEMS}->{$entryname},
				     ENTRYNAME => $entryname);
				     
		$newkeystore->retrieve_state() or return;
				
		my $autorenew = $self->{ITEMS}->{$args{ENTRY}}->{autorenew_days};	     			
		my $renewalstate = $newkeystore->{INSTANCE}->{STATE}->{DATA}->{RENEWAL}->{STATUS};
		
			if($renewalstate eq 'sendrequest') {
					CertNanny::Logging->log({MSG => "Initial enrollment request send." , PRIO => 'info'});
				    # get previous renewal status
			    #$self->retrieve_state() or return;
			
			    # check if we can write to the file
			    $newkeystore->store_state() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
			}
			if($renewalstate eq 'completed') {
				my $isValid = $newkeystore->checkvalidity($autorenew);
				CertNanny::Logging->log({MSG => "Initial enrollment completed successfully. Onbehalf." , PRIO => 'info'});
				$newkeystore->store_state() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
			}
			
			return 1;
			
	}else{
		
		if($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'password' or
			$self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'anonymous'	
		){
			CertNanny::Logging->log({MSG => "Start initial enrollment with authentication method " . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} , PRIO => 'info'});
				
					
			##Change keystore attributes to instantitae a openSSL keystore with the entrollment certificate
		    $entry->{initialenroll}->{targetType}=  $entry->{type} ;  
		    $entry->{type}= 'OpenSSL';    
		    $self->{CONFIG}->{INITIALENROLLEMNT} = 'yes'; 			
	
			my $newkeystore = 
	   		CertNanny::Keystore->new(CONFIG => $self->{CONFIG},
			     ENTRY =>  $self->{ITEMS}->{$entryname},
			     ENTRYNAME => $entryname);
				     
			$newkeystore->retrieve_state() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
	
			     
			$newkeystore->{INSTANCE}->{INITIALENROLLEMNT} = 'yes';
				
			if($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'password'){
				if (! defined $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword}){
							
					CertNanny::Logging->log({MSG => 'Using commandline argument challangePassword for initial enrollment' , PRIO => 'debug'});
					if(exists $self->{globalchallengepassword} && $self->{globalchallengepassword} ne ''){
							$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword} = $self->{globalchallengepassword} ;				
			
					}	
				}
			}
												
			my $key = $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRYNAME} . "-key.pem";
    		my $keyfile = File::Spec->catfile($newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{statedir},$key);
    
    		      
			unless(-e $keyfile) {
				
			my $newkey = $newkeystore->{INSTANCE}->generatekey(); 	;
				 
			CertNanny::Logging->log({MSG => "keyfile $newkey->{KEYFILE} ,  " , PRIO => 'debug'}); 
		 	$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile} = $newkey->{KEYFILE} ;  
		 	CertNanny::Logging->log({MSG => "keyfile $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile} ,  " , PRIO => 'debug'});
	    	$newkeystore->{INSTANCE}->{ENTRY}->{format}= 'PEM';  
		
			}else{
				CertNanny::Logging->log({MSG => "Key already generated" , PRIO => 'debug'});
				#CertNanny::Logging->log({MSG => 'newkeystore with key : '.Dumper($newkeystore) , PRIO => 'debug'});
				 $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile} = $keyfile ; 
				 $entry->{keyfile}= $entry->{initialenroll}->{auth}->{key};
		 	  	 $entry->{pin} = $entry->{initialenroll}->{auth}->{pin};	
			    
			
			}	
				
			my $selfsigncert = $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRYNAME}."-selfcert.pem";
   			my $outCert = File::Spec->catfile($newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{statedir},$selfsigncert);
				
			unless(-e $outCert) {
					
				CertNanny::Logging->log({MSG => "Initial enrollment started, generate new selfsigned cert ", PRIO => 'debug'});
				my $newSelfsignCert= $newkeystore->{INSTANCE}->selfsign();
			   	#CertNanny::Logging->log({MSG => Dumper($newSelfsignCert) , PRIO => 'debug'});
			   	$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $newSelfsignCert->{CERT} ; 	 
			}else{
				$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $outCert ; 	 
			}
				
				
			$newkeystore->{CERT} = $newkeystore->{INSTANCE}->getcert();

			if (defined $newkeystore->{CERT}) {
				$newkeystore->{CERT}->{INFO} = $newkeystore->getcertinfo(%{$newkeystore->{CERT}});
				my $subjectname = $newkeystore->{CERT}->{INFO}->{SubjectName};
				my $serial = $newkeystore->{CERT}->{INFO}->{SerialNumber};
						my $issuer = $newkeystore->{CERT}->{INFO}->{IssuerName};
						CertNanny::Logging->debug("Certificate Information:\n\tSubjectName: $subjectname\n\tSerial: $serial\n\tIssuer: $issuer");
						
						my %convopts = %{$newkeystore->{CERT}};
						
						$convopts{OUTFORMAT} = 'PEM';
						$newkeystore->{CERT}->{RAW}->{PEM}  = $newkeystore->convertcert(%convopts)->{CERTDATA};
						$convopts{OUTFORMAT} = 'DER';
						$newkeystore->{CERT}->{RAW}->{DER}  = $newkeystore->convertcert(%convopts)->{CERTDATA};
			}else{
				CertNanny::Logging->error("Could not parse instance certificate");
					return;
			}
		
			$newkeystore->{INSTANCE}->setcert($newkeystore->{CERT});
						
			#disable engine specific configuration 
			$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile} = $keyfile ;  
			$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $outCert ; 			
			$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{engine_section} = undef; 
			$newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine} = undef; 
		
			#Start the initial enrollment runining an native openSSL keystore renewal 
			my $ret = $newkeystore->{INSTANCE}->renew();	
			
			my $renewalstate = $newkeystore->{INSTANCE}->{STATE}->{DATA}->{RENEWAL}->{STATUS};
					
			if(defined $renewalstate)
			{
							CertNanny::Logging->debug("renewalstate is ". $renewalstate);
			}
		
			if(defined $renewalstate and $renewalstate eq 'sendrequest') {
				CertNanny::Logging->log({MSG => "Initial enrollment request send." , PRIO => 'info'});
				$newkeystore->store_state() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";	
			}		
			

			if(!defined $renewalstate  ) {
				unlink  $selfsigncert;
				CertNanny::Logging->log({MSG => "Initial enrollment completed successfully. Mode:" .$self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} , PRIO => 'info'});				
			}
				 		
				return 1;			
		}else{
							
			CertNanny::Logging->log({MSG => "Initial enrollment authentication method ".$self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode}." not supported", PRIO => 'error'});			
		}
	}
	
#		my $keystore = $args{KEYSTORE};
#			$keystore->{INSTANCE}->renew();
#
#
#	    $rc = $keystore->checkvalidity($warnexpiry);
#	    if (! $rc) {
#		CertNanny::Logging->log({MSG => "Certificate is valid for less than $warnexpiry days",PRIO => 'notice'});
#		$keystore->warnexpiry();
#		
#		}
	
    return 1;
	
}

sub do_renew
{
    my $self = shift;
    my %args = ( @_ );

    my $keystore = $args{KEYSTORE};

    my $autorenew = $self->{ITEMS}->{$args{ENTRY}}->{autorenew_days};
    my $warnexpiry = $self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days};

    my $rc;

    $rc = $keystore->checkvalidity(0);
    if (! $rc) {
	CertNanny::Logging->log({MSG => "Certificate has expired. No automatic renewal can be performed.", PRIO => 'error'});
	return 1;
    }
    
    $rc = $keystore->checkvalidity($autorenew);
    if (! $rc) { 
    # schedule automatic renewal	

 	CertNanny::Util::backoffTime( $self->{CONFIG} );

	$keystore->{INSTANCE}->renew();
    }

    $rc = $keystore->checkvalidity($warnexpiry);
    if (! $rc) {
	CertNanny::Logging->log({MSG => "Certificate is valid for less than $warnexpiry days",PRIO => 'notice'});
	$keystore->warnexpiry();
    }
    return 1;
}

sub setOption {
    my $self = shift;
    my $key = shift;
    my $value = shift;
    
    $self->{$key} = $value;
    
    return 1;
}

1;
