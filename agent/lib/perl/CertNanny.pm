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
use Data::Dumper;

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

    $self->{CONFIG} = CertNanny::Config->new($args{CONFIG});
    return unless defined $self->{CONFIG};
    if($self->{CONFIG}->get("logfile", "FILE"))
    {
       #TODO Fehlerbehandlung
       #write alle messages into a file 
       my $file = $self->{CONFIG}->get("logfile", "FILE");
       open STDOUT, "> $file";
       open STDERR, ">&STDOUT";
       $|=1;
    }
    # set default library path
    my @dirs = File::Spec->splitdir($FindBin::Bin);
    pop @dirs;
    if (!$self->{CONFIG}->get("path.lib", "FILE")) {
	$self->{CONFIG}->set("path.lib", File::Spec->catdir(@dirs, 'lib'));
    }
    
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


sub AUTOLOAD
{
    my $self = shift;
    my $attr = $AUTOLOAD;
    $attr =~ s/.*:://;
    return if $attr eq 'DESTROY';   

    # automagically call
    if ($attr =~ /(?:info|check|renew)/) {
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
	print "LOG: [info] Checking keystore $entry\n" if ($loglevel >= 3);
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
	    print "LOG: [error] Could not instantiate keystore $entry\n" if ($loglevel >= 1);
	}
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

    my $autorenew = $self->{ITEMS}->{$args{ENTRY}}->{autorenew_days};
    my $warnexpiry = $self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days};
    
    my $rc = $keystore->checkvalidity($autorenew);
    if (! $rc) {
	$keystore->log({MSG => "Certificate is to be scheduled for automatic renewal ($autorenew days prior to expiry)"});
    }
    $rc = $keystore->checkvalidity($warnexpiry);
    if (! $rc) {
	$keystore->log({MSG => "Certificate is valid for less than $warnexpiry days",PRIO => 'notice'});
	$keystore->warnexpiry();
    }
    return 1;
}


sub do_renew
{
    my $self = shift;
    my %args = ( @_ );

    my $keystore = $args{KEYSTORE};

    my $autorenew = $self->{ITEMS}->{$args{ENTRY}}->{autorenew_days};
    my $warnexpiry = $self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days};
    
    my $rc = $keystore->checkvalidity($autorenew);
    if (! $rc) {
	# schedule automatic renewal
	$keystore->log({MSG => "Scheduling renewal"});
	$keystore->{INSTANCE}->renew();
    }

    $rc = $keystore->checkvalidity($warnexpiry);
    if (! $rc) {
	$keystore->log({MSG => "Certificate is valid for less than $warnexpiry days",PRIO => 'notice'});
	$keystore->warnexpiry();
    }
}




1;
