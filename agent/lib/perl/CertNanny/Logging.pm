#TODO mehr kommentieren
#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-04 Stefan Kraus <stefan.kraus@db.com; stefan.kraus05@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Logging;

#use base qw(Exporter);

use Data::Dumper;
use Carp;

use CertNanny::Util;

use strict;
use warnings;
use English;

use vars qw( $VERSION );

$VERSION = 0.10;

my $singletonObject;

# constructor parameters:
# CONFIG - Config object
# LOGGING - Logging object
sub new {
	if ( !defined $singletonObject ) {
		my $proto = shift;
		my $class = ref($proto) || $proto;
		my %args  = (
			@_,    # argument pair list
		);

		my $self = {};
		bless $self, $class;
		$singletonObject = $self;
		$self->{CONFIG} = $args{CONFIG};

		$self->loglevel( $args{CONFIG}->get('loglevel') || 3 );

		$self->redirect_stdout_stderr();
		$self->log(
			{
				MSG  => "Logging succesfully redirected to file",
				PRIO => 'debug'
			}
		);

		$singletonObject = $self;
		return ($self);
	}
	else {
		return $singletonObject;
	}
}

sub instance {
	$singletonObject ||= (shift)->new();
}

sub DESTROY {
	my $self = shift;

	return unless ( exists $self->{TMPFILE} );
	foreach my $file ( @{ $self->{TMPFILE} } ) {
		unlink $file;
	}
}

sub loglevel {
	my $self = (shift)->instance();
	$self->{OPTIONS}->{LOGLEVEL} = shift if (@_);

	if ( !defined $self->{OPTIONS}->{LOGLEVEL} ) {
		return 3;
	}
	return $self->{OPTIONS}->{LOGLEVEL};
}

sub redirect_stdout_stderr {
	my $self = (shift)->instance();

	if ( $self->{CONFIG}->get( "logfile", "FILE" ) ) {
		print 'Logging is redirected to '
		  . $self->{CONFIG}->get('logfile') . "\n";

		#TODO Fehlerbehandlung
		#write alle messages into a file
		my $file = $self->{CONFIG}->get( "logfile", "FILE" );
		$| = 1;
		open STDOUT, ">>", $file || die "Could not redirect STDOUT. Stopped";
		open STDERR, ">>", $file || die "Could not redirect STDERR. Stopped";
	}

	return 1;
}

sub log {
	my $self = (shift)->instance();
	my $arg  = shift;
	confess "Not a hash ref" unless ( ref($arg) eq "HASH" );
	return unless ( defined $arg->{MSG} );
	my $prio = lc( $arg->{PRIO} || "info" );

	my %level = (
		'debug'  => 4,
		'info'   => 3,
		'notice' => 2,
		'error'  => 1,
		'fatal'  => 0
	);

	print STDERR "WARNING: log called with undefined priority '$prio'"
	  unless exists $level{$prio};
	if ( $level{$prio} <= $self->loglevel() ) {

		# fallback to STDERR
		#TODO wieder rückgängig machen
		(my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst ) = localtime(time);
		$year =sprintf("%04d", $year + 1900);
		$mon =sprintf("%02d", $mon + 1);
		$mday =sprintf("%02d", $mday);
		$hour=sprintf("%02d",$hour);
		$min=sprintf("%02d",$min);
		$sec=sprintf("%02d",$sec);
		 
		print STDERR "$year-$mon-$mday $hour:$min:$sec : [$prio] $arg->{MSG} \n";

	   # call hook
	   #$self->executehook($self->{INSTANCE}->{OPTIONS}->{ENTRY}->{hook}->{log},
	   #			   '__PRIORITY__' => $prio,
	   #			   '__MESSAGE__' => $arg->{MSG});
	}
	return 1;
}

sub debug {
	my $self = (shift)->instance();
	my $arg  = shift;

	#    if (exists $self->{DEBUG} and $self->{DEBUG}) {
	$self->log(
		{
			MSG  => $arg,
			PRIO => 'debug'
		}
	);

	#    }
}

sub info {
	my $self = (shift)->instance();
	my $arg  = shift;

	$self->log(
		{
			MSG  => $arg,
			PRIO => 'info'
		}
	);
}

# set error message
# arg: error message
# message is also logged with priority ERROR
sub error {
	my $self = (shift)->instance();
	my $arg  = shift;
	$self->log(
		{
			MSG  => $arg,
			PRIO => 'error'
		}
	);
}

1;
