#TODO package CertNanny::Logging mehr kommentieren
#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-04 Stefan Kraus <stefan.kraus05@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Logging;

#use base qw(Exporter);

use Data::Dumper;
use FindBin qw($Script);
use Carp;

use strict;
use warnings;
use English;
use utf8;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);

$VERSION = 0.10;

@EXPORT = qw(logLevel log2File log2Console LogOff 
             log debug info notice error fatal);    # Symbols to autoexport (:DEFAULT tag)

my $INSTANCE;

my ($stdOutFake, $stdErrFake, @logBuffer, $logTarget);

my $dbgInfo = 1;
# 0: level, PID, text                         i.E.: 2013-09-13 15:58:26 : [info] [788] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 1: last detail w/o getInstance and Logging  i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 2: full details w/o getInstance and Logging i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 3: full details                             i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::getInstance(65)->CertNanny::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)->CertNanny::Logging::info(224)->CertNanny::Logging::log(168)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog

BEGIN {
  open($stdOutFake, ">&", STDOUT);
  open($stdErrFake, ">&", STDERR);
  $logTarget;  # 0: Off   1: Console   2: File  #  DO NOT SET HERE! USE logOff, log2File, log2Console INSTEAD
}

sub getInstance {
  $INSTANCE ||= (shift)->new(@_);

  # If Configuration is not present, we are still in initialisation phase
  if (!defined($INSTANCE->{CONFIG})) {
    shift;
    my %args = (@_);
    $logTarget = -1;
    $INSTANCE->{CONFIG} = $args{CONFIG};
    if (defined $INSTANCE->{CONFIG}) {
      # only instantiate if $self->{CONFIG} exists.
      # otherwise initalisation phase is not yet finished
      $INSTANCE->logLevel($args{CONFIG}->get('loglevel') || 3);
    }
  }
  return $INSTANCE;
}


sub new {
  if (!defined $INSTANCE) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = (@_);    # argument pair list

    my $self = {};
    bless $self, $class;
    $INSTANCE = $self;
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  my $self = shift;

  return undef unless (exists $self->{TMPFILE});
  foreach my $file (@{$self->{TMPFILE}}) {
    unlink $file;
  }
}


sub logLevel {
  my $self = (shift)->getInstance();
  $self->{OPTIONS}->{LOGLEVEL} = shift if (@_);

  if (!defined $self->{OPTIONS}->{LOGLEVEL}) {
    return 3;
  }
  return $self->{OPTIONS}->{LOGLEVEL};
} ## end sub logLevel


sub logOff {
  my $self = (shift)->getInstance();
  
  if ($logTarget != 0) {
    $self->debug('Logging is disabled');
    $| = 1;
    open STDOUT, ">", "/dev/null";
    open STDERR, ">", "/dev/null";
    $logTarget = 0;
  } ## end if ($logTarget != 0)
  
  return 1;
} ## end sub logOff


sub log2Console {
  my $self = (shift)->getInstance();
  
  if ($logTarget != 1) {
    $self->debug('Logging is redirected to console');
    $| = 1;
    open STDOUT, ">&", $stdOutFake;
    open STDERR, ">&", $stdErrFake;
    $logTarget = 1;
  } ## end if ($logTarget != 1)
  
  return 1;
} ## end sub log2Console


sub log2File {
  my $self = (shift)->getInstance();

  if ($logTarget != 2) {
    if (my $file = $self->{CONFIG}->get("logfile", "FILE")) {
      $self->debug('Logging is redirected to ' . $self->{CONFIG}->get('logfile'));

      #TODO sub logFile Fehlerbehandlung
      #write alle messages into a file
      $| = 1;
      open STDOUT, ">>", $file || die "Could not redirect STDOUT. Stopped";
      open STDERR, ">>", $file || die "Could not redirect STDERR. Stopped";
    } ## end if ($self->{CONFIG}->get...)
    $logTarget = 2;
  } ## end if ($logTarget != 2)

  return 1;
} ## end sub log2File


sub log {
  my $self = (shift)->getInstance();
  my $arg  = shift;

  confess "Not a hash ref" unless (ref($arg) eq "HASH");
  return undef unless (defined $arg->{MSG});
  my $prio = lc($arg->{PRIO} || "info");

  my %level = ('debug'  => 4,
               'info'   => 3,
               'notice' => 2,
               'error'  => 1,
               'fatal'  => 0);

  print STDERR "WARNING: log called with undefined priority '$prio'"
    unless exists $level{$prio};
  if ($level{$prio} <= $self->logLevel()) {

    # fallback to STDERR
    #TODO sub log wieder rueckgaengig machen
    (my $sec, my $min, my $hour, my $mday, my $mon, my $year, my $wday, my $yday, my $isdst) = localtime(time);
    $year = sprintf("%04d", $year + 1900);
    $mon  = sprintf("%02d", $mon + 1);
    $mday = sprintf("%02d", $mday);
    $hour = sprintf("%02d", $hour);
    $min  = sprintf("%02d", $min);
    $sec  = sprintf("%02d", $sec);

    my ($logStr, $subroutine, $i, $line) = ('' ,'', 0, 0);
    while (defined(caller($i))) {
      $logStr = (caller($i))[3];
      $line = $line ? (caller($i-1))[2] : __LINE__;
      $i++;
      if ($dbgInfo > 0) {
        if ((($dbgInfo <= 2) && ($logStr !~ /getInstance|Logging/)) || ($dbgInfo >= 3)) {
          if ($dbgInfo == 1) {
            $subroutine = "$logStr($line)" if (!$subroutine);  
          } else {
            $subroutine = $subroutine ? "$logStr($line)->$subroutine" : "$logStr($line)";  
          }
        }
      }
    }
 #   if (!utf8::is_utf8($arg->{MSG}) and ($arg->{MSG} !~ m/\A [[:ascii:]]* \Z/xms)) {
 #    $arg->{MSG} = '---Binary Data---';
 #  }
    if ($subroutine) {
      $logStr = "$year-$mon-$mday $hour:$min:$sec : [$prio] [$$] [$subroutine] $arg->{MSG}\n";
    } else {
      $logStr = "$year-$mon-$mday $hour:$min:$sec : [$prio] [$$] $arg->{MSG}\n";
    }

    if ($logTarget >= 0) {   # Bereit
      while (@logBuffer) {
        print STDERR shift(@logBuffer);
      }
      print STDERR $logStr;
    } else {                         # Noch nicht bereit
      push @logBuffer, $logStr;
    }

    # call hook
    #$self->executehook($self->{INSTANCE}->{OPTIONS}->{ENTRY}->{hook}->{log},
    #			   '__PRIORITY__' => $prio,
    #			   '__MESSAGE__' => $arg->{MSG});
  } ## end if ($level{$prio} <= $self...)
  return 1;
} ## end sub log


sub debug {
  my $self = (shift)->getInstance();
  my $arg  = join(' ', @_);

  $self->log({MSG  => $arg,
              PRIO => 'debug'});
  
  return 0
} ## end sub debug


sub info {
  my $self = (shift)->getInstance();
  my $arg  = join(' ', @_);

  $self->log({MSG  => $arg,
              PRIO => 'info'});
  
  return 0
} ## end sub info


sub notice {
  my $self = (shift)->getInstance();
  my $arg  = join(' ', @_);

  $self->log({MSG  => $arg,
              PRIO => 'notice'});
  
  return 0
} ## end sub notice


sub error {
  my $self = (shift)->getInstance();
  my $arg  = join(' ', @_);
  
  $self->log({MSG  => $arg,
              PRIO => 'error'});
  
  return 1
} ## end sub error


sub fatal {
  my $self = (shift)->getInstance();
  my $arg  = join(' ', @_);

  $self->log({MSG  => $arg,
              PRIO => 'fatal'});
  
  return 1
} ## end sub fatal


1;
