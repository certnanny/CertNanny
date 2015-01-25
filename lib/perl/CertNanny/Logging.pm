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

use File::Basename;

use strict;
use warnings;
use English;
use utf8;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);

@EXPORT = qw(printerr printout 
             logLevel
             log2File log2Console log2SysLog LogOff
             err2File err2Console err2SysLog errOff
             log debug info notice error fatal);    # Symbols to autoexport (:DEFAULT tag)

my $INSTANCE;

my ($stdOutFake, $stdErrFake, @logBuffer, $logTarget, $errTarget);

my $dbgInfo = 1;
# 0: level, PID, text                         i.E.: 2013-09-13 15:58:26 : [info] [788] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 1: last detail w/o getInstance and Logging  i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 2: full details w/o getInstance and Logging i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 3: full details                             i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::getInstance(65)->CertNanny::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)->CertNanny::Logging::info(224)->CertNanny::Logging::log(168)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog

BEGIN {
  open($stdOutFake, ">&", STDOUT);
  open($stdErrFake, ">&", STDERR);
  $logTarget;  # DO NOT SET HERE! USE logOff, log2File(1|0), log2Console(1|0) INSTEAD
  $errTarget;  # DO NOT SET HERE! USE errOff, err2File(1|0), err2Console(1|0) INSTEAD
  # logTarget and errTarget are a bit-Vektor:
  # -1 not yet initialised
  # Bit 0 (1) : Logging to Console
  # Bit 1 (2) : Logging to File
  # ToDo: Logging to syslog
  # Bit 2 (4) : Logging to Syslog (to be implemented)
}

sub getInstance {
  $INSTANCE ||= (shift)->new(@_);

  # If Configuration is not present, we are still in initialisation phase
  if (!defined($INSTANCE->{CONFIG})) {
    shift;
    my %args = (@_);
    $logTarget = -1;
    $errTarget = -1;
    $INSTANCE->{CONFIG} = $args{CONFIG};
    if (defined $INSTANCE->{CONFIG}) {
      # only instantiate if $self->{CONFIG} exists.
      # otherwise initalisation phase is not yet finished
      # and we determine the loglevel

      # Determining Debug Level
      my $logLevel;
      # Prio 0: Default : 3
      $logLevel = 3;
      # Prio 1: If a config file value is given, take this
      if (defined($args{CONFIG}->get('log.level')))     {$logLevel = $args{CONFIG}->get('log.level')}
      # Prio 2: If a commandline parameter debug is given without value, take 4
      if (defined($args{debug}) && ($args{debug} == 0)) {$logLevel = 4}
      # Prio 3: If a commandline parameter debug is given with value, take the value of debug
      if (defined($args{debug}) && ($args{debug} != 0)) {$logLevel = $args{debug}}
      # Prio 4: If a commandline parameter verbose is given, take 6
      if (defined($args{verbose}))                      {$logLevel = 6} 
      $INSTANCE->logLevel($logLevel);

      # Determine Logtargets
      $INSTANCE->log2Console('STATUS', $args{CONFIG}->get('log.out.console'));
      $INSTANCE->log2File('STATUS', $args{CONFIG}->get('log.out.file') ne '');
      $INSTANCE->log2SysLog('STATUS', $args{CONFIG}->get('log.out.syslog') ne '');
      # Determine Errtargets
      $INSTANCE->err2Console('STATUS', $args{CONFIG}->get('log.err.console'));
      $INSTANCE->err2File('STATUS', $args{CONFIG}->get('log.err.file') ne '');
      $INSTANCE->err2SysLog('STATUS', $args{CONFIG}->get('log.err.syslog') ne '');
      if (defined($args{verbose})) {
        $INSTANCE->log2Console('STATUS', 1);
        $INSTANCE->err2Console('STATUS', 1);
      } 
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
  close STDOUT;
  close STDERR;
}


sub printerr {
  my $self = (shift)->getInstance();
  my $str = join('', @_);
  
  # Log to console
  if ($errTarget & 1) {
    $| = 1;
    open STDERR, ">&", $stdErrFake;
    print STDERR $str;
  }
  # Log to file
  if ($errTarget & 2) {
    $| = 1;
    my $file = $self->{CONFIG}->get('log.err.file', "FILE");
    open STDERR, ">>", $file || die "Could not redirect STDERR. Stopped";
    print STDERR $str;
  }
  # Log to syslog
  if ($errTarget & 4) {
  }
} ## end sub printerr


sub printout {
  my $self = (shift)->getInstance();
  my $str = join('', @_);
  
  # Log to console
  if ($logTarget & 1) {
    $| = 1;
    open STDOUT, ">&", $stdOutFake;
    print STDOUT $str;
  }
  # Log to file
  if ($logTarget & 2) {
    $| = 1;
    my $file = $self->{CONFIG}->get('log.out.file', "FILE");
    open STDOUT, ">>", $file || die "Could not redirect STDOUT. Stopped";
    print STDOUT $str;
  }
  # Log to syslog
  if ($logTarget & 4) {
  }

} ## end sub logLevel


sub logLevel {
  my $self = (shift)->getInstance();
  $self->{OPTIONS}->{LOGLEVEL} = shift if (@_);

  if (!defined $self->{OPTIONS}->{LOGLEVEL}) {
    return 3;
  }
  return $self->{OPTIONS}->{LOGLEVEL};
} ## end sub logLevel


sub errOff {
  my $self = (shift)->getInstance();

  if ($errTarget != 0) {
    $self->debug('Error Logging is disabled');
    $| = 1;
    open STDERR, ">", "/dev/null";
    $errTarget = 0;
  } ## end if ($errTarget != 0)

  return 1;
} ## end sub logOff


sub err2Console {
  my $self  = (shift)->getInstance();
  my %args = (STATUS => 0,
              @_);

  $errTarget = 1 if $errTarget == -1;
  my $status = $errTarget & 1;

  if ($args{STATUS}) {
    $errTarget |= 0b00000001;
  } else {
    $errTarget &= 0b11111110;
  }

  if ($status != ($errTarget & 1)) {
    if ($errTarget & 1) {
      $self->debug('Console Error Logging enabled');
    } else {
      $self->debug('Console Error Logging disabled');
    }
  }  
  
  return 1;
} ## end sub err2Console


sub err2File {
  my $self = (shift)->getInstance();
  my %args = (STATUS => 0,
              CLEAR  => undef,
              @_);

  $errTarget = 2 if $errTarget == -1;
  my $status = $errTarget & 2;

  if ($args{STATUS}) {
    $errTarget |= 0b00000010;
  } else {
    $errTarget &= 0b11111101;
  }

  my $file = $self->{CONFIG}->get('log.err.file', "FILE");
  my $filedir = dirname($file);
  eval {unlink $file} if $args{CLEAR};
  eval {mkdir($filedir)};
  if ($status != ($errTarget & 2)) {
    if ($errTarget & 1) {
      $self->debug("File Error Logging enabled to $file");
    } else {
      $self->debug('File Error Logging disabled');
    }
  }

  return 1;
} ## end sub err2File


sub err2SysLog {
  my $self  = (shift)->getInstance();
  my %args = (STATUS => 0,
              @_);

  $errTarget = 1 if $errTarget == -1;
  my $status = $errTarget & 4;

  if ($args{STATUS}) {
    $errTarget |= 0b00000100;
  } else {
    $errTarget &= 0b11111011;
  }

  if ($status != ($errTarget & 4)) {
    if ($errTarget & 4) {
      $self->debug('SysLog Error Logging enabled');
    } else {
      $self->debug('SysLog Error Logging disabled');
    }
  }  
  
  return 1;
} ## end sub err2SysLog


sub logOff {
  my $self = (shift)->getInstance();
  
  if ($logTarget != 0) {
    $self->debug('Logging is disabled');
    $| = 1;
    open STDOUT, ">", "/dev/null";
    $logTarget = 0;
  } ## end if ($logTarget != 0)
  
  return 1;
} ## end sub logOff


sub log2Console {
  my $self  = (shift)->getInstance();
  my %args = (STATUS => 0,
              @_);

  $logTarget = 1 if $logTarget == -1;
  my $status = $logTarget & 1;

  if ($args{STATUS}) {
    $logTarget |= 0b00000001;
  } else {
    $logTarget &= 0b11111110;
  }

  if ($status != ($logTarget & 1)) {
    if ($logTarget & 1) {
      $self->debug('Console Logging enabled');
    } else {
      $self->debug('Console Logging disabled');
    }
  }  
  
  return 1;
} ## end sub log2Console


sub log2File {
  my $self = (shift)->getInstance();
  my %args = (STATUS => 0,
              CLEAR  => undef,
              @_);

  $logTarget = 2 if $logTarget == -1;
  my $status = $logTarget & 2;

  if ($args{STATUS}) {
    $logTarget |= 0b00000010;
  } else {
    $logTarget &= 0b11111101;
  }

  my $file = $self->{CONFIG}->get('log.out.file', "FILE");
  my $filedir = dirname($file);
  eval {unlink $file} if $args{CLEAR};
  eval {mkdir($filedir)};
  if ($status != ($logTarget & 2)) {
    if ($logTarget & 1) {
      $self->debug("File Logging enabled to $file");
    } else {
      $self->debug('File Logging disabled');
    }
  }

  return 1;
} ## end sub log2File


sub log2SysLog {
  my $self  = (shift)->getInstance();
  my %args = (STATUS => 0,
              @_);

  $logTarget = 1 if $logTarget == -1;
  my $status = $logTarget & 4;

  if ($args{STATUS}) {
    $logTarget |= 0b00000100;
  } else {
    $logTarget &= 0b11111011;
  }

  if ($status != ($logTarget & 4)) {
    if ($logTarget & 4) {
      $self->debug('SysLog Logging enabled');
    } else {
      $self->debug('SysLog Logging disabled');
    }
  }  
  
  return 1;
} ## end sub log2SysLog


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

  push @logBuffer, "WARNING: log called with undefined priority '$prio'"
    unless exists $level{$prio};

  my $logStr = '';
  if ($level{$prio} <= $self->logLevel()) {
    (my $sec, my $min, my $hour, my $mday, my $mon, my $year, my $wday, my $yday, my $isdst) = localtime(time);
    $year = sprintf("%04d", $year + 1900);
    $mon  = sprintf("%02d", $mon + 1);
    $mday = sprintf("%02d", $mday);
    $hour = sprintf("%02d", $hour);
    $min  = sprintf("%02d", $min);
    $sec  = sprintf("%02d", $sec);

    my ($subroutine, $i, $line) = ('' ,'', 0, 0);
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
    push @logBuffer, $logStr;

    # call hook
    #$self->executehook($self->{INSTANCE}->{OPTIONS}->{ENTRY}->{hook}->{log},
    #			   '__PRIORITY__' => $prio,
    #			   '__MESSAGE__' => $arg->{MSG});
  } ## end if ($level{$prio} <= $self...)

  if ($logTarget >= 0) {   # Bereit
    while (@logBuffer) {
      $self->printerr(shift(@logBuffer));
    }
  }

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
