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
             switchLogging
             switchFileLog switchConsoleLog switchSysLog logOff
             switchFileErr switchConsoleErr switchSysErr errOff
             log debug info notice error fatal);    # Symbols to autoexport (:DEFAULT tag)

my $INSTANCE;

my ($stdOutFake, $stdErrFake, @outBuffer, @errBuffer);
my %logTarget;

my $dbgInfo = 1;
# 0: level, PID, text                         i.E.: 2013-09-13 15:58:26 : [info] [788] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 1: last detail w/o getInstance and Logging  i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 2: full details w/o getInstance and Logging i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
# 3: full details                             i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::getInstance(65)->CertNanny::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)->CertNanny::Logging::info(224)->CertNanny::Logging::log(168)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog

BEGIN {
  open($stdOutFake, ">&", STDOUT);
  open($stdErrFake, ">&", STDERR);
  # logTarget and errTarget are a bit-Vektor:
  # -1 not yet initialised
  # Bit 0 (1) : Logging to Console
  # Bit 1 (2) : Logging to File
  # ToDo Logging to syslog
  # Bit 2 (4) : Logging to Syslog (to be implemented)
}


sub getInstance {
  $INSTANCE ||= (shift)->new(@_);

  # If Configuration is not present, we are still in initialisation phase
  if (!defined($INSTANCE->{CONFIG})) {
    shift;
    my %args = (@_);
    $INSTANCE->{CONFIG} = $args{CONFIG};
    if (defined $INSTANCE->{CONFIG}) {
      # only instantiate if $self->{CONFIG} exists.
      # otherwise initalisation phase is not yet finished
      # and we determine the loglevel

      # Determining Debug Level
      # Downward compatibility
      if (!defined($args{CONFIG}->get('log.level')))    {$args{CONFIG}->set('log.level',    $args{CONFIG}->get('loglevel'))}
      if (!defined($args{CONFIG}->get('log.out.file'))) {$args{CONFIG}->set('log.out.file', $args{CONFIG}->get('logfile'))}
      if (!defined($args{CONFIG}->get('log.err.file'))) {$args{CONFIG}->set('log.err.file', $args{CONFIG}->get('logfile'))}
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
      $INSTANCE->switchConsoleLog('STATUS', $args{CONFIG}->get('log.out.console'));
      $INSTANCE->switchFileLog   ('STATUS', $args{CONFIG}->get('log.out.file') ne '');
      $INSTANCE->switchSysLog    ('STATUS', $args{CONFIG}->get('log.out.syslog') ne '');
      # Determine Errtargets
      $INSTANCE->switchConsoleErr('STATUS', $args{CONFIG}->get('log.err.console'));
      $INSTANCE->switchFileErr   ('STATUS', $args{CONFIG}->get('log.err.file') ne '');
      $INSTANCE->switchSysErr    ('STATUS', $args{CONFIG}->get('log.err.syslog') ne '');
      if (defined($args{verbose})) {
        $INSTANCE->switchConsoleLog('STATUS', 1);
        $INSTANCE->switchConsoleErr('STATUS', 1);
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


sub _print {
  my $self   = (shift)->getInstance();
  my $target = shift;
  my $str    = join('', @_);
  
  my $myOut;
  my $myFile;
  my $buffer;
  if ($target eq 'Err') {
    $myOut  = $stdErrFake;
    $myFile = defined($self->{CONFIG}) ? $self->{CONFIG}->get('log.err.file', "FILE") :  undef;
    $buffer = \@errBuffer;
  } else {
    $myOut  = $stdOutFake;
    $myFile = defined($self->{CONFIG}) ? $self->{CONFIG}->get('log.out.file', "FILE") :  undef;
    $buffer = \@outBuffer;
  }
  push(@$buffer, $str);
  
  if ($logTarget{$target.'Console'} ||
     ($logTarget{$target.'File'} && defined($myFile)) ||
      $logTarget{$target.'SysLog'}) {
    while (@$buffer) {
      $str = shift(@$buffer);
      # Log to console
      if ($logTarget{$target.'Console'}) {
        $| = 1;
        open STDERR, ">&", $myOut;
        print STDERR $str;
      }
      # Log to file
      if ($logTarget{$target.'File'} && defined($myFile)) {
        $| = 1;
        open STDERR, ">>", $myFile || die "Could not redirect STDERR. Stopped";
        print STDERR $str;
      }
      # Log to syslog
      if ($logTarget{$target.'SysLog'}) {
      }
    }
  }
  return 1;
} ## end sub printerr


sub printerr {
  my $self = (shift)->getInstance();
  $self->_print('Err', @_);
  return 1;
} ## end sub printerr


sub printout {
  my $self = (shift)->getInstance();
  $self->_print('Log', @_);
  return 1;
} ## end sub logLevel


sub logLevel {
  my $self = (shift)->getInstance();
  $self->{OPTIONS}->{LOGLEVEL} = shift if (@_);

  if (!defined $self->{OPTIONS}->{LOGLEVEL}) {
    return 3;
  }
  return $self->{OPTIONS}->{LOGLEVEL};
} ## end sub logLevel


sub _Off {
  my $self = (shift)->getInstance();
  my $target = shift;

  if ($logTarget{$target.'Console'} != 0 ||
      $logTarget{$target.'File'}    != 0 ||
      $logTarget{$target.'SysLog'}  != 0) {
    $| = 1;
    if ($target eq 'Err') {
      $self->debug('Error Logging is disabled');
      open STDERR, ">", "/dev/null";
    } else {
      $self->debug('Logging is disabled');
      open STDOUT, ">", "/dev/null";
    }  
    $logTarget{$target.'Console'} = 0;
    $logTarget{$target.'File'}    = 0;
    $logTarget{$target.'SysLog'}  = 0;
  } ## end $logTarget{$target.'Cons ... 

  return 1;
} ## end sub _Off


sub errOff {
  my $self = (shift)->getInstance();
  $self->Off('Err');
  return 1;
} ## end sub logOff


sub logOff {
  my $self = (shift)->getInstance();
  $self->Off('Log');
  return 1;
} ## end sub logOff


sub switchLogging {
  my $self  = (shift)->getInstance();
  my %args = (STATUS => 0,
              @_);
              
  if ($args{STATUS}) {
    if (defined($args{FILE})) {
      eval {unlink $args{FILE}} if $args{CLEAR};
      eval {mkdir(dirname($args{FILE}))};
    }
    if (!$logTarget{$args{TARGET}}) {
      my $type   = substr($args{TARGET}, 0, 3);
      my $target = substr($args{TARGET}, 3);
      $type = ($type eq 'Err') ? 'Errorlogging to ' : 'Logging to ';
      $self->debug($type . $target . ' enabled')
    }
    $logTarget{$args{TARGET}} = 1;
  } else {
    if (defined($args{FILE})) {
      eval {unlink $args{FILE}} if $args{CLEAR};
    }
    if ($logTarget{$args{TARGET}})  {
      my $type   = substr($args{TARGET}, 0, 3);
      my $target = substr($args{TARGET}, 3);
      $type = ($type eq 'Err') ? 'Errorlogging to ' : 'Logging to ';
      $self->debug($type . $target . ' disabled')
    }
    $logTarget{$args{TARGET}} = 0;
  }

  return 1;
} ## end sub switchLogging


sub switchConsoleErr {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'ErrConsole',
                       'STATUS', !$logTarget{'ErrConsole'},
                       'MESSAGE', 'Console Error Logging',
                       @_);
  return 1;
} ## end sub switchConsoleErr


sub switchFileErr {
  my $self = (shift)->getInstance();
  $self->switchLogging('TARGET', 'ErrFile',
                       'STATUS', !$logTarget{'ErrFile'},
                       'MESSAGE', "File Error Logging to " . $self->{CONFIG}->get('log.err.file'),
                       'FILE'   , $self->{CONFIG}->get('log.err.file', "FILE"),
                       'CLEAR',  undef,
                       @_);
  return 1;
} ## end sub switchFileErr


sub switchSysErr {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'ErrSysLog',
                       'STATUS', !$logTarget{'ErrSysLog'},
                       'MESSAGE', 'SysLog Error Logging',
                       @_);
  return 1;
} ## end sub switchSysErr


sub switchConsoleLog {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'LogConsole',
                       'STATUS', !$logTarget{'LogConsole'},
                       'MESSAGE', 'Console Logging',
                       @_);
  return 1;
} ## end sub switchConsoleLog


sub switchFileLog {
  my $self = (shift)->getInstance();
  $self->switchLogging('TARGET', 'LogFile',
                       'STATUS', !$logTarget{'LogFile'},
                       'MESSAGE', "File Logging to " . $self->{CONFIG}->get('log.err.file'),
                       'FILE'   , $self->{CONFIG}->get('log.log.file', "FILE"),
                       'CLEAR',  undef,
                       @_);
  return 1;
} ## end sub switchFileLog


sub switchSysLog {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'LogSysLog',
                       'STATUS', !$logTarget{'LogSysLog'},
                       'MESSAGE', 'SysLog Logging',
                       @_);
  return 1;
} ## end sub switchSysLog


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

  push @outBuffer, "WARNING: log called with undefined priority '$prio'"
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
    $self->printerr($logStr);

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
