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
use Sys::Syslog qw(:standard :macros);

use strict;
use warnings;
use English;
use utf8;

use CertNanny::Util;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);

@EXPORT = qw(Out Err
             logLevel
             switchLogging
             switchFileOut switchConsoleOut switchSysLogOut outOff
             switchFileErr switchConsoleErr switchSysLogErr errOff
             log debug info notice error emergency);    # Symbols to autoexport (:DEFAULT tag)

my $INSTANCE;

my ($stdOutFake, $stdErrFake, @outBuffer, @errBuffer);
my %logTarget;
my %logTargetOpen;
my $dbgInfo;
my $bufferOut;

BEGIN {
  open($stdOutFake, ">&", STDOUT);
  open($stdErrFake, ">&", STDERR);
  $dbgInfo = 1;
  $bufferOut = 1;
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
      if (!defined($args{CONFIG}->get('log.out.file'))) {$args{CONFIG}->set('log.out.file', $args{CONFIG}->get('logfile'))}
      if (!defined($args{CONFIG}->get('log.err.file'))) {$args{CONFIG}->set('log.err.file', $args{CONFIG}->get('logfile'))}
      
      foreach my $target ('console', 'file', 'syslog') {
        # Downward compatibility
        if (!defined($args{CONFIG}->get('log.level.'.$target))) {$args{CONFIG}->set('log.level.'.$target, $args{CONFIG}->get('loglevel'))}

        # Debug Level is determined in 5 Steps (highest Prio wins)
        # Prio 0: Default : 3
        my $logLevel = 3;
        # Prio 1: If a config file value is given, take this
        if (defined($args{CONFIG}->get('log.level.'.$target))) {$logLevel = $args{CONFIG}->get('log.level.'.$target)}
        if (defined($args{debug})) {
          my $debug = lc($args{debug});
          if ($debug eq '') {
            # Prio 2: If a commandline parameter debug is given without value, take 4
            $logLevel = 4
          } else {
            # Prio 3: If a commandline parameter debug is given with value, take the value of debug
            # Commandline format:
            #   Option 1: # : Take the given Level for console, file and syslog
            if ($debug =~/^\d$/) {
              $logLevel = $args{debug}
            }
            if ($debug =~/^([cfs]\d){1,3}$/) {
              my %debugLevel = split(//, $debug);
              $logLevel = $debugLevel{substr($target, 0, 1)} if defined($debugLevel{substr($target, 0, 1)});
            }
          }
        }
        # Prio 4: If a commandline parameter verbose is given, take 6
        if (defined($args{verbose})) {$logLevel = 6} 

        # set Loglevel
        $INSTANCE->logLevel('TARGET', $target, 'LEVEL', $logLevel);
      }
      
      # Decide how to handle SysLog Messages
      foreach my $target ('out', 'err') {
        if (defined($args{CONFIG}->get("log.${target}.syslog")) && ($args{CONFIG}->get("log.${target}.syslog") ne '')) {
          my @syslog = split(/ /, $args{CONFIG}->get("log.${target}.syslog"));
          $INSTANCE->{OPTIONS}->{SYSLOG}->{$target}->{IDENTIFIER} = (defined($syslog[0])) ? $syslog[0] : '';
          $INSTANCE->{OPTIONS}->{SYSLOG}->{$target}->{FACILITIES} = (defined($syslog[2])) ? $syslog[2] : 3;
          $INSTANCE->{OPTIONS}->{SYSLOG}->{$target}->{OPTIONS}    = (defined($syslog[1])) ? $syslog[1] : '';
        } else {
          $INSTANCE->{OPTIONS}->{SYSLOG}->{$target}->{IDENTIFIER} = '';
        }
      }

      # Determine Logtargets
      $INSTANCE->switchFileOut   ('STATUS', defined($args{CONFIG}->get('log.out.file')) && ($args{CONFIG}->get('log.out.file') ne ''));
      $INSTANCE->switchConsoleOut('STATUS', $args{CONFIG}->get('log.out.console'));
      $INSTANCE->switchSysLogOut ('STATUS', defined($args{CONFIG}->get('log.out.syslog')) && ($args{CONFIG}->get('log.out.syslog') ne ''));
      # Determine Errtargets
      $INSTANCE->switchFileErr   ('STATUS', defined($args{CONFIG}->get('log.err.file')) && ($args{CONFIG}->get('log.err.file') ne ''));
      $INSTANCE->switchConsoleErr('STATUS', $args{CONFIG}->get('log.err.console'));
      $INSTANCE->switchSysLogErr ('STATUS', defined($args{CONFIG}->get('log.err.syslog')) && ($args{CONFIG}->get('log.err.syslog') ne ''));
      if (defined($args{verbose})) {
        $INSTANCE->switchConsoleOut('STATUS', 1);
        $INSTANCE->switchConsoleErr('STATUS', 1);
      }
      # Now we know, what to do with Logs and it's no more buffering needed
      $bufferOut = 0;

      # Determining Debug Details
      # 0: level, PID, text                         i.E.: 2013-09-13 15:58:26 : [info] [788] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      # 1: last detail w/o getInstance and Logging  i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      # 2: full details w/o getInstance and Logging i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      # 3: full details                             i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::getInstance(65)->CertNanny::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)->CertNanny::Logging::info(224)->CertNanny::Logging::log(168)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      $dbgInfo = 1;
      if (defined($args{CONFIG}->get('log.detail'))) {$dbgInfo = $args{CONFIG}->get('log.detail')}
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
    $self->setVariable('NAME',  'KEYSTORE', 
                       'VALUE', 'Common');
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  my $self = shift;

  $self->Err();
  $self->Out();
  return undef unless (exists $self->{TMPFILE});
  foreach my $file (@{$self->{TMPFILE}}) {unlink $file}
  close STDOUT;
  close STDERR;
}


sub logLevel {
  my $self = (shift)->getInstance();
  my %args = ('TARGET', 'console',
              @_);
              
  $self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}} = $args{LEVEL} if defined($args{LEVEL});

  if (!defined($self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}})) {
    $self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}} = 3;
  }
  return $self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}};
} ## end sub logLevel


sub Off {
  my $self = (shift)->getInstance();
  my $target = shift;

  if ($logTarget{$target.'console'} != 0 ||
      $logTarget{$target.'file'}    != 0 ||
      $logTarget{$target.'syslog'}  != 0) {
    $| = 1;
    if ($target eq 'err') {
      $self->debug('MSG', 'Error Logging is disabled');
      close STDERR;
      open STDERR, ">", "/dev/null";
    } else {
      $self->debug('MSG', 'Logging is disabled');
      close STDOUT;
      open STDOUT, ">", "/dev/null";
    }  
    $logTarget{$target.'console'} = 0;
    $logTarget{$target.'file'}    = 0;
    $logTarget{$target.'syslog'}  = 0;
  } ## end $logTarget{$target.'Cons ... 

  return 1;
} ## end sub _Off


sub errOff {
  my $self = (shift)->getInstance();
  $self->_Off('err');
  return 1;
} ## end sub errOff


sub outOff {
  my $self = (shift)->getInstance();
  $self->_Off('out');
  return 1;
} ## end sub outOff


sub switchLogging {
  my $self  = (shift)->getInstance();
  my %args = (STATUS => 0,
              @_);
              
  my $type   = substr($args{TARGET}, 0, 3);
  my $target = substr($args{TARGET}, 3);
  if ($args{STATUS}) {
    if (defined($args{FILE})) {
      eval {unlink $args{FILE}} if $args{CLEAR};
      eval {mkdir(dirname($args{FILE}))};
      $target .= ":$args{FILE}";
    }
    if (defined($args{FILELAST})) {
      eval {unlink $args{FILELAST}} if $args{CLEAR};
      eval {mkdir(dirname($args{FILELAST}))};
      $target .= " (last):$args{FILELAST}";
    }
    if (!$logTarget{$args{TARGET}}) {
      $type = ($type eq 'err') ? 'Errorlogging to ' : 'Logging to ';
      $self->debug('MSG', $type . $target . ' enabled')
    }
    $logTarget{$args{TARGET}} = 1;
  } else {
    if (defined($args{FILE})) {
      eval {unlink $args{FILE}} if $args{CLEAR};
      $target .= ": $args{FILE}";
    }
    if (defined($args{FILELAST})) {
      eval {unlink $args{FILELAST}} if $args{CLEAR};
      $target .= " (last): $args{FILELAST}";
    }
    if ($logTarget{$args{TARGET}})  {
      $type = ($type eq 'err') ? 'Errorlogging to ' : 'Logging to ';
      $self->debug('MSG', $type . $target . ' disabled')
    }
    $logTarget{$args{TARGET}} = 0;
  }

  return 1;
} ## end sub switchLogging


sub switchConsoleErr {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'errconsole',
                       'STATUS', !$logTarget{'errconsole'},
                       @_);
  return 1;
} ## end sub switchConsoleErr


sub switchFileErr {
  my $self = (shift)->getInstance();
  $self->switchLogging('TARGET',   'errfile',
                       'STATUS',   !$logTarget{'errfile'},
                       'FILE',     $self->{CONFIG}->get('log.err.file', "FILE"),
                       'FILELAST', $self->{CONFIG}->get('log.err.filelast', "FILE"),
                       'CLEAR',    undef,
                       @_);
  return 1;
} ## end sub switchFileErr


sub switchSysLogErr {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'errsyslog',
                       'STATUS', !$logTarget{'errsyslog'},
                       @_);
  return 1;
} ## end sub switchSysLogErr


sub switchConsoleOut {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'outconsole',
                       'STATUS', !$logTarget{'outconsole'},
                       @_);
  return 1;
} ## end sub switchConsoleOut


sub switchFileOut {
  my $self = (shift)->getInstance();
  $self->switchLogging('TARGET',   'outfile',
                       'STATUS',   !$logTarget{'outfile'},
                       'FILE',     $self->{CONFIG}->get('log.out.file', "FILE"),
                       'FILELAST', $self->{CONFIG}->get('log.out.filelast', "FILE"),
                       'CLEAR',    undef,
                       @_);
  return 1;
} ## end sub switchFileOut


sub switchSysLogOut {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'outsyslog',
                       'STATUS', !$logTarget{'outsyslog'},
                       @_);
  return 1;
} ## end sub switchSysLogOut


sub _print {
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $target    = $args{TARGET};
  my $str       = $args{STR};
  my $dbg       = 0;
  # SYSLOG:ERROR my $dbg       = 3;
  my $buffer;
  
  my $myFile     = defined($self->{CONFIG}) ? CertNanny::Util->expandStr($self->{CONFIG}->get('log.'.lc($target).'.file', "FILE"), %args)     :  undef;
  my $myLastFile = defined($self->{CONFIG}) ? CertNanny::Util->expandStr($self->{CONFIG}->get('log.'.lc($target).'.filelast', "FILE"), %args) :  undef;

  my $fileTarget     = $logTarget{$target.'file'} && defined($args{PRIO}) && defined($myFile) && ($myFile ne '');
  my $lastFileTarget = $logTarget{$target.'file'} && defined($args{PRIO}) && defined($myLastFile) && ($myLastFile ne '');
  my $consoleTarget  = $logTarget{$target.'console'};
  my $sysLogTarget   = $logTarget{$target.'syslog'} && defined($args{PRIO}) && ($self->{OPTIONS}->{SYSLOG}->{$target}->{IDENTIFIER} ne '');
  
  my %level = ('emergency' => 0,
  #              'alert'     => 1,
  #              'critical'  => 2,
                'error'     => 1,
  #              'warning'   => 4,
                'notice'    => 2,
                'info'      => 3,
                'debug'     => 4);

  # SYSLOG Levels
  # my %level = ('emergency' => 0,
  #              'alert'     => 1,
  #              'critical'  => 2,
  #              'error'     => 3,
  #              'warning'   => 4,
  #              'notice'    => 5,
  #              'info'      => 6,
  #              'debug'     => 7);

  if ($target eq 'out') {
    $buffer = \@outBuffer;
    if (defined($args{PRIO})) {
      my $prio = lc($args{PRIO} || "info");

      if (exists $level{$prio}) {
        $dbg = $level{$prio};
      } else {
        push @$buffer, "${dbg}:WARNING: log called with undefined priority '$prio'" unless exists $level{$prio};
      }
    }
  }

  if ($target eq 'err') {
    $buffer     = \@errBuffer;
  }
  
  push(@$buffer, "${dbg}:${str}");
  
  if ($bufferOut) {
    if ($args{FLUSH}) {
      # DESTROY Mode => Flush Buffer no matter where STD* points to
      while (@$buffer) {
        $str = shift(@$buffer);
        if ($str =~ /^([^:]):(.*)$/s) {
          $dbg = $1;
          $str = $2;
        }
        print STDOUT $str if ($target eq 'out');
        print STDERR $str if ($target eq 'err');
      }
    }
  } else {
    while (@$buffer) {
      $str = shift(@$buffer);
      if ($str =~ /^([^:]):(.*)$/s) {
        $dbg = $1;
        $str = $2;
      }
      # Log to file
      if ($fileTarget && ($target eq 'err') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        $| = 1;
        open STDERR, ">>", $myFile || die "Could not redirect STDERR to <$myFile>. Stopped";
        print STDERR $str;
        close STDERR;
      }
      if ($fileTarget && ($target eq 'out') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        open STDOUT, ">>", $myFile || die "Could not redirect STDOUT to <$myFile>. Stopped";
        print STDOUT $str;
        close STDOUT;
      }
      
      #Log to LastFile
      if ($lastFileTarget && ($target eq 'err') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        $| = 1;
        if (!$logTargetOpen{$myLastFile}) {
          open STDERR, ">", $myLastFile || die "Could not redirect STDERR to <$myLastFile>. Stopped";
          $logTargetOpen{$myLastFile} = 1;
        } else {
          open STDERR, ">>", $myLastFile || die "Could not redirect STDERR to <$myLastFile>. Stopped";
        }
        print STDERR $str;
        close STDERR;
      }
      if ($lastFileTarget && ($target eq 'out') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        $| = 1;
        if (!$logTargetOpen{$myLastFile}) {
          open STDOUT, ">", $myLastFile || die "Could not redirect STDOUT. Stopped";
          $logTargetOpen{$myLastFile} = 1;
        } else {
          open STDOUT, ">>", $myLastFile || die "Could not redirect STDOUT. Stopped";
        }
        print STDOUT $str;
        close STDOUT;
      }
      
      # Log to console
      if ($consoleTarget && ($target eq 'err') && ($dbg <= $self->logLevel('TARGET', 'console'))) {
        $| = 1;
        open STDERR, ">&", $stdErrFake;
        print STDERR $str;
        close STDERR;
      }
      if ($consoleTarget && ($target eq 'out') && ($dbg <= $self->logLevel('TARGET', 'console'))) {
        $| = 1;
        open STDOUT, ">&", $stdOutFake;
        print STDOUT $str;
        close STDOUT;
      }
      
      # Log to syslog
      if ($sysLogTarget && ($dbg <= $self->logLevel('TARGET', 'syslog'))) {
        my $syslogIdentifier = CertNanny::Util->expandStr($self->{OPTIONS}->{SYSLOG}->{$target}->{IDENTIFIER});
        my $syslogOptions    = $self->{OPTIONS}->{SYSLOG}->{$target}->{OPTIONS};
        my $syslogFacilities = $self->{OPTIONS}->{SYSLOG}->{$target}->{FACILITIES};
        if ($syslogIdentifier ne '') {
          Sys::Syslog::openlog($syslogIdentifier, $syslogOptions, $syslogFacilities);
          Sys::Syslog::syslog($dbg, "%s", $str);
          Sys::Syslog::closelog();
        }
      }
    }
  }
  return 1;
} ## end sub _print


sub _log {
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $logStr = '';
  if (defined($args{PRIO})) {
    # confess "Not a hash ref" unless (ref($arg) eq "HASH");
    return undef unless (defined $args{MSG});
    my ($subroutine, $i, $line) = ('', 0, 0);
    # It's a debug, notice, etc. message, so we add a timestamp, etc.
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
    $subroutine = "[$subroutine] " if ($subroutine);
    $logStr = CertNanny::Util->expandStr("__YEAR__-__MONTH__-__DAY__ __HOUR__:__MINUTE__:__SECOND__ : [__PRIO__] [__PID__] __SUB____MSG__\n", 
                                         '__PRIO__', lc($args{PRIO} || "info"),
                                         '__SUB__',  $subroutine,
                                         '__MSG__',  $args{MSG});
  } else {
    # It's a normal output message, so we just make an expandStr
    $logStr = defined($args{MSG}) ? CertNanny::Util->expandStr($args{MSG}) : defined($args{STR}) ? $args{STR} : '';
  }
  
  $self->_print('STR', $logStr,
                %args);

  return 1;
} ## end sub _log


sub Out {
  my $self = (shift)->getInstance();
  my %args = (@_);
  
  if (!defined($args{STR}) && !defined($args{MSG})) {
    # Call by Destroy => Flush outBuffer
    $args{FLUSH} = 1;
  }
  $self->_log('TARGET', 'out', 
              %args);

  return 1;
} ## end sub log


sub Err {
  my $self = (shift)->getInstance();
  my %args = (@_);
  
  if (!defined($args{STR}) || defined($args{MSG})) {
    # Call by Destroy => Flush outBuffer
    $args{FLUSH} = 1;
  }
  $self->_log('TARGET', 'err', 
              'PRIO',   0,
              %args);

  return 1;
} ## end sub log


# SYSLOG Levels 
sub emergency {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->Out('PRIO', 'emergency', 
             %args);
  
  return 0
} ## end sub emergancy


#sub alert {
#  my $self = (shift)->getInstance();
#  my %args = (@_);
#
#  $self->Out('PRIO', 'alert', 
#             %args);
#  
#  return 0
#} ## end sub alert


#sub critical {
#  my $self = (shift)->getInstance();
#  my %args = (@_);
#
#  $self->Out('PRIO', 'critical', 
#             %args);
#  
#  return 0
#} ## end sub critical


sub error {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->Out('PRIO', 'error', 
             %args);
  
  return 0
} ## end sub error


#sub warning {
#  my $self = (shift)->getInstance();
#  my %args = (@_);
#
#  $self->Out('PRIO', 'warning', 
#             %args);
#  
#  return 0
#} ## end sub warning


sub notice {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->Out('PRIO', 'notice', 
             %args);
  
  return 0
} ## end sub notice


sub info {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->Out('PRIO', 'info', 
             %args);
  
  return 0
} ## end sub info


sub debug {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->Out('PRIO', 'debug', 
             %args);
  
  return 0
} ## end sub debug


1;
