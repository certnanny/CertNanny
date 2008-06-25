#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
#
# DBCA::Util
#
# $Id$
#
# 2002-11-11 Martin Bartosch; Cynops GmbH <m.bartosch@cynops.de>
#

package CertNanny::Util;

use base qw(Exporter);

use strict;
use Time::Local;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;

$VERSION = 0.10;

@EXPORT      = qw(timestamp isodatetoepoch epochtoisodate addisodate printableisodate run_command system);       # Symbols to autoexport (:DEFAULT tag)

#sub system {
#	die "do not use system() in CertNanny, it is broken when CertNanny is used as a Windows service";
#}

sub run_command
{
	my $command = shift;
	
	open my $PROGRAM, "$command|" or die "could note execute $command";
	my $output = do {
		local $/;
		<$PROGRAM>;
	};
	close($PROGRAM);
	print $output;
	return $?;
}

# returns current time as ISO timestamp (UTC)
# format: yyyymmddhhmmss
sub timestamp
{
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) =
	gmtime(time);
    return sprintf("%04d%02d%02d%02d%02d%02d", 
		   $year + 1900,
		   $mon + 1,
		   $mday,
		   $hour,
		   $min,
		   $sec);
}


# convert ISO date to Unix timestamp (seconds since the Epoch)
# arg: ISO date (YYYYMMDDHHMMSS)
# return: Epoch (seconds) or undef on error
sub isodatetoepoch
{
    my $isodate = shift;

    return unless defined $isodate;

    if (my ($year, $mon, $mday, $hours, $min, $sec) = ($isodate =~ /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/))
    {
	$mon -= 1;
	$year -= 1900;
	return timegm($sec, $min, $hours, $mday, $mon, $year);
    }
    return;
}

# convert Unix Epoch to ISO Date
# arg: Epoch seconds
# return: ISO Date (YYYYMMDDHHMMSS)
sub epochtoisodate
{
    my $epoch = shift;
    my ($seconds, $minutes, $hours, $day_of_month, $month, $year,
	$wday, $yday, $isdst) = gmtime($epoch);
    return sprintf("%04d%02d%02d%02d%02d%02d", 
		   $year + 1900, 
		   $month + 1, 
		   $day_of_month,
		   $hours,
		   $minutes,
		   $seconds);
}



# expand time format controls (subset as specified by date(1))
# %y last two digits of year (00..99)
# %Y year (1970...)
# %m month (01..12)
# %d day of month (01..31)
# %H hour (00..23)
# %M minute (00..59)
# %S second (00..59)
sub expanddate
{
    my $arg = shift;

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
	localtime(time);

    $arg =~ s/%y/sprintf("%02d", ($year + 1900) % 100)/ge;
    $arg =~ s/%Y/$year + 1900/ge;
    $arg =~ s/%m/sprintf("%02d", $mon + 1)/ge;
    $arg =~ s/%d/sprintf("%02d", $mday)/ge;
    $arg =~ s/%H/sprintf("%02d", $hour)/ge;
    $arg =~ s/%M/sprintf("%02d", $min)/ge;
    $arg =~ s/%S/sprintf("%02d", $sec)/ge;

    $arg;
}


# return a printable represantation of a compacted ISO date
# arg: ISO Date, format YYYYMMDDHHMMSS
sub printableisodate
{
    my $arg = shift;
    my @date = ($arg =~ /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    sprintf("%04d-%02d-%02d %02d:%02d:%02d", @date);
}





1;
