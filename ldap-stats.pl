#!/usr/bin/env perl
#
# Program: Generate LDAP Statistics Reports <ldap-stats.pl>
#
# Source code home: http://prefetch.net/code/ldap-stats.pl
#
# Author: Matty < matty91 @ gmail dot com >
# Author: LDAP Tool Box project
# Author: David Coutadeur <david.coutadeur@gmail.com>
#
# Current Version: 7
#
# Revision History:
#
#  Version 7
#  - add option (--log26) for new openldap 2.6 log format compatibility (#27)
#
#  Version 6
#  - Choose syslog date format
#
#  Version 5.2
#  Perl::Tidy and Perl::Critic -- Gavin Henry, Suretec Systems Ltd.
#
#  Version 5.1
#  - Changed the location of the uc() statement -- Quanah Gibson-Mount
#
#  Version 5.0
#  - Changed reporting structure to be dynamic -- Quanah Gibson-Mount
#  - Fixed a bug with name resolution -- Quanah Gibson-Mount
#  - Added the URL to the script -- Quanah Gibson-Mount
#
#  Version 4.2
#  - Utilize strict mode --  Peter Schober
#
#  Version 4.1
#  - Fixed a typo in the length() function -- Peter Schober
#
#  Version 4.0
#  - Added "-d" option to print all days
#  - Fixed day sort order
#  - Added "-m" option to print all months
#  - Fixed month sort order
#  - Correct spelling. -- Dave Horsfall
#  - Align headings. -- Dave Horsfall
#  - Support ldapi:// connections ("LOCAL-SOCKET"). -- Dave Horsfall
#  - Only do lookup if numeric IP. -- Dave Horsfall
#
#  Version 3.0 - 3.4
#  - Added ability to resolve IP addresses to hostnames with "-n" option
#  - Adjusted print() routines to limit lines to 80-characters -- Dave Horsfall
#  - Clean up unnecessary (..) in regexes -- Peter Marschall
#  - Split attributes found in searches (controlled by new option -s) -- Peter Marschall
#  - Added report to print which filters are used
#  - Added report to print explicit attributes requested -- Francis Swasey
#  - Fix usage: correct line break, all lines < 80 chars -- Peter Marschall
#  - Replace unnecessary printf() by print -- Peter Marschall
#  - Concatenate arguments into one call to print instead of multiple calls -- Peter Marschall
#  - Adapt underlining of some headers to length of logfile / date -- Peter Marschall
#  - Added additional checks to address missing entries during logfile rotation
#  - Fixed "uninitialized value in hash element" -- Todd Lyons
#  - Added additional comments to code
#  - Added report for operations by time of day
#  - Added report for operations per day
#  - Added report for operations per month
#  - Removed debug statements to speedup logfile processing
#  - Changed printf() format specifiers to match column definitions
#
#  Version 2.0 - 2.2
#  - Adjusted the Search base comparison to catch ""
#  - Translate "" to RootDSE in the search base results
#  - Only print "Unindexed attribute" if unindexed attributes exist
#  - Normalize the bind DN and search base to avoid duplicates
#  - Fix typo with binddn array
#  - Improved filter for anonymous and authenticated binds -- Peter Marschall
#  - Logfiles are now passed as arguments to ldap-stats.pl
#    (e.g, ldap-stats.pl openldap1 openldap2 openldap3 old* ) -- Peter Marschall
#  - Cleaned up and combined filters for ADDs, MODs, DELs -- Peter Marschall
#  - Added support for CMPs & MODRDNs -- Peter Marschall
#  - Reduced number of regular expressions to one per filter -- Peter Marschall
#  - Removed head and tail program requirements, as dates are read on the fly from the
#    decoded logfile -- Peter Marschall
#  - Support for gzip and bzip2 compressed files  -- Peter Marschall
#  - Optimized some expressions -- Peter Marschall
#  - Removed several Perl warnings, and added "-w" to default runtime options -- Peter Marschall
#  - Support for regular expressions in logfile names (e.g., ldap-stats.pl /var/log/openldap* ) -- Peter Marschall
#  - Changed default Perl interpreter to /usr/bin/perl
#  - Changed to OpenLDAP license
#
#  Version 1.1 - 1.9
#  - Updated the bind, binddn, search, search base, and unindexed search regexs to
#    match a wider array of characters -- added by Peter Marschall
#  - Shortened several regular expressions by replacing "[0-9]" with "\d" -- added by Peter Marschall
#  - Fixed a divide by zero bug when logfiles contain 0 connections  -- added by  Dave Horsfall
#  - Removed unnecessary file open(s)
#  - Removed end of line ($) character from anonymous BIND regular expressions
#  - Added "-l" option to print lines as they are processed from a logfile
#  - Updated documentation
#  - Updated formatting of search dn report
#  - Updated formatting of search base report
#  - Added an additional report with the number of binds per DN
#  - Updated examples
#  - Added additional debug messages to connection setup
#  - Fixed documentation issues
#  - Added debugging flag (-d) to give detailed information on logfile processing
#  - Added "usage" subroutine to ease option maintenance
#  - Fixed a bug in the BIND calculations -- found and fixed by Quanah Gibson-Mount
#  - Fixed a bug in the MOD calculations -- found and fixed by Quanah Gibson-Mount
#  - Fixed a bug in the SRCH calculations -- found and fixed by Quanah Gibson-Mount
#  - Added a connection associative array to coorelate conn identifiers w/hosts -- Quanah Gibson-Mount
#  - Updated the usage message with information on "-c" option
#  - The "-f" option now accepts multiple logfiles
#  - Changed the headers to include information on all logfiles processed
#  - Added the day the report was run to the report headers
#
#  Version 1.0
#   Original release
#
# Last Updated: 21-02-2022
#
# Purpose:
#   Produces numerous reports from OpenLDAP 2.1, 2.2, 2.3, 2.4, 2.5 and 2.6 logfiles.
#
# License:
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted only as authorized by the OpenLDAP
#  Public License.
#
#  A copy of this license is available in the file LICENSE in the
#  top-level directory of the distribution or, alternatively, at
#  <http://www.OpenLDAP.org/license.html>.
#
# Installation:
#   1. Enable a minimum of 'loglevel 256' in the slapd.conf configuration file.
#   2. Copy the shell script to a suitable location.
#   3. Refer to the usage section for options and examples.
#
# Usage:
#   Refer to the usage subroutine,
#
# Example:
#   Refer to http://prefetch.net/code/ldap-stats.pl.txt to see sample output

use strict;
use warnings;
use Getopt::Long;
use Socket;
use Carp;
use 5.006;    # As returned by Perl::MinimumVersion

#######################
### usage subroutine
### Parameters: None
#######################
sub usage {
    print
"Usage: ldap-stats.pl [ -s ] [ -c <count> ] [ -l <count> ] [ -h ] <logfile> ...\n"
      . "   -c <count>             Number of lines to display for each report [25]\n"
      . "   -d                     Display all available days in the day of month report\n"
      . "   -h                     Display a usage help screen\n"
      . "   -l <count>             Print status message after processing <count> lines [0]\n"
      . "   -m                     Display all available months in the month of year report\n"
      . "   -n                     Resolve IP addresses to hostnames\n"
      . "   -o <ops> -o <ops> ...  Operations to print in the reports [ALL]\n"
      . "                          Valid operations are: CONNECT, FAILURES, BIND, UNBIND,\n"
      . "                          SRCH, CMP, ADD, MOD, MODRDN, DEL\n"
      . "                          Predefined reports are: ALL, READ, WRITE\n"
      . "   -s                     Split attributes found used in searches\n"
      . "   -D                     Use RFC5424 date format\n"
      . "   --log26                Use OpenLDAP 2.6 log format\n";
    return;
}

### Declare lexical variables
my ( $logfile, $i, $counter, $help );
my ( %unindexed, %search, @operations );

### Allow the number of entries displayed to be variable
my $count = 25;

### Figure out if we need to print "Processing X lines"
my $increment = 0;

## tell whether to split attributes in searches
my $splitattrs = 0;

# Tell whether to lookup names
my $resolvename = 0;

# Print all months
my $printmonths = 0;

# Print all days
my $printdays = 0;

# Use RFC5242 date format
my $dateformat = 0;

# Use OpenLDAP 2.6 log format
my $log26 = 0;

# Maximum number of greater qtimes to display
my $max_qtimes = 10;

# Maximum number of greater etimes to display
my $max_etimes = 10;

###################################
#### Get some options from the user
###################################
#getopts("o:l:c:nhsmd", \%options);

GetOptions(
    'count|c=i'      => \$count,
    'days|d'         => \$printdays,
    'dateformat|D'   => \$dateformat,
    'help|h'         => \$help,
    'length|l=i'     => \$increment,
    'months|m'       => \$printmonths,
    'network|n'      => \$resolvename,
    'operations|o=s' => \@operations,
    'split|s'        => \$splitattrs,
    'log26'          => \$log26,
);

### print a nice usage message
if ($help) {
    usage;
    exit 1;
}

### Make sure there is at least one logfile
if ( !@ARGV ) {
    usage;
    exit 1;
}

############################
### Define various variables
############################
my $date = localtime time;

if ( !@operations ) {
    @operations = ('ALL');
}

my %stats = (
    TOTAL_CONNECT      => 0,
    TOTAL_BIND         => 0,
    TOTAL_UNBIND       => 0,
    TOTAL_SRCH         => 0,
    TOTAL_DEL          => 0,
    TOTAL_ADD          => 0,
    TOTAL_CMP          => 0,
    TOTAL_MOD          => 0,
    TOTAL_MODRDN       => 0,
    TOTAL_UNINDEXED    => 0,
    TOTAL_AUTHFAILURES => 0,
);

my %hours;               # Hash to store the time of day (e.g., 21st of August)
my %days;                # Hash to store the days of each month (e.g., 21st)
my %months;              # Hash to store the day of the month (e.g., Dec)
my %hosts;               # Hash to store client IP addresses
my %conns;               # Hash to store connection identifiers
my %binddns;             # Hash to store bind DNs
my %logarray;            # Hash to store logfiles
my %filters;             # Hash to store search filters
my %searchattributes;    # Hash to store specific attributes that are requested
my %operations;          # Hash to store operations information
my %qtimes;              # Hash to store qtimes { conn,op => qtime,... }
my %etimes;              # Hash to store etimes { conn,op => etime,... }
my %ops;                 # Hash to store operations { conn,op => operation,... }

$operations{CONNECT} = {
    DATA    => 0,
    STRING  => '  Connect',
    SPACING => ' --------',
    FIELD   => '%8s',
};

$operations{FAILURES} = {
    DATA    => 0,
    STRING  => ' Failed',
    SPACING => ' ------',
    FIELD   => '%6s',
};

$operations{BIND} = {
    DATA    => 0,
    STRING  => '    Bind',
    SPACING => ' -------',
    FIELD   => '%7s',
};

$operations{UNBIND} = {
    DATA    => 0,
    STRING  => '  Unbind',
    SPACING => ' -------',
    FIELD   => '%7s',
};

$operations{SRCH} = {
    DATA    => 0,
    STRING  => '   Search',
    SPACING => ' --------',
    FIELD   => '%8s',
};

$operations{ADD} = {
    DATA    => 0,
    STRING  => '   Add',
    SPACING => ' -----',
    FIELD   => '%5s',
};

$operations{CMP} = {
    DATA    => 0,
    STRING  => '   Cmp',
    SPACING => ' -----',
    FIELD   => '%5s',
};

$operations{MOD} = {
    DATA    => 0,
    STRING  => '   Mod',
    SPACING => ' -----',
    FIELD   => '%5s',
};

$operations{MODRDN} = {
    DATA    => 0,
    STRING  => ' ModRDN',
    SPACING => ' ------',
    FIELD   => '%6s',
};

$operations{DEL} = {
    DATA    => 0,
    STRING  => '  Del',
    SPACING => ' ----',
    FIELD   => '%4s',
};

my $dateregexp_full;
my $dateregexp_split;

# RFC 5424 format
if ($dateformat) {
    $dateregexp_full  = '(\d+-\d+-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)';
    $dateregexp_split = '\d+-(\d+)-(\d+)T(\d+):(\d+):(\d+)\.\d+\+\d+:\d+';
}
# standard OpenLDAP 2.4/2.5 log format
else {
    $dateregexp_full  = '(\w+\s+\d+\s+\d+:\d+:\d+)';
    $dateregexp_split = '(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)';
}
# standard 2.6 log format
if($log26) {
    $dateregexp_full  = '([0-9a-h]{8}\.[0-9a-h]{8})';
    $dateregexp_split = '([0-9a-h]{8})\.([0-9a-h]{8})';
}

# Function extracting month, day and hour from given log line
sub getTimeComponents
{
    my $line = shift;
    my ( $month, $day, $hour ) = ( "undef", "undef", "undef" );
    if( $log26 )
    {
        if( $line =~ /^$dateregexp_split.*$/m )
        {
            # compute time components
            my $ts = hex("0x".$1); # number of second since epoch
            my $tn = hex("0x".$2); # number of nanoseconds
            my $completedate = scalar localtime $ts;
            ( $month, $day, $hour ) = $completedate =~ /^\w+\s+(\w+)\s+(\d+)\s+(\d+):/m;
        }
    }
    else
    {
        if( $line =~ /^$dateregexp_split.*$/m )
        {
            # return direct matched time components
            ( $month, $day, $hour ) = ( $1, $2, $3 );
        }
    }

    return ( $month, $day, $hour );
}

# Function extracting full date from given log line
sub getFullDate
{
    my $line = shift;
    my ( $month, $day, $hour, $min, $sec );
    my $fulldate = "";

    if( $log26 )
    {
        if ( $line =~ /^$dateregexp_split/m ) {
            # compute time components
            my $ts = hex("0x".$1); # number of second since epoch
            my $tn = hex("0x".$2); # number of nanoseconds
            my $completedate = scalar localtime $ts;
            ( $month, $day, $hour, $min, $sec ) =
                $completedate =~ /^\w+\s+(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)/m;

            $fulldate = "$month $day $hour:$min:$sec.".$tn;
        }
    }
    else
    {
        if ( $line =~ /^$dateregexp_full/m ) {
            $fulldate = $1;
        }
    }
    return $fulldate;
}

# Function that store the operation lines with correct format
sub storeOp
{
    my $connop = shift;
    my $line = shift;

    if($ops{"$connop"})
    {
        $ops{"$1,$2"} .= "                  $line";
    }
    else
    {
        $ops{"$1,$2"} .= "$line";
    }
}


###################################################
### Open the logfile and process all of the entries
###################################################
for my $file (@ARGV) {
    $logfile = $file;
    my $lines = 0;

    ### find open filter to use
    my $openfilter = '<' . $logfile . q{};

    ### decode gzipped / bzip2-compressed files
    if ( $logfile =~ /\.bz2$/mx ) {
        $openfilter = q{bzip2 -dc "} . $logfile . q{"|}
          or carp "Problem decompressing!: $!\n";
    }

    if ( $logfile =~ /\.(gz|Z)$/mx ) {
        $openfilter = q{gzip -dc "} . $logfile . q{"|}
          or carp "Problem decompressing!: $!\n";
    }

    ### If the logfile isn't valid, move on to the next one
    if ( !open LOGFILE, $openfilter ) {
        print "ERROR: unable to open '$logfile': $!\n";
        next;
    }

    ### setup the arrray to hold the start/stop times
    $logarray{$logfile} = {
        SDATE => q{},
        EDATE => q{},
    };

    ### Only print banner if requested
    if ( $increment > 0 ) {
        ### Print a banner and initialize the $counter variable
        print "\nProcessing file \"$logfile\"\n"
          . q{-} x ( 18 + length ${$logfile} ) . "\n";
        $counter = 0;
        $lines   = $increment;
    }

    while ( my $line = <LOGFILE> ) {

        my $fulldate = getFullDate($line);

        ### check start and end dates
        if ( $line =~ /^$dateregexp_full/mx ) {
            if ( !$logarray{$logfile}{SDATE} ) {
                $logarray{$logfile}{SDATE} = $fulldate;
            }
            $logarray{$logfile}{EDATE} = $fulldate;
        }

        ### Check to see if we have processed $lines lines
        if ( ( $lines > 0 ) && ( $counter == $lines ) ) {
            print "  Processed $lines lines in \"$logfile\"\n";
            $lines += $increment;
        }

        my ( $month, $day, $hour ) = getTimeComponents($line);

        ### Check for a new connection
        if ( $line =~
/conn=(\d+) [ ] fd=\d+ [ ] (?:ACCEPT|connection) [ ] from/mx
           )
        {
            my $conn  = $1;
            my $host;

            if ( $line =~ /IP=(\d+\.\d+\.\d+\.\d+):/mx ) {
                $host = $1;
            }
            elsif ( $line =~ /PATH=(\S+)/mx ) {
                $host = 'LOCAL-SOCKET';
            }
            else {
                $host = 'UNKNOWN';
            }

            ### Create an array to store the list of hosts
            if ( !( defined $hosts{$host} ) ) {
                $hosts{$host} = {
                    CONNECT      => 1,
                    AUTHFAILURES => 0,
                    BIND         => 0,
                    UNBIND       => 0,
                    SRCH         => 0,
                    ADD          => 0,
                    CMP          => 0,
                    MOD          => 0,
                    MODRDN       => 0,
                    DEL          => 0,
                };
            }
            else {
                ### Entry exists, increment the CONNECT value
                $hosts{$host}{CONNECT}++;
            }

            ### Create an array to store the hours
            if ( !( defined $hours{$hour} ) ) {
                $hours{$hour} = {
                    CONNECT      => 1,
                    AUTHFAILURES => 0,
                    BIND         => 0,
                    UNBIND       => 0,
                    SRCH         => 0,
                    ADD          => 0,
                    CMP          => 0,
                    MOD          => 0,
                    MODRDN       => 0,
                    DEL          => 0,
                };
            }
            else {
                ### Entry exists, increment the CONNECT value
                $hours{$hour}{CONNECT}++;
            }

            ### Create an array to store the months
            if ( !( defined $months{$month} ) ) {
                $months{$month} = {
                    CONNECT      => 1,
                    AUTHFAILURES => 0,
                    BIND         => 0,
                    UNBIND       => 0,
                    SRCH         => 0,
                    ADD          => 0,
                    CMP          => 0,
                    MOD          => 0,
                    MODRDN       => 0,
                    DEL          => 0,
                };
            }
            else {
                ### Entry exists, increment the CONNECT value
                $months{$month}{CONNECT}++;
            }

            ### Create an array to store the days
            if ( !( defined $days{$day} ) ) {
                $days{$day} = {
                    CONNECT      => 1,
                    AUTHFAILURES => 0,
                    BIND         => 0,
                    UNBIND       => 0,
                    SRCH         => 0,
                    ADD          => 0,
                    CMP          => 0,
                    MOD          => 0,
                    MODRDN       => 0,
                    DEL          => 0,
                };
            }
            else {
                ### Entry exists, increment the CONNECT value
                $days{$day}{CONNECT}++;
            }

            ### Add the host to the connection table
            $conns{$conn} = $host;

            ### Increment the total number of connections
            $stats{TOTAL_CONNECT}++;

            ### Check for anonymous binds
        }
        elsif ( $line =~
/conn=(\d+)  [ ] op=(\d+) [ ] BIND [ ] dn="" [ ] method=128/mx
          )
        {
            my $conn  = $1;
            storeOp("$1,$2","$line");

            ### Increment the counters
            if (   defined $conns{$conn}
                && defined $hosts{ $conns{$conn} } )
            {
                $hosts{ $conns{$conn} }{BIND}++;
                $hours{$hour}{BIND}++;
                $days{$day}{BIND}++;
                $months{$month}{BIND}++;
                $stats{TOTAL_BIND}++;
            }

            ### Add the binddn to the binddns array
            $binddns{anonymous}++;

            ### Check for non-anonymous binds
        }
        elsif ( $line =~
/conn=(\d+) [ ] op=(\d+) [ ] BIND [ ] dn="([^"]+)" [ ] mech=/mx
          )
        {
            my $conn   = $1;
            storeOp("$1,$2","$line");
            my $binddn = lc $$;

            ### Increment the counters
            if (   defined $conns{$conn}
                && defined $hosts{ $conns{$conn} } )
            {
                $hosts{ $conns{$conn} }{BIND}++;
                $hours{$hour}{BIND}++;
                $days{$day}{BIND}++;
                $months{$month}{BIND}++;
                $stats{TOTAL_BIND}++;
            }

            ### Add the binddn to the binddns array
            $binddns{$binddn}++;

            ### Check the search base
        }
        elsif ( $line =~
/\bconn=(\d+) [ ] op=(\d+) [ ] SRCH [ ] base="([^"]*?)" [ ] .*filter="([^"]*?)"/mx
          )
        {
            my $base   = lc $3;
            storeOp("$1,$2","$line");
            my $filter = $4;

            ### Stuff the search base into an array
            if ( defined $base ) {
                $search{$base}++;
            }

            if ( defined $filter ) {
                $filters{$filter}++;
            }

            ### Check for search attributes
        }
        elsif ( $line =~ /\bconn=(\d+) [ ] op=(\d+) [ ] SRCH [ ] attr=(.+)/mx ) {
            storeOp("$1,$2","$line");
            my $attrs = lc $3;

            if ($splitattrs) {
                for my $attr ( split q{ }, $attrs ) {
                    $searchattributes{$attr}++;
                }
            }
            else {
                $searchattributes{$attrs}++;
            }

            ### Check for SEARCHES
        }
        elsif ( $line =~
            /conn=(\d+) [ ] op=(\d+) [ ] SEARCH [ ] RESULT [ ] .*qtime=([\d.]+) .* etime=([\d.]+)/mx
          )
        {
            my $conn  = $1;
            my $op    = $2;
            storeOp("$1,$2","$line");
            my $qtime = $3;
            $qtime =~ tr/\.//d; # remove . => microsecond format
            my $etime = $4;
            $etime =~ tr/\.//d; # remove . => microsecond format
            $qtimes{"$conn,$op"} = $qtime;
            $etimes{"$conn,$op"} = $etime;

            ### Increment the counters
            if (   defined $conns{$conn}
                && defined $hosts{ $conns{$conn} } )
            {
                $hosts{ $conns{$conn} }{SRCH}++;
                $hours{$hour}{SRCH}++;
                $days{$day}{SRCH}++;
                $months{$month}{SRCH}++;
                $stats{TOTAL_SRCH}++;
            }

            ### Check for unbinds
        }
        elsif (
            $line =~ /conn=(\d+) [ ] op=(\d+) [ ] UNBIND/mx )
        {
            my $conn  = $1;
            storeOp("$1,$2","$line");

            ### Increment the counters
            if (   defined $conns{$conn}
                && defined $hosts{ $conns{$conn} } )
            {
                $hosts{ $conns{$conn} }{UNBIND}++;
                $hours{$hour}{UNBIND}++;
                $days{$day}{UNBIND}++;
                $months{$month}{UNBIND}++;
                $stats{TOTAL_UNBIND}++;
            }

            ### Check the result of the last operation
            ### TODO: Add other err=X values from contrib/ldapc++/src/LDAPResult.h
        }
        elsif ( $line =~
/conn=(\d+) [ ] op=(\d+)(?: SEARCH)? [ ] RESULT [ ] .*qtime=([\d.]+) .* etime=([\d.]+)/mx
          )
        {
            my $conn  = $1;
            my $op    = $2;
            storeOp("$1,$2","$line");
            my $qtime = $3;
            $qtime =~ tr/\.//d; # remove . => microsecond format
            my $etime = $4;
            $etime =~ tr/\.//d; # remove . => microsecond format
            $qtimes{"$conn,$op"} = $qtime;
            $etimes{"$conn,$op"} = $etime;

            if ( $line =~ /\berr=49\b/mx ) {
                ### Increment the counters
                if (   defined $conns{$conn}
                    && defined $hosts{ $conns{$conn} } )
                {
                    $hosts{ $conns{$conn} }{AUTHFAILURES}++;
                    $hours{$hour}{AUTHFAILURES}++;
                    $days{$day}{AUTHFAILURES}++;
                    $months{$month}{AUTHFAILURES}++;
                    $stats{TOTAL_AUTHFAILURES}++;
                }
            }

            ### Check for entry changes: add, modify modrdn, delete
        }
        elsif ( $line =~
/conn=(\d+) [ ] op=(\d+) [ ] (ADD|CMP|MOD|MODRDN|DEL) [ ] dn=/mx
          )
        {
            my $conn  = $1;
            storeOp("$1,$2","$line");
            my $type  = $3;

            ### Increment the counters
            if (   defined $conns{$conn}
                && defined $hosts{ $conns{$conn} } )
            {
                $hosts{ $conns{$conn} }{$type}++;
                $hours{$hour}{$type}++;
                $days{$day}{$type}++;
                $months{$month}{$type}++;
                $stats{ 'TOTAL_' . $type }++;
            }

            ### Check for unindexed searches
        }
        elsif ( $line =~
            /: [ ] \(([a-zA-Z0-9\;\-]+)\) [ ] index_param [ ] failed/mx )
        {
            my $attr = $1;

            $unindexed{$attr}++;
            $stats{TOTAL_UNINDEXED}++;
        }
        $counter++;
    }
    close LOGFILE;
}

###################################################################
### Print a nice header with the logfiles and date ranges processed
###################################################################
## Please see file perltidy.ERR
print "\n\n"
  . "Report Generated on $date\n"
  . q{-} x ( 20 + length $date ) . "\n";

for my $logfile ( sort keys %logarray ) {
    if ( !-z $logfile ) {
        printf "Processed \"$logfile\":  %s - %s\n", $logarray{$logfile}{SDATE},
          $logarray{$logfile}{EDATE};
    }
    else {
        printf "Processed \"$logfile\":  no data\n";
    }
}

#######################################
### Print an overall report with totals
#######################################

my $total_operations =
  $stats{TOTAL_BIND} +
  $stats{TOTAL_UNBIND} +
  $stats{TOTAL_SRCH} +
  $stats{TOTAL_MOD} +
  $stats{TOTAL_ADD} +
  $stats{TOTAL_MODRDN} +
  $stats{TOTAL_DEL};

print "\n\n" . "Operation totals\n" . "----------------\n";
printf "Total operations              : %d\n", $total_operations;
printf "Total connections             : %d\n", $stats{TOTAL_CONNECT};
printf "Total authentication failures : %d\n", $stats{TOTAL_AUTHFAILURES};
printf "Total binds                   : %d\n", $stats{TOTAL_BIND};
printf "Total unbinds                 : %d\n", $stats{TOTAL_UNBIND};
printf "Total searches                : %d\n", $stats{TOTAL_SRCH};
printf "Total compares                : %d\n", $stats{TOTAL_CMP};
printf "Total modifications           : %d\n", $stats{TOTAL_MOD};
printf "Total modrdns                 : %d\n", $stats{TOTAL_MODRDN};
printf "Total additions               : %d\n", $stats{TOTAL_ADD};
printf "Total deletions               : %d\n", $stats{TOTAL_DEL};
printf "Unindexed attribute requests  : %d\n", $stats{TOTAL_UNINDEXED};
printf "Operations per connection     : %.2f\n",
  $stats{TOTAL_CONNECT} ? $total_operations / $stats{TOTAL_CONNECT} : 0;

###################################################
### Process the host information and print a report
###################################################
for my $selected (@operations) {
    $selected = uc $selected;

    my $ops_ref = {
        CONNECT  => sub { $operations{CONNECT}{DATA}  = 1 },
        FAILURES => sub { $operations{FAILURES}{DATA} = 1 },
        BIND     => sub { $operations{BIND}{DATA}     = 1 },
        UNBIND   => sub { $operations{UNBIND}{DATA}   = 1 },
        SRCH     => sub { $operations{SRCH}{DATA}     = 1 },
        CMP      => sub { $operations{CMP}{DATA}      = 1 },
        ADD      => sub { $operations{ADD}{DATA}      = 1 },
        MOD      => sub { $operations{MOD}{DATA}      = 1 },
        MODRDN   => sub { $operations{MODRDN}{DATA}   = 1 },
        DEL      => sub { $operations{DEL}{DATA}      = 1 },
        ALL      => sub {
            $operations{CONNECT}{DATA}  = 1;
            $operations{FAILURES}{DATA} = 1;
            $operations{BIND}{DATA}     = 1;
            $operations{UNBIND}{DATA}   = 1;
            $operations{SRCH}{DATA}     = 1;
            $operations{CMP}{DATA}      = 1;
            $operations{ADD}{DATA}      = 1;
            $operations{MOD}{DATA}      = 1;
            $operations{MODRDN}{DATA}   = 1;
            $operations{DEL}{DATA}      = 1;
        },
        READ => sub {
            $operations{CONNECT}{DATA} = 1;
            $operations{BIND}{DATA}    = 1;
            $operations{UNBIND}{DATA}  = 1;
            $operations{SRCH}{DATA}    = 1;
            $operations{CMP}{DATA}     = 1;
        },
        WRITE => sub {
            $operations{CONNECT}{DATA} = 1;
            $operations{BIND}{DATA}    = 1;
            $operations{UNBIND}{DATA}  = 1;
            $operations{ADD}{DATA}     = 1;
            $operations{MOD}{DATA}     = 1;
            $operations{MODRDN}{DATA}  = 1;
            $operations{DEL}{DATA}     = 1;
        },
    };
    if   ( $ops_ref->{$selected} ) { $ops_ref->{$selected}->() }
    else                           { croak "Unknown operation: '$selected';\n" }
}

print "\n\n";
my $printstr = 'Hostname       ';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{STRING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{STRING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{STRING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{STRING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{STRING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{STRING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{STRING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{STRING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{STRING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{STRING}      : q{};
$printstr .= "\n";
print $printstr;
$printstr = '---------------';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{SPACING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{SPACING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{SPACING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{SPACING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{SPACING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{SPACING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{SPACING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{SPACING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{SPACING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{SPACING}      : q{};
print "$printstr\n";

for my $index ( sort keys %hosts ) {

    ### Resolve IP addresses to names if requested
    my $host = $index;

    ### Convert the IP address to an Internet address, and resolve with gethostbyaddr()
    if ( $resolvename && ( $index =~ /\d+\.\d+\.\d+\.\d+/mx ) ) {
        my $ipaddr = inet_aton($index);
        $host = gethostbyaddr $ipaddr, AF_INET;
        if ( !defined $host ) {
            $host = $index;
        }
    }
    printf '%-15.15s', $host;
    if ( $operations{CONNECT}{DATA} ) {
        printf " $operations{CONNECT}{FIELD}",
          $hosts{$index}{CONNECT} ? $hosts{$index}{CONNECT} : 0;
    }
    if ( $operations{FAILURES}{DATA} ) {
        printf " $operations{FAILURES}{FIELD}",
          $hosts{$index}{AUTHFAILURES} ? $hosts{$index}{AUTHFAILURES} : 0;
    }
    if ( $operations{BIND}{DATA} ) {
        printf " $operations{BIND}{FIELD}",
          $hosts{$index}{BIND} ? $hosts{$index}{BIND} : 0;
    }
    if ( $operations{UNBIND}{DATA} ) {
        printf " $operations{UNBIND}{FIELD}",
          $hosts{$index}{UNBIND} ? $hosts{$index}{UNBIND} : 0;
    }
    if ( $operations{SRCH}{DATA} ) {
        printf " $operations{SRCH}{FIELD}",
          $hosts{$index}{SRCH} ? $hosts{$index}{SRCH} : 0;
    }
    if ( $operations{CMP}{DATA} ) {
        printf " $operations{CMP}{FIELD}",
          $hosts{$index}{CMP} ? $hosts{$index}{CMP} : 0;
    }
    if ( $operations{ADD}{DATA} ) {
        printf " $operations{ADD}{FIELD}",
          $hosts{$index}{ADD} ? $hosts{$index}{ADD} : 0;
    }
    if ( $operations{MOD}{DATA} ) {
        printf " $operations{MOD}{FIELD}",
          $hosts{$index}{MOD} ? $hosts{$index}{MOD} : 0;
    }
    if ( $operations{MODRDN}{DATA} ) {
        printf " $operations{MODRDN}{FIELD}",
          $hosts{$index}{MODRDN} ? $hosts{$index}{MODRDN} : 0;
    }
    if ( $operations{DEL}{DATA} ) {
        printf " $operations{DEL}{FIELD}",
          $hosts{$index}{DEL} ? $hosts{$index}{DEL} : 0;
    }
    print "\n";
}

#######################################################
### Process the hours information and print a report
########################################################
print "\n\n";
$printstr = 'Hour of Day  ';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{STRING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{STRING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{STRING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{STRING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{STRING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{STRING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{STRING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{STRING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{STRING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{STRING}      : q{};
$printstr .= "\n";
print $printstr;
$printstr = '-------------';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{SPACING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{SPACING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{SPACING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{SPACING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{SPACING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{SPACING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{SPACING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{SPACING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{SPACING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{SPACING}      : q{};
print "$printstr\n";

for my $index ( sort keys %hours ) {
    printf '%-2s:00 - %2s:59', $index, $index;
    if ( $operations{CONNECT}{DATA} ) {
        printf " $operations{CONNECT}{FIELD}",
          $hours{$index}{CONNECT} ? $hours{$index}{CONNECT} : 0;
    }
    if ( $operations{FAILURES}{DATA} ) {
        printf " $operations{FAILURES}{FIELD}",
          $hours{$index}{AUTHFAILURES} ? $hours{$index}{AUTHFAILURES} : 0;
    }
    if ( $operations{BIND}{DATA} ) {
        printf " $operations{BIND}{FIELD}",
          $hours{$index}{BIND} ? $hours{$index}{BIND} : 0;
    }
    if ( $operations{UNBIND}{DATA} ) {
        printf " $operations{UNBIND}{FIELD}",
          $hours{$index}{UNBIND} ? $hours{$index}{UNBIND} : 0;
    }
    if ( $operations{SRCH}{DATA} ) {
        printf " $operations{SRCH}{FIELD}",
          $hours{$index}{SRCH} ? $hours{$index}{SRCH} : 0;
    }
    if ( $operations{CMP}{DATA} ) {
        printf " $operations{CMP}{FIELD}",
          $hours{$index}{CMP} ? $hours{$index}{CMP} : 0;
    }
    if ( $operations{ADD}{DATA} ) {
        printf " $operations{ADD}{FIELD}",
          $hours{$index}{ADD} ? $hours{$index}{ADD} : 0;
    }
    if ( $operations{MOD}{DATA} ) {
        printf " $operations{MOD}{FIELD}",
          $hours{$index}{MOD} ? $hours{$index}{MOD} : 0;
    }
    if ( $operations{MODRDN}{DATA} ) {
        printf " $operations{MODRDN}{FIELD}",
          $hours{$index}{MODRDN} ? $hours{$index}{MODRDN} : 0;
    }
    if ( $operations{DEL}{DATA} ) {
        printf " $operations{DEL}{FIELD}",
          $hours{$index}{DEL} ? $hours{$index}{DEL} : 0;
    }
    print "\n";
}

#######################################################
### Process the month information and print a report
########################################################
print "\n\n";
$printstr = 'Day of Month ';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{STRING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{STRING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{STRING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{STRING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{STRING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{STRING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{STRING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{STRING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{STRING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{STRING}      : q{};
$printstr .= "\n";
print $printstr;
$printstr = '-------------';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{SPACING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{SPACING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{SPACING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{SPACING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{SPACING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{SPACING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{SPACING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{SPACING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{SPACING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{SPACING}      : q{};
print "$printstr\n";

for ( 1 .. 31 ) {
    if ( defined $days{$_} || $printdays ) {
        printf '  %-11s', $_;
        if ( $operations{CONNECT}{DATA} ) {
            printf " $operations{CONNECT}{FIELD}",
              $days{$_}{CONNECT} ? $days{$_}{CONNECT} : 0;
        }
        if ( $operations{FAILURES}{DATA} ) {
            printf " $operations{FAILURES}{FIELD}",
              $days{$_}{AUTHFAILURES} ? $days{$_}{AUTHFAILURES} : 0;
        }
        if ( $operations{BIND}{DATA} ) {
            printf " $operations{BIND}{FIELD}",
              $days{$_}{BIND} ? $days{$_}{BIND} : 0;
        }
        if ( $operations{UNBIND}{DATA} ) {
            printf " $operations{UNBIND}{FIELD}",
              $days{$_}{UNBIND} ? $days{$_}{UNBIND} : 0;
        }
        if ( $operations{SRCH}{DATA} ) {
            printf " $operations{SRCH}{FIELD}",
              $days{$_}{SRCH} ? $days{$_}{SRCH} : 0;
        }
        if ( $operations{CMP}{DATA} ) {
            printf " $operations{CMP}{FIELD}",
              $days{$_}{CMP} ? $days{$_}{CMP} : 0;
        }
        if ( $operations{ADD}{DATA} ) {
            printf " $operations{ADD}{FIELD}",
              $days{$_}{ADD} ? $days{$_}{ADD} : 0;
        }
        if ( $operations{MOD}{DATA} ) {
            printf " $operations{MOD}{FIELD}",
              $days{$_}{MOD} ? $days{$_}{MOD} : 0;
        }
        if ( $operations{MODRDN}{DATA} ) {
            printf " $operations{MODRDN}{FIELD}",
              $days{$_}{MODRDN} ? $days{$_}{MODRDN} : 0;
        }
        if ( $operations{DEL}{DATA} ) {
            printf " $operations{DEL}{FIELD}",
              $days{$_}{DEL} ? $days{$_}{DEL} : 0;
        }
        print "\n";
    }
}
#######################################################
### Process the month information and print a report
########################################################
print "\n\n";
$printstr = ' Month       ';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{STRING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{STRING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{STRING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{STRING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{STRING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{STRING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{STRING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{STRING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{STRING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{STRING}      : q{};
$printstr .= "\n";
print $printstr;
$printstr = '-------------';
$printstr .= $operations{CONNECT}{DATA}  ? $operations{CONNECT}{SPACING}  : q{};
$printstr .= $operations{FAILURES}{DATA} ? $operations{FAILURES}{SPACING} : q{};
$printstr .= $operations{BIND}{DATA}     ? $operations{BIND}{SPACING}     : q{};
$printstr .= $operations{UNBIND}{DATA}   ? $operations{UNBIND}{SPACING}   : q{};
$printstr .= $operations{SRCH}{DATA}     ? $operations{SRCH}{SPACING}     : q{};
$printstr .= $operations{CMP}{DATA}      ? $operations{CMP}{SPACING}      : q{};
$printstr .= $operations{ADD}{DATA}      ? $operations{ADD}{SPACING}      : q{};
$printstr .= $operations{MOD}{DATA}      ? $operations{MOD}{SPACING}      : q{};
$printstr .= $operations{MODRDN}{DATA}   ? $operations{MODRDN}{SPACING}   : q{};
$printstr .= $operations{DEL}{DATA}      ? $operations{DEL}{SPACING}      : q{};
print "$printstr\n";

my $month_table;
if ($dateformat) {
    $month_table = [qw(01 02 03 04 05 06 07 08 09 10 11 12)];
}
else {
    $month_table = [qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)];
}

for my $index (@$month_table) {
    if ( defined $months{$index} || $printmonths ) {
        printf '  %-11s', $index;
        if ( $operations{CONNECT}{DATA} ) {
            printf " $operations{CONNECT}{FIELD}",
              $months{$index}{CONNECT} ? $months{$index}{CONNECT} : 0;
        }
        if ( $operations{FAILURES}{DATA} ) {
            printf " $operations{FAILURES}{FIELD}",
              $months{$index}{AUTHFAILURES}
              ? $months{$index}{AUTHFAILURES}
              : 0;
        }
        if ( $operations{BIND}{DATA} ) {
            printf " $operations{BIND}{FIELD}",
              $months{$index}{BIND} ? $months{$index}{BIND} : 0;
        }
        if ( $operations{UNBIND}{DATA} ) {
            printf " $operations{UNBIND}{FIELD}",
              $months{$index}{UNBIND} ? $months{$index}{UNBIND} : 0;
        }
        if ( $operations{SRCH}{DATA} ) {
            printf " $operations{SRCH}{FIELD}",
              $months{$index}{SRCH} ? $months{$index}{SRCH} : 0;
        }
        if ( $operations{CMP}{DATA} ) {
            printf " $operations{CMP}{FIELD}",
              $months{$index}{CMP} ? $months{$index}{CMP} : 0;
        }
        if ( $operations{ADD}{DATA} ) {
            printf " $operations{ADD}{FIELD}",
              $months{$index}{ADD} ? $months{$index}{ADD} : 0;
        }
        if ( $operations{MOD}{DATA} ) {
            printf " $operations{MOD}{FIELD}",
              $months{$index}{MOD} ? $months{$index}{MOD} : 0;
        }
        if ( $operations{MODRDN}{DATA} ) {
            printf " $operations{MODRDN}{FIELD}",
              $months{$index}{MODRDN} ? $months{$index}{MODRDN} : 0;
        }
        if ( $operations{DEL}{DATA} ) {
            printf " $operations{DEL}{FIELD}",
              $months{$index}{DEL} ? $months{$index}{DEL} : 0;
        }
        print "\n";
    }
}

####################################################
### Process the unindexed searches and print a report
####################################################
my @sarray;    # sort array
if ( $stats{TOTAL_UNINDEXED} > 0 ) {

    print "\n\n"
      . "# Uses        Unindexed attribute\n"
      . "----------    -----------------------------------------------------------\n";

    @sarray =
      reverse sort { $unindexed{$a} <=> $unindexed{$b} } keys %unindexed;
  UNINDEXED:
    for my $num ( 0 .. $#sarray ) {
        if ( $num > $count ) {
            last UNINDEXED;
        }
        printf "  %-8d    %-60s\n", $unindexed{ $sarray[$num] }, $sarray[$num];
    }
}

######################################################
### Process the stored search bases and print a report
######################################################
print "\n\n"
  . "# Searches    Search base\n"
  . "----------    -----------------------------------------------------------\n";

@sarray = reverse sort { $search{$a} <=> $search{$b} } keys %search;
SEARCH:
for my $num ( 0 .. $#sarray ) {
    if ( $num > $count ) {
        last SEARCH;
    }
    printf "  %-8d    %-60s\n", $search{ $sarray[$num] },
      $sarray[$num] || 'RootDSE';
}

######################################################
### Process the stored search filters
######################################################
print "\n\n"
  . "# Uses        Filter\n"
  . "----------    -----------------------------------------------------------\n";

@sarray = reverse sort { $filters{$a} <=> $filters{$b} } keys %filters;
FILTER:
for my $num ( 0 .. $#sarray ) {
    if ( $num > $count ) {
        last FILTER;
    }
    printf "  %-8d    %-60s\n", $filters{ $sarray[$num] }, $sarray[$num];
}

######################################################
### Process the stored attribute array
######################################################
print "\n\n"
  . "# Uses        Attributes explicitly requested in search string\n"
  . "----------    -------------------------------------------------\n";

@sarray =
  reverse sort { $searchattributes{$a} <=> $searchattributes{$b} }
  keys %searchattributes;
SEARCHATTR:
for my $num ( 0 .. $#sarray ) {
    if ( $num > $count ) {
        last SEARCHATTR;
    }
    printf "  %-8d    %-60s\n", $searchattributes{ $sarray[$num] },
      $sarray[$num];
}

######################################################
### Process the stored binddns and print a report
######################################################
print "\n\n"
  . "# Binds       Bind DN\n"
  . "----------    --------------------------------------------------------------\n";

@sarray = reverse sort { $binddns{$a} <=> $binddns{$b} } keys %binddns;
BINDDN:
for my $num ( 0 .. $#sarray ) {
    if ( $num > $count ) {
        last BINDDN;
    }
    printf "  %-8d    %-60s\n", $binddns{ $sarray[$num] }, $sarray[$num];
}

###################################################
### Process greater qtimes and etimes
###################################################

print "\n\n"
  . "# qtime (s)       Operation\n"
  . "------------      --------------------------------------------------------------\n";
# sort qtimes by their value (descending) and only select the n first ones
my %greater_qtimes = map { $_ => $qtimes{$_} } (sort { $qtimes{$b} <=> $qtimes{$a} } keys %qtimes)[0..$max_qtimes];
# for each greater qtime (from the greater to the lower)
foreach my $connop (sort { $greater_qtimes{$b} <=> $greater_qtimes{$a} } keys %greater_qtimes ) {
    # format time from µs (123456789) to s (123.456789)
    my $qt = substr($greater_qtimes{$connop},0,-6) . '.' . substr($greater_qtimes{$connop},-6);
    # if we find some associated operation(s) display them
    if($ops{"$connop"})
    {
        printf "  %-12s    %s\n", $qt, $ops{"$connop"};
    }
    # else, just display conn + op
    else
    {
        printf "  %-12s    %s\n", $qt, "operation not found (conn,op) = (" . $connop . ")" ;
    }
}

print "\n\n"
  . "# etime (s)       Operation\n"
  . "------------      --------------------------------------------------------------\n";
# sort etimes by their value (descending) and only select the n first ones
my %greater_etimes = map { $_ => $etimes{$_} } (sort { $etimes{$b} <=> $etimes{$a} } keys %etimes)[0..$max_etimes];
# for each greater etime (from the greater to the lower)
foreach my $connop (sort { $greater_etimes{$b} <=> $greater_etimes{$a} } keys %greater_etimes ) {
    # format time from µs (123456789) to s (123.456789)
    my $et = substr($greater_etimes{$connop},0,-6) . '.' . substr($greater_etimes{$connop},-6);
    # if we find some associated operation(s) display them
    if($ops{"$connop"})
    {
        printf "  %-12s    %s\n", $et, $ops{"$connop"};
    }
    # else, just display conn + op
    else
    {
        printf "  %-12s    %s\n", $et, "operation not found (conn,op) = (" . $connop . ")" ;
    }
}


print "\n\n";

# EOF
