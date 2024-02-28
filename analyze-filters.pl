#!/usr/bin/perl
# Program: Analyze filters in OpenLDAP logs <analyze-filters.pl>
#
# Source code home: https://github.com/ltb-project/ldap-scripts/analyze-filters.pl
#
# Author: LDAP Tool Box project
# Author: David Coutadeur <david.coutadeur@gmail.com>
#
# Current Version: 1
#
# Purpose:
#  Display the number of occurrences for each type of filter in OpenLDAP logs
#  Mainly used for index tuning
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
#   1. Enable a minimum of 'loglevel 256' in OpenLDAP configuration
#   2. Copy the perl script to a suitable location.
#   3. Refer to the usage section for options and examples.
#
# Usage:
#   ./analyze-filters.pl slapd.log
#

use strict;
use warnings;
use Data::Dumper;


# Function replacing static values by the tag <value>
# don't replace * in the values
sub format_value
{
  my $value = shift;
  $value =~ s/[^*]+/<value>/g;
  return $value;
}

# Get file from arguments passed to script
unless( @ARGV)
{
  print "missing file to analyze\n";
  exit 1;
}

my $file = shift @ARGV;
my $filters; # { "filter" => occurrence }

print "Analyze file $file\n";

open(my $fh, "<", "$file") or die "Can't open < $file: $!";
while(my $line = <$fh>)
{
  if( $line =~ /filter="([^"]+)"/ )
  {
    my $filter = "$1";
    $filter =~ s/\(([^=]+)=([^)]+)\)/"($1=" . &format_value("$2") . ")"/eg;
    $filters->{$filter}++;
  }
}

# Print table of filters, ordered by occurrences
print "| Occurrences | Filters                                                        |\n";
print "+-------------+----------------------------------------------------------------+\n";
foreach my $filter (sort {$filters->{$b} <=> $filters->{$a}} keys %$filters) {
  print sprintf "|%12s | %62s |\n", $filters->{$filter}, $filter;
}

