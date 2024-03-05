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

my $full_filters; # { "full_filter" => occurrence }
my $comp_filters; # { "component_filter" => occurrence }


foreach my $file (@ARGV)
{

    print "Analyze file $file\n";

    open(my $fh, "<", "$file") or die "Can't open < $file: $!";
    while(my $line = <$fh>)
    {
      if( $line =~ /filter="([^"]+)"/ )
      {
        my $full_filter = "$1";
        my $comp_filter = "$1";

        # Compute full filter
        $full_filter =~ s/\(([^=(]+)=([^)]+)\)/"($1=" . &format_value("$2") . ")"/eg;
        $full_filters->{$full_filter}++;

        # Compute components of filter
        while ($comp_filter =~ /\(([^=(]+)=([^)]+)\)/g) {
          $comp_filters->{"($1=" . &format_value("$2") . ")"}++;
        }
      }
    }
}

# Print table of full_filters, ordered by occurrences
print "| Occurrences | Full filters                                                   |\n";
print "+-------------+----------------------------------------------------------------+\n";
foreach my $filter (sort {$full_filters->{$b} <=> $full_filters->{$a}} keys %$full_filters) {
  print sprintf "|%12s | %62s |\n", $full_filters->{$filter}, $filter;
}

# Print table of filter components, ordered by occurrences
print "\n";
print "| Occurrences | Filter components                                              |\n";
print "+-------------+----------------------------------------------------------------+\n";
foreach my $filter (sort {$comp_filters->{$b} <=> $comp_filters->{$a}} keys %$comp_filters) {
  print sprintf "|%12s | %62s |\n", $comp_filters->{$filter}, $filter;
}

