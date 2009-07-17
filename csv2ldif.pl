#!/usr/bin/perl -w

#====================================================================
# Script to convert CSV into LDIF
#
# Copyright (C) 2009 Clement OUDOT
# Copyright (C) 2009 LTB-project.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# GPL License: http://www.gnu.org/licenses/gpl.txt
#
#====================================================================

#====================================================================
# Configuration
#====================================================================
# CSV delimiter (default is ",")
my $csv_delimiter = ";";

# Strip CSV headers (jump to second line)
my $csv_strip_headers = 1;

# Containers begin and end characters for replacement
my $beginc = "{";
my $endc = "}";

# Mapping definition
# First hash level is the task name
# Sublevels use Net::LDAP::Entry hash representation
# Each CSV field is noted {i} where i is the field number
# and { } are containers delimiters ($beginc and $endc)
my $map = {
    person => {
        dn => 'uid={0},ou=users,dc=example,dc=com',
        objectClass => [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ],
        uid => '{0}',
	givenName => '{1}',
        sn => '{2}',
        cn => '{1} {2}',
    },
    group => {
        dn => 'cn={0},ou=groups,dc=example,dc=com',
        objectClass => [ 'top', 'groupOfUniqueNames' ],
        cn => '{0}',
        uniqueMember => 'uid={1},ou=users,dc=example,dc=com',
    },
};

#====================================================================
# Modules
#====================================================================
use Text::CSV;
use Net::LDAP::LDIF;
use strict;

#====================================================================
# Get command line arguments
#====================================================================
# Task
my $task = shift @ARGV;
# CSV input file
my $file = shift @ARGV;

#====================================================================
# LDIF and CSV file
#====================================================================
my $ldif = Net::LDAP::LDIF->new( "$task.ldif", "w");
my $csv = Text::CSV->new({
    sep_char => $csv_delimiter,
    binary => 1,
    });
open (CSV, "<", $file) or die $!;

#====================================================================
# Main
#====================================================================
while (<CSV>) {

    # Strip headers
    next if (($. == 1) and ( $csv_strip_headers == 1));

    # Parse CSV line
    if ($csv->parse($_)) {
        my @columns = $csv->fields();
        # Replace strings in map
        my %localmap = %{$map->{$task}};

        while ( my ($k, $v) = each %localmap ) {

            # Manage arrays
            if ( ref($v) eq "ARRAY") {
                my @values = @$v;
                foreach ( @values ) { $_ =~ s/$beginc(\d)$endc/$columns[$1]/g; };
                $v = \@values;
            } else {
                $v =~ s/$beginc(\d)$endc/$columns[$1]/g;
            }
            $localmap{$k} = $v;
        }
        my $dn = $localmap{dn};
        delete $localmap{dn};
        my $entry = Net::LDAP::Entry->new($dn, %localmap);
        $ldif->write_entry( $entry );
        if ( my $ldif_error = $ldif->error() ) {
            print "Fail to add entry in LDIF: $ldif_error\n";
        }

    } else {
	# Error in parsing
        my $err = $csv->error_input;
        print STDERR "Failed to parse line: $err\n";
    }

    # Next line
    next;

}

#====================================================================
# Exit
#====================================================================
close CSV;
exit 0;

