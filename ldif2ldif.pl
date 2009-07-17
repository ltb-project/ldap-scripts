#!/usr/bin/perl -w

#====================================================================
# Script to convert LDIF into LDIF
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
# Containers begin and end characters for replacement
my $beginc = "{";
my $endc = "}";

# Mapping configuration
my $map = {
    person => {
        dn => 'uid={uid},ou=users,dc=example,dc=com',
	objectClass => [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ],
	cn => '{cn}',
	sn => '{sn}',
	givenName => '{givenname}',
	mail => '{givenname}{sn}@example.com',
	seeAlso => 'cn={employeetype},ou=groups,dc=example,dc=com',
   }
};

#====================================================================
# Modules
#====================================================================
use Net::LDAP::LDIF;
use strict;

#====================================================================
# Get command line arguments
#====================================================================
# Task
my $task = shift @ARGV;
# LDIF input file
my $file = shift @ARGV;
# LDIF output file

my $ldif = Net::LDAP::LDIF->new( $file );
my $outldif = Net::LDAP::LDIF->new( "$task.ldif", "w" );

while( not $ldif->eof() ) {
    my $entry = $ldif->read_entry();
    if ( $ldif->error() ) {
        print "Error msg: ", $ldif->error ( ), "\n";
        print "Error lines:\n", $ldif->error_lines ( ), "\n";
    } else {
        # Replace strings in map
        my %localmap = %{$map->{$task}};

        while ( my ($k, $v) = each %localmap ) {
            if ( ref($v) eq "ARRAY") {
                my @values = @$v;
                foreach ( @values ) { $_ =~ s/$beginc(\w*)$endc/&replace_value($entry,$1)/ge; };
                $v = \@values;
            } else {
               $v =~ s/$beginc(\w*)$endc/&replace_value($entry,$1)/gi;
            }
            $localmap{$k} = $v;
        }

        my $dn = $localmap{dn};
        delete $localmap{dn};
        my $outentry = Net::LDAP::Entry->new($dn, %localmap);
	$outldif->write_entry( $outentry );
	if ( my $ldif_error = $outldif->error() ) {
		print "Fail to add entry in LDIF: $ldif_error\n";
	}
    }
}

# This sub takes the first value of wanted attribute
# and removes the whitespaces from begin and end
sub replace_value {
    my $entry = shift;
    my $attr = shift;

    my $value = $entry->get_value($attr);
    $value =~ s/^\s+|\s+$//g;
    return $value;
}

#====================================================================
# Exit
#====================================================================
$ldif->done ( );
exit 0;
