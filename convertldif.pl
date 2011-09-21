#!/usr/bin/perl

#====================================================================
# Script to convert LDIF into LDIF for server migration
#
# Copyright (C) 2011 Clement OUDOT
# Copyright (C) 2011 LTB-project.org
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
# Attributes to exclude
my $attr_exclude = [
    qw(
      createTimeStamp
      modifyTimeStamp
      nsRoleDN
      numSubordinates
      )
];

# Values to exclude
my $val_exclude =
  { 'objectClass' => [qw(exampleObjectClass otherObjectClass)], };

# Attributes to map
my $map = {
    'c'  => 'co',
    'co' => 'c',
};

# Branches to exclude
my $branch_exclude = [
    qw(
      cn=config
      cn=monitor
      )
];

# LDIF Options

# Sort attributes
my $ldif_sort = 0;

# DN encoding
# none, base64 or canonical
my $ldif_encode = "base64";

# Convert attribute names in lowercase
my $ldif_lowercase = 0;

# Columns wrapping
my $ldif_wrap = 78;

#====================================================================
# Modules
#====================================================================
use Net::LDAP::LDIF;
use strict;
use utf8;

#====================================================================
# Get command line arguments
#====================================================================
# Input file
my $file = shift @ARGV;

unless ($file) {
    print STDERR "Usage: $0 file.ldif\n";
    exit 1;
}

my $inldif = Net::LDAP::LDIF->new($file);

# Output file
my $outldif = Net::LDAP::LDIF->new(
    "$file.convert", "w",
    sort      => $ldif_sort,
    encode    => $ldif_encode,
    lowercase => $ldif_lowercase,
    wrap      => $ldif_wrap,
);

# Parse LDIF
while ( not $inldif->eof() ) {

    my $entry = $inldif->read_entry();

    next unless $entry;

    if ( $inldif->error() ) {
        print STDERR "Error msg: ",    $inldif->error(),       "\n";
        print STDERR "Error lines:\n", $inldif->error_lines(), "\n";
    }

    # Test 1: excluded branch
    my $dn            = $entry->dn();
    my $exclude_entry = 0;

    foreach my $branch (@$branch_exclude) {
        if ( $dn =~ /$branch$/i ) {
            print STDERR "DN $dn exlcuded (belongs to branch $branch)\n";
            $exclude_entry = 1;
            last;
        }
    }

    next if $exclude_entry;

    #  Create a new entry
    my $new_entry = Net::LDAP::Entry->new();
    $new_entry->dn($dn);

    foreach my $attr ( $entry->attributes ) {

        # Test 2: excluded attribute
        if ( grep ( /^$attr$/i, @$attr_exclude ) ) {
            print STDERR "Entry $dn: attribute $attr excluded\n";
            next;
        }

        # Test 3: excluded value
        foreach my $key_val_exclude ( keys %$val_exclude ) {

            if ( $attr =~ /^$key_val_exclude$/i ) {
                my $val        = $val_exclude->{$key_val_exclude};
                my $values     = $entry->get_value( $attr, asref => 1 );
                my $new_values = [];
                foreach my $value (@$values) {
                    unless ( grep( /^$value$/i, @$val ) ) {
                        push @$new_values, $value;
                    }
                    else {
                        print STDERR
                          "Entry $dn: value $_ for attribute $attr excluded\n";
                    }
                }
                $new_entry->add( $attr => $new_values );
                next;
            }
        }

        # Test 4: mapped attribute
        foreach my $key_map ( keys %$map ) {
            if ( $attr =~ /^$key_map$/i ) {
                my $mapped_attr = $map->{$key_map};

                print STDERR
                  "Entry $dn: Use $mapped_attr value for attribute $attr\n";
                $new_entry->add(
                    $attr => $entry->get_value( $mapped_attr, asref => 1 ) );
                next;
            }
        }

        # Here, we just keep the attribute
        $new_entry->add( $attr => $entry->get_value( $attr, asref => 1 ) );

    }

    # Print new entry in LDIF
    $outldif->write_entry($new_entry);
}

#====================================================================
# Exit
#====================================================================
$inldif->done();
$outldif->done();

exit 0;
