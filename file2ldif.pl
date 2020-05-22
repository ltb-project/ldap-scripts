#!/usr/bin/perl -w

#====================================================================
# Script to convert CSV or LDIF into LDIF
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
my $endc   = "}";

# Write changes and not full entries
my $change = 1;

# CSV delimiter (default is ",")
my $csv_delimiter = ";";

# CSV multi values delimiter
my $csv_multivalues_delimiter = ",";

# Strip CSV headers (jump to second line)
my $csv_strip_headers = 1;

# Mapping configuration
my $map = {
    l_person => {
        dn => 'uid={(lc)uid},ou=users,dc=example,dc=com',
        objectClass =>
          [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ],
        cn        => '{cn}',
        sn        => '{(uc)sn}',
        givenName => '{(ucfirstlc)givenname}',
        mail      => '{(fmail)givenname}.{(fmail)sn}@example.com',
    },
    l_group => {
        dn           => 'cn={employeetype},ou=groups,dc=example,dc=com',
        objectClass  => [ 'top', 'groupOfUniqueNames' ],
        uniqueMember => 'cn=empty',
    },
    l_group_add => {
        change_op    => 'add',
        dn           => 'cn={(lc)employeetype},ou=groups,dc=example,dc=com',
        uniqueMember => 'uid={(lc)uid},ou=users,dc=example,dc=com',
    },
    l_group_del => {
        change_op    => 'delete',
        dn           => 'cn={(lc)employeetype},ou=groups,dc=example,dc=com',
        uniqueMember => 'cn=empty',
    },
    c_person => {
        dn => 'uid={1},ou=users,dc=example,dc=com',
        objectClass =>
          [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ],
        uid       => '{1}',
        givenName => '{2}',
        sn        => '{3}',
        cn        => '{2} {3}',
    },
    c_group => {
        dn           => 'cn={1},ou=groups,dc=example,dc=com',
        objectClass  => [ 'top', 'groupOfUniqueNames' ],
        cn           => '{1}',
        uniqueMember => 'uid={2},ou=users,dc=example,dc=com',
    },
};

#====================================================================
# Modules
#====================================================================
use Net::LDAP::LDIF;
use strict;

#====================================================================
# Get command line arguments
#====================================================================
# TODO: use getopts
# Task
my $task = shift @ARGV;

# Input file
my $file = shift @ARGV;

# Changetype (add, modify, delete, modrdn)
my $changetype = shift @ARGV;
$changetype = "add" unless $changetype;

# Output file
my $outldif = Net::LDAP::LDIF->new( "$task.ldif", "w", change => $change );
my $inldif;

# Determine input type file (CSV or LDIF)
my ($type) = ( $file =~ m/.*\.(\w+)/ );

# If CSV, generate a tmp LDIF file
if ( $type =~ m/csv/i ) {

    # Load Text::CSV module
    use Text::CSV;

    # Open CSV
    my $csv = Text::CSV->new(
        {
            sep_char => $csv_delimiter,
            binary   => 1,
        }
    );
    open( CSV, "<", $file ) or die $!;

    # Parse CSV
    $inldif = Net::LDAP::LDIF->new( "$file.ldif", "w" );

    while (<CSV>) {

        # Strip headers
        next if ( ( $. == 1 ) and ( $csv_strip_headers == 1 ) );

        # Parse CSV line
        if ( $csv->parse($_) ) {
            my @columns = $csv->fields();

            # Write every column as attribute
            my $entry = Net::LDAP::Entry->new('o=fakedn');
            for my $i ( 0 .. $#columns ) {
                my @values =
                  split( /\Q$csv_multivalues_delimiter\E/, $columns[$i] );
                $entry->add( $i + 1 => \@values );
            }
            $inldif->write_entry($entry);
        }
        else {

            # Error in parsing
            my $err = $csv->error_input;
            print STDERR "Failed to parse line: $err\n";
        }

        # Next line
        next;
    }

    close CSV;
    $inldif->done();
    $inldif = Net::LDAP::LDIF->new("$file.ldif");
}
else {
    $inldif = Net::LDAP::LDIF->new($file);
}

# Parse LDIF
while ( not $inldif->eof() ) {
    my $entry = $inldif->read_entry();
    next unless $entry;
    if ( $inldif->error() ) {
        print STDERR "Error msg: ",    $inldif->error(),       "\n";
        print STDERR "Error lines:\n", $inldif->error_lines(), "\n";
    }
    else {

        # Replace strings in map
        my %localmap = %{ $map->{$task} };

        while ( my ( $k, $v ) = each %localmap ) {
            if ( ref($v) eq "ARRAY" ) {
                my @values = @$v;
                my @all_values;
                foreach (@values) {
                    my $new_values = &generate_value( $entry, $_ );
                    push @all_values, @$new_values if $new_values;
                }
                $v = \@all_values;
            }
            else {
                $v = &generate_value( $entry, $v );
            }
            $localmap{$k} = $v;
        }

        # DN
        my $dn = shift @{ $localmap{'dn'} };
        delete $localmap{dn};

        # Change operation
        my $change_op = shift @{ $localmap{change_op} };
        delete $localmap{change_op};
        $change_op = "add" unless $change_op;

        # Remove empty values
        while ( my ( $key, $value ) = each(%localmap) ) {
            delete $localmap{$key} if ( $value eq "" );
            delete $localmap{$key}
              if ( ref($value) eq "ARRAY" and @$value == 0 );
        }

        # Write entry
        my $outentry = Net::LDAP::Entry->new($dn);
        $outentry->changetype($changetype);
        $outentry->$change_op(%localmap);
        $outldif->write_entry($outentry);
        if ( my $ldif_error = $outldif->error() ) {
            print STDERR "Fail to add entry in LDIF: $ldif_error\n";
        }
    }
}

# Takes all values of wanted attribute
# Removes the whitespaces from begin and end
# Apply subroutine if any
# @return ARRAYREF of values
sub replace_value {
    my $entry = shift;
    my $key   = shift;
    my $sub;
    my $attr;
    my $value;
    my @result;

    # Check subroutine presence
    if ( $key =~ m/\((.*)\)(.*)/ ) {
        $sub  = $1;
        $attr = $2;
    }
    else { $attr = $key }

    # Replace DN
    if ( $attr eq "dn" ) { $value = [ $entry->dn() ]; }

    # Get all attribute values
    else { $value = $entry->get_value( $attr, asref => 1 ); }

    # Empty value
    return "" unless defined $value;

    foreach my $val (@$value) {

        my $safe_val = $val;

        # Trim begin and end whitespaces
        $safe_val =~ s/^\s+|\s+$//g;

        # Apply subroutine if any
        $safe_val = &apply_sub( $val, $sub ) if ($sub);

        push @result, $safe_val;
    }

    return \@result;
}

# Create the new values
# Call replace_value to get the mapping
# @return ARRAYREF of new values
sub generate_value {
    my $entry = shift;
    my $value = shift;
    my $key;
    my @result;

    if ( $value =~ m/$beginc([^$endc]*)?$endc/ ) {
        my @keys = ( $value =~ m/$beginc([^$endc]*)?$endc/g );

        # If multiple keys, use only first attribute value
        if ( $#keys > 0 ) {
            my $hValues = {};
            foreach $key (@keys) {
                my $new_values = &replace_value( $entry, $key );
                if ($new_values) {
                    $hValues->{$key} = shift @$new_values;

                }
            }
            my $safe_value = $value;
            $safe_value =~ s/$beginc([^$endc]*)?$endc/$hValues->{$1}/ge;
            push @result, $safe_value;
        }
        else {
            # Else use all attributes values
            $key = shift @keys;
            my $new_values = &replace_value( $entry, $key );
            if ($new_values) {
                foreach my $new_value (@$new_values) {
                    my $safe_value = $value;
                    $safe_value =~ s/$beginc([^$endc]*)?$endc/$new_value/ge;
                    push @result, $safe_value;
                }
            }
        }
    }
    else {
        push @result, $value;
    }

    return \@result;
}

# Apply subroutine
sub apply_sub {
    my $value = shift;
    my $sub   = shift;

    $value = lc($value)            if ( $sub eq "lc" );
    $value = lcfirst($value)       if ( $sub eq "lcfirst" );
    $value = uc($value)            if ( $sub eq "uc" );
    $value = ucfirst($value)       if ( $sub eq "ucfirst" );
    $value = ucfirst( lc($value) ) if ( $sub eq "ucfirstlc" );
    $value = &fmail($value)        if ( $sub eq "fmail" );

    return $value;
}

# Formate values for mail address
sub fmail {
    my $value = shift;

    # Force lower case
    $value = lc($value);

    # Replace spaces by -
    $value =~ s/(\s+)/-/g;

    # Remove accents
    eval { require Text::Unaccent };
    if ($@) { return $value; }
    else {
        $value = unac_string( 'UTF-8', $value );
        return $value;
    }
}

#====================================================================
# Exit
#====================================================================
$inldif->done();
$outldif->done();
unlink "$file.ldif" if ( $type =~ m/csv/i );
exit 0;
