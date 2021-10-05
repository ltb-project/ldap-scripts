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

# Values to map
my $val_map =
  { 'creatorsName' => { 'cn=dirman' => 'cn=manager,dc=example,dc=com' }, };

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

# Remove empty values
my $remove_empty_values = 1;

# Force UTF-8 conversion
my $force_utf8_conversion = 1;

#====================================================================
# Modules
#====================================================================
use Net::LDAP::LDIF;
use strict;
use utf8;



#====================================================================
# Functions
#====================================================================

# unwrap the LDIF file
sub unwrapLdifFile {
    my $f = shift;
    open(FH, '<', $f) or die $!;
    my @content;
    my $i = 0;

    while(<FH>){
       if( $_ =~ /^ / )
       {
           my $res = $_;
           $res =~ s/^[ ]+//g; # remove starting space
           $content[($i-1)] =~ s/\n//; # remove trailing \n
           $content[($i-1)] .= $res; # concat values
       }
       else
       {
           $content[$i] = $_;
           $i++;
       }
    }
    close(FH);
    open(FH, '>', $f) or die $!;
    foreach (@content)
    {
        next if $_ =~ /^control:/; # remove the control attribute
        print FH $_;
    }
    close(FH);
}




#====================================================================
# Get command line arguments
#====================================================================
# Input file
my $file = shift @ARGV;

unless ($file) {
    print STDERR "Usage: $0 file.ldif\n";
    exit 1;
}

# unwrap the ldif file (attribute values are no more splitted in multiple lines)
# + remove control attribute (sometime returned by IBM Tivoli Directory Server)
#&unwrapLdifFile($file);

my $inldif = Net::LDAP::LDIF->new($file);

# Output file
my $outldif = Net::LDAP::LDIF->new(
    "$file.conv.ldif", "w",
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

        my $exclude_attr = 0;

        # Test 2: excluded attribute
        if ( grep ( /^$attr$/i, @$attr_exclude ) ) {
            print STDERR "Entry $dn: attribute $attr excluded\n";
            next;
        }

        # Test 3: mapped values
        foreach my $key_val_map ( keys %$val_map ) {

            if ( $attr =~ /^$key_val_map$/i ) {
                foreach
                  my $key_val_map_attr ( keys %{ $val_map->{$key_val_map} } )
                {
                    if (
                        grep /^$key_val_map_attr$/i,
                        $entry->get_value($key_val_map)
                      )
                    {
                        print STDERR
"Entry $dn: Value substitution for attribute $key_val_map\n";
                        $entry->delete( $key_val_map => [$key_val_map_attr] );
                        $entry->add( $key_val_map =>
                              $val_map->{$key_val_map}->{$key_val_map_attr} );
                    }
                }
            }
        }

        # Exclude empty attribute
        if ($remove_empty_values) {
            my $old_values  = $entry->get_value( $attr, asref => 1 );
            my $new_values  = [];
            my $need_remove = 0;
            foreach my $old_value (@$old_values) {
                unless ( grep( /^\s*$/, $old_value ) ) {
                    push @$new_values, $old_value;
                }
                else {
                    print STDERR
                      "Entry $dn: empty value for attribute $attr excluded\n";
                    $need_remove = 1;
                }
            }
            if ($need_remove) {
                if ( defined $new_values->[0] ) {
                    $entry->replace( $attr => $new_values );
                }
                else {
                    $entry->delete( $attr => [] );
                }
            }
        }

        # Force UT8 encoding
        if ($force_utf8_conversion) {
            my $old_values = $entry->get_value( $attr, asref => 1 );
            my $new_values = [];

            require Encode;

            foreach my $old_value (@$old_values) {
                eval {
                    my $safevalue = $old_value;
                    Encode::from_to( $safevalue, "utf8", "iso-8859-1",
                        Encode::FB_CROAK );
                };
                if ($@) {
                    Encode::from_to( $old_value, "iso-8859-1",
                        "utf8", Encode::FB_CROAK );
                    print STDERR
"Entry $dn: Force value utf8 conversion for attribute $attr\n";
                }

                push @$new_values, $old_value;
            }

            $entry->replace( $attr => $new_values );
        }

        # Test 4: excluded value
        foreach my $key_val_exclude ( keys %$val_exclude ) {

            if ( $attr =~ /^$key_val_exclude$/i ) {
                my $val        = $val_exclude->{$key_val_exclude};
                my $old_values = $entry->get_value( $attr, asref => 1 );
                my $new_values = [];

                foreach my $old_value (@$old_values) {
                    unless ( grep( /^$old_value$/i, @$val ) ) {
                        push @$new_values, $old_value;
                    }
                    else {
                        print STDERR
"Entry $dn: value $old_value for attribute $attr excluded\n";
                    }
                }

                $new_entry->add( $attr => $new_values );
                $exclude_attr = 1;
            }

        }

        next if $exclude_attr;

        # Test 5: mapped attribute
        foreach my $key_map ( keys %$map ) {
            if ( $attr =~ /^$key_map$/i ) {
                my $mapped_attr = $map->{$key_map};

                if ( ref $mapped_attr eq 'ARRAY' ) {
                    my $vals = [];
                    foreach my $ma ( @$mapped_attr ) {

                        if ( $entry->exists($ma) ) {

                            print STDERR
                              "Entry $dn: Use $ma value for attribute $attr\n";
                            push @$vals, ( @{$entry->get_value( $ma, asref => 1 )} );
                        }

                    }
                    $new_entry->add(
                        $attr => $vals,
                    );
                }
                else {

                    if ( $entry->exists($mapped_attr) ) {

                        print STDERR
                          "Entry $dn: Use $mapped_attr value for attribute $attr\n";
                        $new_entry->add(
                            $attr => $entry->get_value( $mapped_attr, asref => 1 )
                        );
                    }

                }
                $exclude_attr = 1;


            }
        }

        next if $exclude_attr;

        # Here, we just keep the attribute
        $new_entry->add( $attr => $entry->get_value( $attr, asref => 1 ) )
          if defined $entry->get_value($attr);

    }

    # Map attributes that do not exists in entry
    foreach my $key_map ( keys %$map ) {
        my $mapped_attr = $map->{$key_map};
        if ( !$new_entry->exists($key_map) and $entry->exists($mapped_attr) ) {

            print STDERR
              "Entry $dn: Use $mapped_attr value for attribute $key_map\n";
            $new_entry->add(
                $key_map => $entry->get_value( $mapped_attr, asref => 1 ) );

        }
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
