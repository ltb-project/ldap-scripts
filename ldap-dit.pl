#! /usr/pkg/bin/perl

#====================================================================
# Script to print DIT from LDIF file
#
# Copyright (C) Marc Baudoin
# Copyright (C) LTB-project.org
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

use strict;
use warnings;

use Tree::Simple;
use Net::LDAP::Util qw/ldap_explode_dn/;

my $directory = undef;
my $apex      = undef;

while (<>) {
    if ( my ($dn) = /^dn: (.+)$/ ) {

        # Normalize DN
        my $dn_explode = ldap_explode_dn( $dn, 'casefold' => 'lower' );
        next unless $dn_explode;
        my @dn_full = @$dn_explode;
        my ( $rdn, $branch );

        for my $i ( 0 .. $#dn_full ) {
            $branch = $branch ? $branch .= ", " : "";
            foreach my $attr ( keys %{ $dn_full[$i] } ) {
                if ( $i == 0 ) {
                    $rdn = $rdn ? $rdn .= "+" : "";
                    $rdn .= $attr . "=" . lc( %{ $dn_full[$i] }{$attr} );
                }
                else {
                    $branch .= $attr . "=" . lc( %{ $dn_full[$i] }{$attr} );
                }
            }
        }

        $dn = $rdn . ', ' . $branch;

        if ( not defined($directory) ) {
            $directory->{$dn} = Tree::Simple->new($dn);
            $apex = $dn;
        }
        else {
            $directory->{$dn} = Tree::Simple->new( $dn, $directory->{$branch} );
        }
    }
}

my $depth    = -1;
my @aff_vert = ();

print "$apex\n";

$directory->{$apex}->traverse(
    sub {
        my ($element) = @_;
        my $tag = $element->getNodeValue();
        $depth = $element->getDepth();
        if ( $depth != 0 ) {
            foreach my $p ( 0 .. $depth - 1 ) {
                if ( $aff_vert[$p] ) {
                    print '|   ';
                }
                else {
                    print '    ';
                }
            }
        }
        print '+-- ' . $tag . " ($depth)" . "\n";

        if ( not $element->isLeaf() ) {
            $aff_vert[$depth] = 1 if $element->isFirstChild();
            $aff_vert[$depth] = 0 if $element->isLastChild();
        }
    }
);
