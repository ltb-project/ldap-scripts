#! /usr/pkg/bin/perl

#====================================================================
# Script to convert CSV or LDIF into LDIF
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

my $annuaire = undef;
my $apex     = undef;

while (<>) {
    if ( my ($dn) = /^dn: (.+)$/ ) {
        if ( not defined($annuaire) ) {
            $annuaire->{$dn} = Tree::Simple->new($dn);
            $apex = $dn;
        }
        else {
            my ( $premier, $suite ) = $dn =~ /^([^,]+),(.+)$/;
            $annuaire->{$dn} = Tree::Simple->new( $dn, $annuaire->{$suite} );
        }
    }
}

my $profondeur = -1;
my @aff_vert   = ();

print "$apex\n";

$annuaire->{$apex}->traverse(
    sub {
        my ($element) = @_;
        my $tag = $element->getNodeValue();
        $profondeur = $element->getDepth();
        if ( $profondeur != 0 ) {
            foreach my $p ( 0 .. $profondeur - 1 ) {
                if ( $aff_vert[$p] ) {
                    print '|   ';
                }
                else {
                    print '    ';
                }
            }
        }
        print '+-- ' . $tag . "($profondeur)" . "\n";

        if ( not $element->isLeaf() ) {
            $aff_vert[$profondeur] = 1 if $element->isFirstChild();
            $aff_vert[$profondeur] = 0 if $element->isLastChild();
        }
    }
);
