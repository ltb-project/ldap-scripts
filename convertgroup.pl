#!/usr/bin/perl

#====================================================================
# Script to convert groups for server migration
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
# Source group object class
my $srcGroupOC = "nsRoleDefinition";

# Source group attribute name
my $srcGroupAT = "cn";

# Source member object class
my $srcMemberOC = "inetOrgPerson";

# Source reverse membership attribute
my $srcMemberAT = "nsRoleDN";

# Destination group objectClass
my $dstGroupOC = "groupOfUniqueNames";

# Destination group attribute name (RDN)
my $dstGroupATName = "cn";

# Destination group branch
my $dstGroupBranch = "ou=groups,dc=example,dc=com";

# Destination group attribute member
my $dstGroupATMember = "uniqueMember";

# Destination group attribute member value
my $dstGroupATMemberValue = "dn";

# Default member value for empty groups
my $dstGroupATMemberDefaultValue = "cn=empty";

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
use Net::LDAP::Util qw/ldap_explode_dn/;
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
    "$file.groupconvert", "w",
    sort      => $ldif_sort,
    encode    => $ldif_encode,
    lowercase => $ldif_lowercase,
    wrap      => $ldif_wrap,
);

my $groupMembership;
my $groups;

# Parse source LDIF
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

    # Check objectClass
    next unless ( $entry->exists('objectClass') );

    my $ocvalues = $entry->get_value( 'objectClass', asref => 1 );

    # Reverse membership
    if ( grep ( /^$srcMemberOC$/i, @$ocvalues ) ) {

        # Check reverse membership attribute
        next unless ( $entry->exists($srcMemberAT) );

        # Add user to group
        my $userRef =
          ( $dstGroupATMemberValue eq "dn" )
          ? $entry->dn()
          : $entry->get_value($dstGroupATMemberValue);

        foreach my $group ( $entry->get_value($srcMemberAT) ) {

            # This value is a DN, extract the RDN
            my $dnval = ldap_explode_dn( $group, casefold => 'lower' );
            my $groupName = $dnval->[0]->{$srcGroupAT};
            push @{ $groupMembership->{$groupName} }, $userRef;
        }

    }
    elsif ( grep ( /^$srcGroupOC$/i, @$ocvalues ) ) {
        next unless ( $entry->exists($srcGroupAT) );
        push @$groups, scalar $entry->get_value($srcGroupAT);
    }
}

foreach my $newGroup (@$groups) {

    # Build new group
    my $newGroupDN = $dstGroupATName . "=" . $newGroup . "," . $dstGroupBranch;
    my $newGroupEntry = Net::LDAP::Entry->new();
    $newGroupEntry->dn($newGroupDN);
    $newGroupEntry->add( 'objectClass' => $dstGroupOC );

    # Find members
    if ( exists $groupMembership->{$newGroup} ) {
        $newGroupEntry->add(
            $dstGroupATMember => $groupMembership->{$newGroup} );
    }
    else {
        $newGroupEntry->add(
            $dstGroupATMember => $dstGroupATMemberDefaultValue );
    }

    # Write entry
    $outldif->write_entry($newGroupEntry);
}

#====================================================================
# Exit
#====================================================================
$inldif->done();
$outldif->done();

exit 0;
