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
my $endc = "}";

# Write changes and not full entries
my $change = 1;

# CSV delimiter (default is ",")
my $csv_delimiter = ";";

# Strip CSV headers (jump to second line)
my $csv_strip_headers = 1;

# Mapping configuration
my $map = {
    l_person => {
        dn => 'uid={(lc)uid},ou=users,dc=example,dc=com',
        objectClass => [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ],
        cn => '{cn}',
        sn => '{(uc)sn}',
        givenName => '{(ucfirstlc)givenname}',
        mail => '{(fmail)givenname}.{(fmail)sn}@example.com',
    },
    l_group => {
        dn => 'cn={employeetype},ou=groups,dc=example,dc=com',
        objectClass => [ 'top', 'groupOfUniqueNames' ],
	uniqueMember => 'cn=empty', 
    },
    l_group_add => {
        change_op => 'add',
        dn => 'cn={(lc)employeetype},ou=groups,dc=example,dc=com',
	uniqueMember => 'uid={(lc)uid},ou=users,dc=example,dc=com',
    },
    l_group_del => {
        change_op => 'delete',
        dn => 'cn={(lc)employeetype},ou=groups,dc=example,dc=com',
	uniqueMember => 'cn=empty',
    },
    c_person => {
        dn => 'uid={0},ou=users,dc=example,dc=com',
        objectClass => [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ],
        uid => '{0}',
        givenName => '{1}',
        sn => '{2}',
        cn => '{1} {2}',
    },
    c_group => {
        dn => 'cn={0},ou=groups,dc=example,dc=com',
        objectClass => [ 'top', 'groupOfUniqueNames' ],
        cn => '{0}',
        uniqueMember => 'uid={1},ou=users,dc=example,dc=com',
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
my ($type) = ($file =~ m/.*\.(\w+)/);

# If CSV, generate a tmp LDIF file
if ($type =~ m/csv/i) {
    # Load Text::CSV module
    use Text::CSV;

    # Open CSV
    my $csv = Text::CSV->new({
        sep_char => $csv_delimiter,
        binary => 1,
        });
    open (CSV, "<", $file) or die $!;

    # Parse CSV
    $inldif = Net::LDAP::LDIF->new("$file.ldif", "w" );

    while (<CSV>) {

        # Strip headers
        next if (($. == 1) and ($csv_strip_headers == 1));

        # Parse CSV line
        if ($csv->parse($_)) {
            my @columns = $csv->fields();
            # Write every column as attribute
            my $entry = Net::LDAP::Entry->new('o=fakedn');
            for my $i (0 ..$#columns) {
                 $entry->add($i => $columns[$i]);
            }
            $inldif->write_entry($entry);
        } else {
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
} else {
    $inldif = Net::LDAP::LDIF->new($file);
}

# Parse LDIF
while( not $inldif->eof() ) {
    my $entry = $inldif->read_entry();
    if ( $inldif->error() ) {
        print STDERR "Error msg: ", $inldif->error (), "\n";
        print STDERR "Error lines:\n", $inldif->error_lines (), "\n";
    } else {
        # Replace strings in map
        my %localmap = %{$map->{$task}};

        while ( my ($k, $v) = each %localmap ) {
            if ( ref($v) eq "ARRAY") {
                my @values = @$v;
                foreach ( @values ) { $_ =~ s/$beginc([^$endc]*)?$endc/&replace_value($entry,$1)/ge; };
                $v = \@values;
            } else {
               $v =~ s/$beginc([^$endc]*)?$endc/&replace_value($entry,$1)/ge;
            }
            $localmap{$k} = $v;
        }

	# DN
        my $dn = $localmap{dn};
        delete $localmap{dn};
        
	# Change operation
	my $change_op = $localmap{change_op};
        delete $localmap{change_op};
	$change_op = "add" unless $change_op;

	# Write entry
        my $outentry = Net::LDAP::Entry->new($dn);
	$outentry->changetype($changetype);
	$outentry->$change_op(%localmap);
	$outldif->write_entry( $outentry );
	if ( my $ldif_error = $outldif->error() ) {
		print STDERR "Fail to add entry in LDIF: $ldif_error\n";
	}
    }
}

# Takes the first value of wanted attribute
# Removes the whitespaces from begin and end
# Apply subroutine if any
sub replace_value {
    my $entry = shift;
    my $key = shift;
    my $sub;
    my $attr;
    my $value;

    # Check subroutine presence
    if ( $key =~ m/\((.*)\)(.*)/ ) {
        $sub = $1;
        $attr = $2;
    } else { $attr = $key }

    # Replace DN
    if ($attr eq "dn") { $value = $entry->dn(); }

    # Get first attribute value
    else { $value = $entry->get_value($attr); }

    # Return fake value to avoid errors
    return $attr unless defined $value;

    # Trim begin and end whitespaces
    $value =~ s/^\s+|\s+$//g;

    # Apply subroutine if any
    $value = &apply_sub($value, $sub) if ($sub);

    return $value;
}

# Apply subroutine
sub apply_sub {
    my $value = shift;
    my $sub = shift;

    $value = lc($value) if ($sub eq "lc");
    $value = lcfirst($value) if ($sub eq "lcfirst");
    $value = uc($value) if ($sub eq "uc");
    $value = ucfirst($value) if ($sub eq "ucfirst");
    $value = ucfirst(lc($value)) if ($sub eq "ucfirstlc");
    $value = &fmail($value) if ($sub eq "fmail");

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
	$value = unac_string('UTF-8', $value);
    	return $value;
    }
}

#====================================================================
# Exit
#====================================================================
$inldif->done ();
$outldif->done ();
unlink "$file.ldif" if ($type =~ m/csv/i);
exit 0;
