#!/usr/bin/perl

use strict;
use warnings;

use DateTime;
use Net::LDAP;
use Net::LDAP::Control;
use Net::LDAP::Constant qw( LDAP_CONTROL_RELAX );
use Getopt::Long;

################################################################################
# Variables
################################################################################

my $force;
my $verbose;
my $help;

GetOptions ( "force|f"   => \$force,
             "verbose|v" => \$verbose,
             "help|h"    => \$help
           )
    or &usage();

my (
    $uri,
    $base,
    $filter,
    $binddn,
    $bindpw,
    $min,
    $max
   ) = @ARGV;


my $users; # { dn => { replace => { "pwdChangedTime" => "20250101120000Z" } } }

################################################################################
# Functions
################################################################################


sub usage
{
    print "Missing or bad argument\n";
    print "USAGE: $0 [-h] [-f] [-v] <uri> <base> <filter> <binddn> <bindpw> <min> <max>\n";
    print "DESCRIPTION: find users and spread homogeneously their pwdChangedTime from min to max days ago\n";
    print "   * -f: option to force applying modifications of pwdChangedTime\n";
    print "   * -h: display this help message\n";
    print "   * -v: verbose mode\n";
    print "   * uri: FQDN or LDAP uri, like ldap://host.domain.com or ldaps://host.domain.com\n";
    print "   * base: LDAP search base\n";
    print "   * filter: LDAP filter for selecting users\n";
    print "   * binddn: service account that binds for searching users and modifying pwdChangedTime\n";
    print "   * bindpw: password for service account\n";
    print "   * min: change password from min days ago\n";
    print "   * max: change password up to max days ago\n";
    exit 1;
}


sub get_users_dn
{
    my ($uri, $base, $filter, $binddn, $bindpw) = @_;

    my $result;

    my $ldap = Net::LDAP->new( $uri )
        or die "Unable to connect to LDAP server $uri: $@";

    my $bind_result = $ldap->bind( "$binddn",
                                   password => "$bindpw" );

    $bind_result->code and die $bind_result->error;

    my $search_result = $ldap->search(
                            base   => $base,
                            filter => $filter,
                            scope => "sub",
                            attrs => [ 'pwdChangedTime' ]
                        );

    $search_result->code and die $search_result->error;

    foreach my $entry ($search_result->entries)
    {
        $result->{$entry->dn} = {};
    }

    $ldap->unbind;

    return $result;
}

sub compute_pwd_changed_time
{

    my ( $users, $min, $max ) = @_;

    my $now = DateTime->now;
    my $date;

    my $days = $min;
    foreach my $user ( keys %$users )
    {

        $date = $now->clone();
        $date->subtract(days => $days);
        #print "days: $days " . $date->strftime('%Y%m%d%H%M%SZ')."\n";

        $users->{$user} = { replace => { "pwdChangedTime" => $date->strftime('%Y%m%d000000Z') } };
        if( $days < $max)
        {
            $days++;
        }
        else
        {
            $days = $min;
        }
    }

    return $users;
}

sub display_modifications
{
    my ( $users ) = @_;

    print "\nModifications to apply to LDAP directory\n";
    print "----------------------------------------\n";
    foreach my $user ( keys %$users )
    {
        my $date = $users->{$user}->{replace}->{pwdChangedTime};
        $date =~ s/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/$1-$2-$3 $4:$5:$6/;
        print sprintf "User: %-64s pwdChangedTime: %s\n", "$user", "$date";
    }

}


sub apply_modifications
{

    my ($uri, $base, $filter, $binddn, $bindpw, $users) = @_;
    
    my $ldap = Net::LDAP->new( $uri )
        or die "Unable to connect to LDAP server $uri: $@";

    my $bind_result = $ldap->bind( "$binddn",
                                   password => "$bindpw" );

    $bind_result->code and die $bind_result->error;

    my $relax_control = Net::LDAP::Control->new( type => LDAP_CONTROL_RELAX );
    my $mod;

    foreach my $user ( keys %$users )
    {
        $mod = $ldap->modify( $user, %{ $users->{$user} }, control => [ $relax_control ] );
        $mod->code and die "Error while modifying $user: " . $mod->error;
    }

    $ldap->unbind;
}


################################################################################
# Entry point
################################################################################

if( $help or !$uri or !$base or !$filter or !$binddn or !$bindpw or !$min or !$max )
{
    &usage();
}

unless( $min =~ /^\d+$/ )
{
    print "min: $min is not an integer\n";
    exit 1;
}

unless( $max =~ /^\d+$/ )
{
    print "max: $max is not an integer\n";
    exit 1;
}

$users = &get_users_dn($uri, $base, $filter, $binddn, $bindpw);

if(! keys %$users)
{
    print "No users found, aborting\n";
    exit 2;
}

$users = &compute_pwd_changed_time( $users, $min, $max );

if($verbose)
{
    &display_modifications( $users );
}

print "\nNumber of modifications to apply: ".scalar(keys %$users)."\n";

if($force)
{
    &apply_modifications($uri, $base, $filter, $binddn, $bindpw, $users);
    print "Modifications successfully applied\n";
}
else
{
    print "Modifications not applied (use -f if you want to)\n";
}

exit 0;
