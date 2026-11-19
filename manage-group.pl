#!/usr/bin/perl

use strict;
use warnings;

use JSON;
use Getopt::Long;
use Net::LDAP;
use Data::Dumper;
use Time::HiRes;

################################################################################
# Description
# add or remove members to a group
# The considered members are fetched from a LDAP search
################################################################################

################################################################################
# Variables
################################################################################


my $conf_file = 'manage-group.json';
my $conf;

my $add = '';       # add mode
my $remove = '';    # remove mode
my $verbose = '';   # print debug messages
my $force = '';     # by default, operations are not written into LDAP directory
my $help = '';      # option to display help


my $users;    # hashref of users: { dn1 => {attr1 => [val1, val2], }}
my $group;    # hashref of a unique group: { dn => {attr1 => [val1, val2], }}
my $members;  # list of members to add or remove


################################################################################
# Functions
################################################################################


# displayHelp
# display help if help option is enabled, and then exit
# input: help option
# output: nothing
sub displayHelp
{
  my $help = shift;

  if ( $help )
  {
    print "\n$0 [--add|--remove] [--verbose] [--force] [--help]\n";
    print "add or remove users to a group\n";
    print "--add : add users to given group\n";
    print "--remove: remove users to given group\n";
    print "--verbose : display debug message to the screen\n";
    print "--force :   by default, a mail is sent, with force, it *really* apply operations in LDAP destination *USE WITH CARE*\n";
    print "--help :    display help and exit\n\n";
    exit 0;
  }
}


# arrayToHash
# Convert array to hash for improving search
# input: array reference
# output: hash reference
sub arrayToHash
{
    my ( $array_ref ) = @_;
    my %hashset;

    @hashset{ @$array_ref } = ();

    return \%hashset;
}


# displayVerbose
# display debug message if verbose is on
# input: debug message + list or hash of elements to display
# output: nothing
sub displayVerbose
{
  my ( $msg, $ids ) = @_;
  my $tmp;

  if ( $verbose )
  {
    print "$msg\n";
    if ( ref($ids) eq 'ARRAY' )
    {
      foreach my $elt ( @$ids )
      {
        print " $elt\n";
      }
    }
    elsif(ref($ids) eq 'HASH')
    {
      foreach my $elt ( keys %{$ids} )
      {
        print " $elt\n";
        $tmp = $ids->{$elt};
        print " ".Dumper($tmp);
      }
    }
    print "\n";
  }
}


# display
# display message
# input: debug message + list or hash of elements to display
# output: nothing
sub display
{
  my ( $msg ) = @_;
  print "$msg\n";
}


# function returning a duration formatted as: hh::mm::ss.mmm
# input: duration in seconds
# output: duration formatted as string
sub formatDate
{
  my $duration = shift;
  my $res = sprintf ("%02d:%02d:%02d",(gmtime($duration))[2,1,0]);
  # deal with millisecond part
  $res .= sprintf ".%03d", ($duration-int($duration))*1000;

  return $res
}


# get_configuration
# get configuration from JSON file
# input: file name
# output: hash containing the parsed JSON
sub get_configuration
{
    my $conf_file = shift;

    my $json_text = do {
     open(my $json_fh, "<:encoding(UTF-8)", $conf_file)
        or die("Can't open $conf_file: $!\n");
     local $/;
     <$json_fh>
    };

    my $json = JSON->new;
    my $config = $json->decode($json_text);

    return $config;
}


# getUsers
# get users from a LDAP search
# input: configuration parameters
# output: associative array: { dn1 => {attr1 => [val1, val2], }}
sub getUsers
{
    my $config = shift;

    my $host = $config->{"host"};
    my $bindDN = $config->{"bindDN"};
    my $bindPW = $config->{"bindPW"};
    my $base = $config->{"users"}->{"base"};
    my $filter = $config->{"users"}->{"filter"};
    my $attrs = $config->{"users"}->{"attrs"};

    my ($ldap, $mesg);
    my $entries;

    $ldap = Net::LDAP->new( $host, timeout => 60 ) or die "$@";
    $mesg = $ldap->bind($bindDN, password => $bindPW);
    $mesg->code && die $mesg->error;
    $mesg = $ldap->search(
                           base   => $base,
                           filter => $filter,
                           scope => "sub",
                           attrs => $attrs,
                         );

    $mesg->code && die $mesg->error;

    foreach my $entry ($mesg->entries)
    {
        foreach my $attr (@$attrs)
        {
            $entries->{$entry->dn()}->{$attr} = $entry->get_value( $attr, asref => 1);
        }
    }
    $mesg = $ldap->unbind;
    return $entries;
}


# getGroup
# get one group from a LDAP search
# input: configuration parameters
# output: associative array: { dn1 => {attr1 => [val1, val2], }}
sub getGroup
{
    my $config = shift;

    my $host = $config->{"host"};
    my $bindDN = $config->{"bindDN"};
    my $bindPW = $config->{"bindPW"};
    my $base = $config->{"group"}->{"base"};
    my $filter = $config->{"group"}->{"filter"};
    my $attrs = $config->{"group"}->{"attrs"};

    my ($ldap, $mesg);
    my $entries;

    $ldap = Net::LDAP->new( $host, timeout => 60 ) or die "$@";
    $mesg = $ldap->bind($bindDN, password => $bindPW);
    $mesg->code && die $mesg->error;
    $mesg = $ldap->search(
                           base   => $base,
                           filter => $filter,
                           scope => "sub",
                           attrs => $attrs,
                         );

    $mesg->code && die $mesg->error;

    if( scalar( $mesg->entries ) > 1 )
    {
        die("Too much entries found when fetching group");
    }
    if( scalar( $mesg->entries ) == 0 )
    {
        die("Group entry not found");
    }

    my ($entry) = $mesg->entries();
    foreach my $attr (@$attrs)
    {
        $entries->{$entry->dn()}->{$attr} = $entry->get_value( $attr, asref => 1);
    }
    $mesg = $ldap->unbind;
    return $entries;
}


# computeMembersToAdd
# compute list of users to add to a group:
# add users from given hashref is they don't exist in the group yet
# input: hashref of group, hashref of users: { dn1 => {attr1 => [val1, val2], }}
# output: array ref of list of users to add
sub computeMembersToAdd {

    my ( $group, $users ) = @_;

    my ($group_dn) = keys %$group;
    my @group_members = @{$group->{$group_dn}->{"member"}};
    my @group_members_lc = map { lc } @group_members;
    my $members_hash = &arrayToHash(\@group_members_lc);
    my $members = [];

    foreach my $dn ( keys %$users )
    {
        if( ! exists $members_hash->{lc($dn)})
        {
            # if user DN is not found in current members list, append to the add list
            push @$members, $dn;
        }
    }

    return $members;
}


# computeMembersToRemove
# compute list of users to remove from group:
# remove users from given hashref is they still exist in the group
# input: hashref of group, hashref of users: { dn1 => {attr1 => [val1, val2], }}
# output: array ref of list of users to remove
sub computeMembersToRemove {

    my ( $group, $users ) = @_;

    my ($group_dn) = keys %$group;
    my @group_members = @{$group->{$group_dn}->{"member"}};
    my @group_members_lc = map { lc } @group_members;
    my $members_hash = &arrayToHash(\@group_members_lc);
    my $members = [];

    foreach my $dn ( keys %$users )
    {
        if( exists $members_hash->{lc($dn)} )
        {
            # if user DN is not found in current members list, append to the add list
            push @$members, $dn;
        }
    }

    return $members;
}


# addMembersToGroup
# add new members to given group
# input: config, hashref of group, array ref of members to add
# output: none (members are added into LDAP)
sub addMembersToGroup {

    my ($config, $group, $new_members) = @_;

    my $host = $config->{"host"};
    my $bindDN = $config->{"bindDN"};
    my $bindPW = $config->{"bindPW"};
    my ($group_dn) = keys %$group;

    my ($ldap, $mesg);

    $ldap = Net::LDAP->new( $host, timeout => 60 ) or die "$@";
    $mesg = $ldap->bind($bindDN, password => $bindPW);
    $mesg->code && die $mesg->error;

    $mesg = $ldap->modify( "$group_dn",
                           "add" => {
                               "member" => $new_members
                           } );
    $mesg->code && die $mesg->error;

    $mesg = $ldap->unbind;
}


# removeMembersToGroup
# remove extra members from given group
# input: config, hashref of group, array ref of members to remove
# output: none (members are removed from LDAP)
sub removeMembersToGroup {

    my ($config, $group, $extra_members) = @_;

    my $host = $config->{"host"};
    my $bindDN = $config->{"bindDN"};
    my $bindPW = $config->{"bindPW"};
    my ($group_dn) = keys %$group;

    my ($ldap, $mesg);

    $ldap = Net::LDAP->new( $host, timeout => 60 ) or die "$@";
    $mesg = $ldap->bind($bindDN, password => $bindPW);
    $mesg->code && die $mesg->error;

    $mesg = $ldap->modify( "$group_dn",
                           "delete" => {
                               "member" => $extra_members
                           } );
    if($mesg->code)
    {
        if( $mesg->error =~ /requires attribute 'member'/ )
        {
            print("Operation would have removed all members, but group can't be empty\n");
            print("Make sure there is at least one remaining member.\n");
        }
        die $mesg->error;
    }
    $mesg->code && die $mesg->error;

    $mesg = $ldap->unbind;
}


################################################################################
# Entry point
################################################################################

# Get program arguments
GetOptions (
            'add'        => \$add,
            'remove'     => \$remove,
            'verbose!'  => \$verbose,
            'force!'    => \$force,
            'help'      => \$help,
           );

&displayHelp($help);


# Save script start time
my $scriptStartTime = Time::HiRes::gettimeofday();

# get configuration from JSON file
$conf = &get_configuration( $conf_file );

# ADD MODE
# add users to a group
if( $add )
{

    # get users from LDAP
    $users = &getUsers($conf);
    &displayVerbose("List of fetched users: ", $users);

    # get group from LDAP
    $group = &getGroup($conf);
    &displayVerbose("Current group: ", $group);

    # Compute members to add to group
    $members = &computeMembersToAdd($group, $users);
    &displayVerbose("Members to add: ", $members);

    if( scalar(@$members) == 0 ) {
        my $scriptEndTime = Time::HiRes::gettimeofday();
        &display("Script elapsed time: " . &formatDate($scriptEndTime - $scriptStartTime) );
        exit 0;
    }

    # Apply modifications to group if force option is passed
    &addMembersToGroup($conf, $group, $members) if $force;

    &displayVerbose(scalar(@$members)." user(s) added to group", []) if $force;

}
# REMOVE MODE
# remove users from group
elsif( $remove )
{

    # get users from LDAP
    $users = &getUsers($conf);
    &displayVerbose("List of fetched users: ", $users);

    # get group from LDAP
    $group = &getGroup($conf);
    &displayVerbose("Current group: ", $group);

    # Compute members to remove from group
    $members = &computeMembersToRemove($group, $users);
    &displayVerbose("Members to remove: ", $members);

    if( scalar(@$members) == 0 ) {
        my $scriptEndTime = Time::HiRes::gettimeofday();
        &display("Script elapsed time: " . &formatDate($scriptEndTime - $scriptStartTime) );
        exit 0;
    }

    # Apply modifications to group if force option is passed
    &removeMembersToGroup($conf, $group, $members) if $force;

    &displayVerbose(scalar(@$members)." user(s) removed from group", []) if $force;

}
else
{
  $help = 1;
  &displayHelp($help);
}

# Save script end time
my $scriptEndTime = Time::HiRes::gettimeofday();
&display("Script elapsed time: " . &formatDate($scriptEndTime - $scriptStartTime) );

exit 0;

