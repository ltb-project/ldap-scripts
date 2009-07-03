#!/bin/bash

#========================================================================
# Script for OpenLDAP 2.3.x minimum
#
# This script will attempt to remove any broken aliases into an
# OpenLDAP directory.
#
# Take some command lined parameters :
#   - Option "-b <searchbase>" specified the base where to search
#     for broken aliases. No default, it must be specified.
#
# Tested on :
#   - GNU/Linux platform ;
#
# Dependences into the PATH :
#   - awk
#   - sed
#   - perl
#   - openldap utils (ldapsearch, ldapdelete)
#
# Copyright (C) 2009 Thomas CHEMINEAU
# Copyright (C) 2009 LINAGORA
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
#========================================================================
# More contributions on http://www.linagora.org
#========================================================================

#========================================================================
# Changelog
#========================================================================
# Version 0.1 (2009):
# - First version
# Author: Thomas CHEMINEAU (LINAGORA)
#========================================================================

#------------------------------------------------------------------------
# PARAMETERS
#------------------------------------------------------------------------

#
# LDAP host URI
# eg: ldap://localhost:389
#
MY_LDAP_URI="ldap://localhost:389"

#
# LDAP bind DN which have write rights
# eg: cn=Manager,dc=example,dc=com
#
MY_LDAP_BINDDN="cn=Manager,dc=example,dc=com"

#
# LDAP bind password
#
MY_LDAP_BINDPW="secret"

#
# Log header format
# Could include unix commands
#
MY_LOG_HEADER="`date +\"%b %e %T\"` `hostname` `basename $0`[$$]:"

#------------------------------------------------------------------------
# INIT
#------------------------------------------------------------------------

# Some others parameters. It is recommended to not change them.

MY_LDAP_AUTHTOKEN="-D ${MY_LDAP_BINDDN} -w ${MY_LDAP_BINDPW} -H ${MY_LDAP_URI}"
MY_LDAP_SEARCHBASE=""
MY_SCRIPTNAME="$0"

#------------------------------------------------------------------------
# FUNCTIONS
#------------------------------------------------------------------------

#
# Delete all broken aliases into a specific tree.
#
delete_broken_aliases() {
  # $1: search base dn
  for alias_dn in `search_dn "$1" "sub" "(objectclass=alias)"`
  do
    object_dn=`search_aliasedObjectName "${alias_dn}"`
    if [ `test_dn "${object_dn}"` -ne 0 ] ; then
      if [ `delete_dn "${alias_dn}"` -eq 0 ] ; then
        print_trace "removing broken alias ${alias_dn} [OK]"
      else
        print_trace "removing broken alias ${alias_dn} [FAILED]"
      fi
    fi
  done
}

#
# Delete an entry identified by a DN.
#
delete_dn() {
  # $1: entry dn
  ldapdelete ${MY_LDAP_AUTHTOKEN} "$1" > /dev/null 2>&1
  echo $?
}

#
# Print information.
#
print_trace() {
  # $1: a message
  echo "${MY_LOG_HEADER} $1"
}

#
# Print usage.
#
print_usage() {
  echo "Usage : ${MY_SCRIPTNAME}]" 1>&2
  echo "\t-b <searchbase>" 1>&2
}  

#
# Get the aliasedObjectName value of an LDAP alias.
#
search_aliasedObjectName() {
  # $1: alias dn
  ldapsearch -LLL ${MY_LDAP_AUTHTOKEN} -b "$1" -s base aliasedObjectName \
    | perl -p0e 's/\n //g' | grep -i "aliasedObjectName" | awk -F': ' '{print $2}'
}

#
# Do a LDAP search and return all DN found.
#
search_dn() {
  # $1: base dn
  # $2: scope
  # $3: filter
  ldapsearch -LLL ${MY_LDAP_AUTHTOKEN} -b "$1" -S "" -s "$2" "$3" dn \
    | perl -p0e 's/\n //g' | awk -F': ' '{print $2}'
}

#
# Test if a entry exists.
#
test_dn() {
  # $1: entry dn
  ldapsearch -LLL ${MY_LDAP_AUTHTOKEN} -b "$1" -s base dn > /dev/null 2>&1
  echo $?
}

#------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------

if [ "$#" -ne "2" ]; then
  echo "Error: wrong number of arguments"
  print_usage
  exit 1
fi

while [ "$1" != "" ]; do
  case "$1" in
    -b)
      shift
      MY_LDAP_SEARCHBASE="$1"
      shift
      ;;
    *)
      print_usage
      exit 1
      ;;
  esac
done

delete_broken_aliases "${MY_LDAP_SEARCHBASE}"

exit 0

