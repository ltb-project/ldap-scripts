#!/bin/sh

#====================================================================
# Script for OpenLDAP with ppolicy overlay
#
# Does searches on LDAP directory to determine which user passwords
# came to expiration. If so, sends mails to concerned users.
#
# Tested on :
#   - GNU/Linux platform ;
#   - SunOS 8.5 platform ;
#
# Dependences :
#   - gawk
#   - ldapsearch
#   - mailx
#
# Copyright (C) 2008 Clement OUDOT
# Copyright (C) 2007 Thomas CHEMINEAU
# Copyright (C) 2009 LTB-project.org
# Copyright (C) 2019 Worteks
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
# Changelog
#====================================================================
# Version 0.5 (12/2020)
# - Add parameters for ldapsearch (to make socket connections or no-wrap or pagination with pr=500/noprompt)
# - Add parameter for the "from:" of the mail (mailx can't send with From in the body)
# - Exclude some noise from the ldap global search result (ldap pagination print some comment's lines)
# - >"LIMIT: multi-lined DN causes errors" - so use '-o ldif-wrap=no' in 'LDAP_PARAM'
# Version 0.4 (11/2019)
# - #11 fixed:
#   Add remaning time before password expiration in mail.
# Version 0.3 (03/2010):
# - #295 fixed:
#   Add a parameter to specify the search scope
#   Get compatibility with cut behaviour on SUSE system
# Version 0.2 (08/2008):
# - Use zulu time (GMT) for currentTime
# - Split mail command parameters (binary and subject)
# - Add script statitics to STDOUT
# - Add debug info to STDERR
# - Use ppolicy warning time for mail delay if provided
# - Manage no default ppolicy case (just per-user ppolicies)
# - LDAP user attributes are now configurable
# - Jump to next user if no password change date or no ppolicy
# LIMIT: multi-lined DN causes errors
# TODO: use GMT time for SunOS and test the script for this OS
# Author: Clement OUDOT (LINAGORA)
# 
# Version 0.1 (2007):
# - First version
# Author: Thomas CHEMINEAU (LINAGORA)
#====================================================================


#====================================================================
# Configuration
#====================================================================



#
# LDAP host URI
# eg: ldap://localhost:389
# eg: ldapi://
#
MY_LDAP_HOSTURI="ldap://localhost:389"

#
# LDAP custom parameters
# eg: -E pr=500/noprompt
# eg: -o ldif-wrap=no
# eg: -Q -Y EXTERNAL
# eg (default): -x
#
# For Authentication use : -E pr=500/noprompt -o ldif-wrap=no -x
# For socket use : -E pr=500/noprompt -o ldif-wrap=no -Q -Y EXTERNAL
#
#LDAP_PARAM="-E pr=500/noprompt -o ldif-wrap=no -x"

#
# LDAP root DN (optional)
# eg: cn=Manager,dc=example,dc=com
#
#MY_LDAP_ROOTDN="cn=manager,dc=example,dc=com"

#
# LDAP root password (optional)
#
#MY_LDAP_ROOTPW="secret"

#
# LDAP default password policy DN
# eg: ou=defaultPasswordPolicy,dc=example,dc=com
# If commented, we suppose there are no default, and only per-user policies
#
#MY_LDAP_DEFAULTPWDPOLICYDN="ou=defaultPasswordPolicy,dc=example,dc=com"

#
# LDAP search base for users
# eg: ou=People,dc=example,dc=com
#
MY_LDAP_SEARCHBASE="ou=People,dc=example,dc=com"

#
# LDAP search filter to use to get all users
#
MY_LDAP_SEARCHFILTER="(&(uid=*)(objectClass=inetOrgPerson))"

#
# LDAP search scope to use to get all users
#
MY_LDAP_SEARCHSCOPE="one"

#
# Path to LDAP search binary
#
MY_LDAP_SEARCHBIN="/usr/local/openldap/bin/ldapsearch"

#
# Delay to begin sending adverts
# Comment to use the pwdExpireWarning value of the user's Password Policy
#
#MY_MAIL_DELAY=1296000

#
# LDAP attributes storing user's information
#   NAME: Display name of the user
#   LOGIN: Account ID of the user
#   MAIL: Email of the user
# 
MY_LDAP_NAME_ATTR=cn
MY_LDAP_LOGIN_ATTR=uid
MY_LDAP_MAIL_ATTR=mail

#
# Locale for date
# eg: export LC_ALL=en_US.UTF-8
#
export LC_ALL=en_US.UTF-8

#
# Mail from
#
#MY_MAIL_FROM="noreply@yo.com"

# Mail body message, with particular variables :
#   %name : user name
#   %login : user login
#
MY_MAIL_BODY="From: noreply@example.com\n\n \
	Hi %name,\n\n \
	
	Please change your password. It will expire in %expireDays days on %expireTimeTZ.\n\n \

	As a reminder, the password policy is :\n\n \

	- Minimum Password Length : %pwdMinLength characters\n\n \
	- There is a password history, your new password must be different from you last %pwdInHistory passwords.\n\n \

	The LDAP team."

#
# Mail subject
#
MY_MAIL_SUBJECT="Your account will expire soon"

#
# Mail command binary
# Replace mailx by mail for RedHat
#
MY_MAIL_BIN="mail"

#
# Log header format
# Could include unix commands
#
MY_LOG_HEADER="$(date +\"%b %e %T\") $(hostname) $0[$$]:"

#
# Path to GAWK (GNU awk) binary
#
MY_GAWK_BIN="/usr/bin/gawk"

#====================================================================
# Functions
#====================================================================

#
# Retrieves date in seconds.
# This function could take one parameter, a time returned by the command
# `date +"%Y %m %d %H %M %S"`. Without parameter, it returns GMT time.
#
getTimeInSeconds() {
	date=0
	os=$(uname -s)

	if [ "$1" ]; then
		date=$(TZ=UTC ${MY_GAWK_BIN} 'BEGIN  { \
			if (ARGC == 2) { \
		        	print mktime(ARGV[1]) \
			} \
			exit 0 }' "$1")
	else
		if [ "${os}" = "SunOS" ]; then
			# Under Sun Solaris, there is no simple way to
			# retrieve epoch time.
			# TODO: manage zulu time (GMT)
			date=$(/usr/bin/truss /usr/bin/date 2>&1 | nawk -F= \
				'/^time\(\)/ {gsub(/ /,"",$2);print $2}')
		else
			now=$(date +"%Y %m %d %H %M %S" -u)
			date=$(getTimeInSeconds "$now")
		fi
	fi

	echo "${date}"
}

#====================================================================
# Script
#====================================================================

## Variables initialization
tmp_dir="/tmp/$$.checkldap.tmp"
result_file="${tmp_dir}/res.tmp.1"
buffer_file="${tmp_dir}/buf.tmp.1"
[ -z "${MY_MAIL_FROM}" ] || MY_MAIL_BIN="${MY_MAIL_BIN} -r "
[ -z "${LDAP_PARAM}" ] && LDAP_PARAM="-x" # default authorization
echo "${LDAP_PARAM}" | grep -E "Q|Y|x" 1>/dev/null || LDAP_PARAM="${LDAP_PARAM} -x"
ldap_param="${LDAP_PARAM} -LLL -H ${MY_LDAP_HOSTURI}"
nb_users=0
nb_expired_users=0
nb_warning_users=0

## Some tests
if [ -d ${tmp_dir} ]; then
	echo "Error : temporary directory exists (${tmp_dir})"
	exit 1
fi
mkdir ${tmp_dir}

if [ "${MY_LDAP_ROOTDN}" ]; then
	ldap_param="${ldap_param} -D ${MY_LDAP_ROOTDN} -w ${MY_LDAP_ROOTPW}"
fi

## Performs global search
${MY_LDAP_SEARCHBIN} "${ldap_param}" -s ${MY_LDAP_SEARCHSCOPE} \
	-b "${MY_LDAP_SEARCHBASE}" "${MY_LDAP_SEARCHFILTER}" \
	"dn" | grep -iE '^dn:' > ${result_file}

## Loops on results
while read dnStr
do
	# Do not use blank lines
	if [ ! "${dnStr}" ]; then
		continue
	fi

	# Process ldap search
	dn=$(echo "${dnStr}" | cut -d : -f 2)

	# Increment users counter
	nb_users=$(expr "${nb_users}" + 1)
	
	${MY_LDAP_SEARCHBIN} "${ldap_param}" -s base -b "${dn}" \
		${MY_LDAP_NAME_ATTR} ${MY_LDAP_LOGIN_ATTR} ${MY_LDAP_MAIL_ATTR} pwdChangedTime pwdPolicySubentry \
		> ${buffer_file}

	login=$(grep -w "${MY_LDAP_LOGIN_ATTR}:" ${buffer_file} | cut -d : -f 2 \
		| sed "s/^ *//;s/ *$//")
	name=$(grep -w "${MY_LDAP_NAME_ATTR}:" ${buffer_file} | cut -d : -f 2\
		| sed "s/^ *//;s/ *$//")
	mail=$(grep -w "${MY_LDAP_MAIL_ATTR}:" ${buffer_file} | cut -d : -f 2 \
		| sed "s/^ *//;s/ *$//")
	pwdChangedTime=$(grep -w "pwdChangedTime:" ${buffer_file} \
		| cut -d : -f 2 | cut -c 1-15 | sed "s/^ *//;s/ *$//")
	pwdPolicySubentry=$(grep -w "pwdPolicySubentry:" ${buffer_file} \
		| cut -d : -f 2 | sed "s/^ *//;s/ *$//")

	# Go to next entry if no pwdChangedTime
	if [ ! "${pwdChangedTime}" ]; then
		echo "${MY_LOG_HEADER} No password change date for ${login}" >&2
		continue
	fi

	# Go to next entry if no pwdPolicySubEntry and no default policy
	if [ ! "${pwdPolicySubentry}" -a ! "${MY_LDAP_DEFAULTPWDPOLICYDN}" ]; then
		echo "${MY_LOG_HEADER} No password policy for ${login}" >&2
		continue
	fi

	# Retrieves user policy pwdMaxAge and pwdExpireWarning attributes
	ldap_search="${MY_LDAP_SEARCHBIN} ${ldap_param} -s base"
	if [ "${pwdPolicySubentry}" ]; then
		ldap_search="${ldap_search} -b ${pwdPolicySubentry}"
	else
		ldap_search="${ldap_search} -b ${MY_LDAP_DEFAULTPWDPOLICYDN}"
	fi
	
	ldap_search="$ldap_search pwdMaxAge pwdExpireWarning pwdMinLength pwdInHistory"
	pwdMaxAge=$(${ldap_search} | grep -w "pwdMaxAge:" | cut -d : -f 2 \
		| sed "s/^ *//;s/ *$//")
	pwdExpireWarning=$(${ldap_search} | grep -w "pwdExpireWarning:" | cut -d : -f 2 \
		| sed "s/^ *//;s/ *$//")
	pwdMinLength=$(${ldap_search} | grep -w "pwdMinLength:" | cut -d : -f 2 \
		| sed "s/^ *//;s/ *$//")
	pwdInHistory=$(${ldap_search} | grep -w "pwdInHistory:" | cut -d : -f 2 \
		| sed "s/^ *//;s/ *$//")

        # Go to next user if no pwdMaxAge (no expiration)
        if [ ! "${pwdMaxAge}" ]; then
                echo "${MY_LOG_HEADER} No password expiration configured for ${login}" >&2
                continue
        fi

	# Replace MAIL_DELAY by pwdExpireWarning if exists
	MY_MAIL_DELAY=${MY_MAIL_DELAY:=$pwdExpireWarning}

	# Retrieves time difference between today and last change.
	if [ "${pwdChangedTime}" ]; then
		s=$(echo "${pwdChangedTime}" | cut -c 13-14)
		m=$(echo "${pwdChangedTime}" | cut -c 11-12)
		h=$(echo "${pwdChangedTime}" | cut -c 9-10)
		d=$(echo "${pwdChangedTime}" | cut -c 7-8)
		M=$(echo "${pwdChangedTime}" | cut -c 5-6)
		y=$(echo "${pwdChangedTime}" | cut -c 1-4)
		currentTime=$(getTimeInSeconds)
		pwdChangedTime=$(getTimeInSeconds "$y $M $d $h $m $s")
		diffTime=$(expr "${currentTime}" - "${pwdChangedTime}")
	fi

	# Go to next user if password already expired
	expireTime=$(expr "${pwdChangedTime}" + "${pwdMaxAge}")
	if [ "${currentTime}" -gt "${expireTime}" ]; then
		nb_expired_users=$(expr "${nb_expired_users}" + 1)
		echo "${MY_LOG_HEADER} Password expired for ${login}" >&2
		continue
	fi
	
	expireTimeTZ=$(date -d @"$expireTime" "+%A %d %B %Y %T")
	
	expireTimeMail=$(date -d @"$expireTime" "+%s")

	now=$(date +%s)

	expireDays=$(echo $(( (${expireTimeMail} - ${now} )/(60*60*24) )))

  # Print debug information on STDERR when there is no mail
  if [ -z "${mail}" ];then
    echo "${MY_LOG_HEADER} No mail attribute (${MY_LDAP_MAIL_ATTR}) for user ${login}" >&2
  fi

	# ALL LDAP attributes should be there, else continue to next user
	if [ "${mail}" -a "${name}" \
		-a "${login}" -a "${diffTime}" -a "${pwdMaxAge}" ]
	then
		# Ajusts time with delay
		diffTime=$(expr "${diffTime}" + "${MY_MAIL_DELAY}")
		if [ "${diffTime}" -gt "${pwdMaxAge}" ]; then
			logmsg="${MY_MAIL_BODY}"
			logmsg=$(echo "${logmsg}" | sed "s/%name/${name}/; \
				s/%login/${login}/; s/%expireTimeTZ/${expireTimeTZ}/; s/%pwdMinLength/${pwdMinLength}/; s/%pwdInHistory/${pwdInHistory}/; \
				s/%expireDays/${expireDays}/")

			# Sending mail...
			echo "${logmsg}" | ${MY_MAIL_BIN} "${MY_MAIL_FROM}" -s "${MY_MAIL_SUBJECT}" "${mail}" >&2

			# Print debug information on STDERR
			echo "${MY_LOG_HEADER} Mail sent to user ${login} (${mail})" >&2

			# Increment warning counter
			nb_warning_users=$(expr "${nb_warning_users}" + 1)
		fi
	fi

done < ${result_file}

# Print statistics on STDOUT
echo "${MY_LOG_HEADER} --- Statistics ---"
echo "${MY_LOG_HEADER} Users checked: ${nb_users}"
echo "${MY_LOG_HEADER} Account expired: ${nb_expired_users}"
echo "${MY_LOG_HEADER} Account in warning: ${nb_warning_users}"

# Delete temporary files
rm -rf ${tmp_dir}

# Exit
exit 0
