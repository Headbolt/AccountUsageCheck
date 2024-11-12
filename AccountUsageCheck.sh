#!/bin/bash
#
###############################################################################################################################################
#
# ABOUT THIS PROGRAM
#
#	AccountUsageCheck.sh
#	https://github.com/Headbolt/AccountUsageCheck
#
#   This Script is designed for use in JAMF as scriptan Extension Attribute
#
#   - This script will ...
#		Check the Logs to see if the specified user account has been used
#		Either By Login, Sudo'ing as it, or Athenticating as it to elevate priveledges
#		and will then trigger a policy to change the password if used within the time range
#
#	The Following Variables should be defined
#	Variable 4 - Named "User Account - eg. Administrator"
#	Variable 5 - Named "Range. In the format xm xh xd for minutes, hours, days eg. 12h"
#	Variable 6 - Named "Marker File Name - eg. .PasswordToBeReset"
#	Variable 7 - Named "Password Change policy trigger - eg. AdminLAPS"
#
###############################################################################################################################################
#
# HISTORY
#
#	Version: 1.0 - 12/11/2024
#
#	12/11/2024 - V1.0 - Created by Headbolt
#
###############################################################################################################################################
#
#   DEFINE VARIABLES
#
###############################################################################################################################################
#
User=$4 # Grab the name of the user to check from JAMF variable #4 eg. Administrator
Range=$5 # Grab the time range to check from JAMF variable #5 eg. 8h
MarkerFileName=$6 # Grab the name of the marker file to use/check from JAMF variable #4 eg. .PasswordToBeReset
PolicyTrigger=$7 # Grab the policy trigger to use is a password reset is required from JAMF variable #7 eg. ADMINRESET
#
MarkerFolder="/Users/$User/Library/Application Support/JAMF/Marker Files" # Sets the folder marker file to live in
MarkerFile="$MarkerFolder/$MarkerFileName" # Sets the full path to the Marker file for ease of scripting use
AccountUsed=NO # Sets to an Initial Value
#
ScriptVer=v1.0
ScriptName="Security | Password Usage Check" # Sets Script Name
ExitCode=0 # Sets Default Exit Code as successful
#
###############################################################################################################################################
#
#   Checking and Setting Variables Complete
#
###############################################################################################################################################
# 
# SCRIPT CONTENTS - DO NOT MODIFY BELOW THIS LINE
#
###############################################################################################################################################
#
# Defining Functions
#
###############################################################################################################################################
#
# Script Start Function
#
ScriptStart(){
#
/bin/echo # Outputting a Blank Line for Reporting Purposes
SectionEnd
/bin/echo Starting Script '"'$ScriptName'"'
/bin/echo Script Version '"'$ScriptVer'"'
/bin/echo # Outputting a Blank Line for Reporting Purposes
/bin/echo  ----------------------------------------------- # Outputting a Dotted Line for Reporting Purposes
/bin/echo # Outputting a Blank Line for Reporting Purposes
#
}
#
###############################################################################################################################################
#
# Marker Time Check Function
#
MarkerTimeCheck(){
#
MarkerStamp="" # Ensuring MarkerStamp Variable is initially blank
/bin/echo 'Checking if Marker File "'$MarkerFile'" Exists'
FileExist=$(ls -l "$MarkerFile" 2>&1) # Check if Marker File Exists
#
if [[ $FileExist == "ls: $MarkerFile: No such file or directory" ]] # Examine result of FileCheck
	then
    	/bin/echo # Outputting a Blank Line for Reporting Purposes
		/bin/echo 'Marker File does NOT exist'
	else
    	/bin/echo # Outputting a Blank Line for Reporting Purposes
		MarkerStamp=$(date -r "$MarkerFile" +"%s") # Grabbing TimeStamp in Epoch Time
		/bin/echo 'Marker File exists with Epoch stamp "'$MarkerStamp'"'
fi
#
}
################################################################################################################################################
#
# Marker Age Check Function
#
MarkerAgeCheck(){
#
CurrentTimeStamp=$(date +"%s") # Grabbing current time in Epoch Time
/bin/echo 'Checking age of Marker File compared to current time'
#
/bin/echo # Outputting a Blank Line for Reporting Purposes
/bin/echo 'Marker File exists with Epoch stamp "'$MarkerStamp'"'
/bin/echo 'Current time in Epoch time is "'$CurrentTimeStamp'"'
/bin/echo # Outputting a Blank Line for Reporting Purposes
TimeDiff=$(($CurrentTimeStamp - $MarkerStamp)) # Find relative file age
/bin/echo 'Relative age of Marker file in Epoch time is "'$TimeDiff'"'
#
RangeInteger=$(/bin/echo $Range | cut -c -2) # Pull out just the interger from the desired time range
#
if [[ $(/bin/echo $Range | grep m) != "" ]] # Check if log result indicates User has Authenticated
	then
		RangeTargetAge=$(($RangeInteger * 60)) # Check if range is in Minutes
		/bin/echo 'RangeTargetAge is '$RangeInteger' Minutes, which is '$RangeTargetAge' as an Epoch time difference'
	else
		if [[ $(/bin/echo $Range | grep h) != "" ]] # Check if range is in Mours
			then
				RangeTargetAge=$(($RangeInteger * 60 * 60))
				/bin/echo 'RangeTargetAge is '$RangeInteger' Hours, which is '$RangeTargetAge' as an Epoch time difference'
			else
				if [[ $(/bin/echo $Range | grep d) != "" ]] # Check if range is in Days        
					then
						RangeTargetAge=$(($RangeInteger * 60 * 60 * 24))
						/bin/echo 'RangeTargetAge is '$RangeInteger' Days, which is '$RangeTargetAge' as an Epoch time difference'
					else
						/bin/echo 'Range is in an unsupported format'
						ExitCode=3 # Wrong Format, exit
						ScriptEnd
				fi
		fi
fi
#
/bin/echo # Outputting a Blank Line for Reporting Purposes
#
if [ $RangeTargetAge -le $TimeDiff ] # Check if we have reached the target age
	then
		/bin/echo 'Age of the marker file has reached the desired value, password change being triggered'
		/bin/echo 'Running command "/usr/local/bin/jamf policy -trigger '$PolicyTrigger' &"'
		/usr/local/bin/jamf policy -trigger $PolicyTrigger & # Run desired policy trigger
		SectionEnd
		MarkerCleanup
	else 
		/bin/echo 'Age of the marker file has not yet reached the desired value, password change not yet required'
fi
#
}
#
###############################################################################################################################################
#
# Account Check Function
#
AccountCheck(){
#
/bin/echo 'Checking if account "'$User'" has been used in the last "'$Range'"'
#
LogDumpAuth=$(log show --style syslog --last $Range | grep "Validating credential $User") # Look for "Validating credential" for the User
#
if [[ $LogDumpAuth == "" ]] # Check if log result indicates User has Authenticated
	then
		LogDumpSudo=$(log show --style syslog --last $Range | grep sudo | grep $User) # Look for "Sudo" for the User
		if [[ $LogDumpSudo == "" ]]  # Check if log result indicates User has been SUDO'd
			then
				LogDumpLogin=$(log show --style syslog --last $Range | grep 'User "'$User'" is logged in') # Look for "Log In" for the User
				if [[ $LogDumpLogin == "" ]]  # Check if log result indicates User has Logged In
					then
						AccountUsed=NO
					else
						AccountUsed=LOGIN
				fi
			else
				AccountUsed=SUDO
		fi
	else
		AccountUsed=AUTH
fi
#
if [[ $AccountUsed != "NO" ]]
	then
		SectionEnd
		MarkerWrite
fi
#
}
#
###############################################################################################################################################
#
# Marker File Write Function
#
MarkerWrite(){
#
FolderCreate=$(mkdir "/Users/$User/Library/Application Support/JAMF" 2>&1) # Make Sure the folder path exists
FolderCreate=$(mkdir "/Users/$User/Library/Application Support/JAMF/Marker Files" 2>&1) # Make Sure the folder path exists
#
/bin/echo 'Creating MarkerFile "'$MarkerFile'"'
/bin/echo MarkerFile > "$MarkerFile"
#
}
#
###############################################################################################################################################
#
# Marker Cleanup Function
#
MarkerCleanup(){
#
/bin/echo 'Cleaning up MarkerFile'
/bin/echo 'Running command "rm -R '$MarkerFile'"'
rm -R "$MarkerFile" # Delete MarkerFile now the password reset has been triggered
#
}
#
###############################################################################################################################################
#
# Section End Function
#
SectionEnd(){
#
/bin/echo # Outputting a Blank Line for Reporting Purposes
/bin/echo  ----------------------------------------------- # Outputting a Dotted Line for Reporting Purposes
/bin/echo # Outputting a Blank Line for Reporting Purposes
#
}
#
###############################################################################################################################################
#
# Script End Function
#
ScriptEnd(){
#
/bin/echo Ending Script '"'$ScriptName'"'
/bin/echo "With Exit code $ExitCode"
/bin/echo # Outputting a Blank Line for Reporting Purposes
/bin/echo  ----------------------------------------------- # Outputting a Dotted Line for Reporting Purposes
/bin/echo # Outputting a Blank Line for Reporting Purposes
#
exit $ExitCode
#
}
#
###############################################################################################################################################
#
# End Of Function Definition
#
###############################################################################################################################################
# 
# Begin Processing
#
###############################################################################################################################################
#
ScriptStart
#
MarkerTimeCheck
SectionEnd
#
if [[ $MarkerStamp == "" ]] # Check if log result indicates User has Authenticated
	then
    	AccountCheck
	else
		MarkerAgeCheck
fi
#
SectionEnd
ScriptEnd
