#!/bin/sh

# This is the full path to the the OpenSSL executable
# on your system.  If you don't know where it is, try
# typing "which openssl" on a command line.
#
openssl="/usr/bin/openssl"

if [ -x $openssl ]; then
 if [ "$1" ]; then
  case $1 in
   --version)
    $openssl version
    retval=$?
   ;;
   --verify-dkim-msg)
    if [ "$2" -a "$3" -a "$4" -a "$5" ]; then
     tmpalgo=$2
     tmpmsg=$3
     tmppub=$4
     tmpsig=$5
     $openssl dgst -$tmpalgo -verify $tmppub -signature $tmpsig $tmpmsg 2>&1
     retval=$?
     if [ $retval -eq "Verification OK" ]; then
      retval = 1
     else
      retval = 0
     fi
    else
     retval=-1
    fi
   ;;
   *)
    retval=-1
  esac
 else
  retval=-1
 fi
else
 retval=-1
fi
exit $retval
