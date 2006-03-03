#!/bin/sh

################################################################################
#
# Honeysnap -  simple snapshot summaries of outbound activity in a pcap file
#
# Version 0.6
# Release date 06/02/04
#
# (c) 2005, David Watson, Steve Mumford and Arthur Clune (UK Honeynet Project)
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
################################################################################
#
# CHANGELOG:
#
#    Version	Date		Description
#
#    v0.6	06/02/05	Internal alpha release
#
################################################################################
#
# Changes required before next release:
#
# Revert to using tethereal to detect packets by protocol type, not only port
# Reintroduce splitting and caching of per honeypot pcap files for speed
# Reinstate RRD graphing of trend data
# Replace unique DO_ input parameters with single import (a la perl do-opts)
# Consolidation of functions
# Standardisation and good practice, particularly around temp file writing 
# Internal code review and proper testing against multiple data sets (Kanga?)!
#
################################################################################
#
# New features for future releases:
#
# Alliance Beta testing
# Extra IRC reporting options:
#   number of messages
#   number of unique talker
#   number of unique hosts
#   number of unique channels
#   count of messages per channel
#   count of talkers per channel
#   new channels seen today
#   new talkers seen today per channel
#   new hosts seen today per channel
#   sysops names for each channel
#   splits/joins
#   average rate of messages per channel
#   average rate of messages per talker
#   alerts when these rates significantly alter from historical averages
#   number of unique key words
#   number of unique key words per channel
#   top 10 key words per channel
#   new words seen per day per channel
# Outbound URL reporting (and split GET/POST + USER/PASS requests)
# Better download handling (check for sucess codes first)
# FTP username and password reporting
# FTP directory listing reporting
# String checking against and DB of known:
#   IP addresses 
#   DNS names
#   IRC names
#   IRC keywords
#   Remote servers for download
#   Downloaded file MD5sums
#   HTTP URLs
#   Usernames / passwords
#   Filenames
#   Files in remote directory listings
#   Mail senders / recipients / subjects
#
#################################################################################
# Pre-requesite Software
#
# TCPdump       http://www.tcpdump.org/
# TCPflow       http://www.circlemud.org/~jelson/software/tcpflow/
# privmsg       http://www.honeynet.org/tools/danalysis/privmsg
#
################################################################################


#################################################################################
#
# Section 1 - Functions to configure Honeysnap
#
################################################################################
                                                                                
DATE=`date`

# There is a bug in tcpflow v0.21 that causes some FTP sessions to create
# text files of 2GB size on extract. A workaround is to cap the maximum
# tcpflow stream size. Tune this parameter if you hit a "grep: memory exhausted"# error (or even better, find the bug in the tcpflow source code and fix it!)
                                                                                
MAX_TCPFLOW_BYTES=5000000

# Function to return current date
#   No input variable required
#   Returns current date string

date() {
	echo $DATE
	return 0
}

# Function to display usage information
#   No input variable required
#   Returns usage information and exits with return code of 1

usage() {
	echo
	echo "No config file specified or found. Usage:"
	echo
	echo "$0 name_of_config_file"
	echo
        exit 1
}

# Function to read location of input directory from configuration file
#   Requires 1 input variable (name of config file)
#   Returns 1 output values:
#    - Input data directory string

input_data_directory() {
        local _configfile=$1 _input_data_directory
        if [ -f $_configfile ]
        then
          _input_data_directory=`grep INPUT_DATA_DIRECTORY $_configfile | awk -F= '{ print $2 }'`
          echo $_input_data_directory 
          return 0
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read location of output directory from configuration file
#   Requires 1 input variable (name of config file)
#   Returns 1 output values:
#    - Output data directory string

output_data_directory() {
        local _configfile=$1 _output_data_directory
        if [ -f $_configfile ]
        then
          _output_data_directory=`grep OUTPUT_DATA_DIRECTORY $_configfile | awk  -F= '{ print $2 }'`
          echo $_output_data_directory 
          return 0
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read location of output directory from configuration file
#   Requires 1 input variable (name of config file)
#   Returns 1 output values:
#    - Date mask to filter input data

datemask() {
        local _configfile=$1 _datemask 
        if [ -f $_configfile ]
        then
          _datemask=`grep DATEMASK $_configfile | awk -F= '{ print $2 }'`
          echo $_datemask 
          return 0
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read list of honeypots from config file
#   Requires 1 input variable (name of config file)
#   Returns 1 output values:
#    - Space seperated list of IP addresses

honeypots() {
        local _configfile=$1 _honeypots
        if [ -f $_configfile ]
        then
          _honeypots=`grep HONEYPOTS $_configfile | awk -F= '{ print $2 }'`
          echo $_honeypots
          return 0
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to merge multiple pcap files into one pcap file for analysis
#   Requires 1 input variable (name of config file)

pcap_merge() {
        local _directory=$1 _directory _pcap_count _pcaps

        if [ ! -d $_directory/pcap_unmerged ]
        then 
	  mkdir $_directory/pcap_unmerged
        fi 

        ls  $_directory | grep argus > /dev/null
        if [ $? -eq 0 ]
        then 
	  mv $_directory/*.argus $_directory/pcap_unmerged
        fi

        _pcap_count=`ls $_directory/pcap.* | wc -l`
        if [ $_pcap_count -gt 1 ]
	then
	  echo "Found multiple pcap file, merging."
          echo
	  mv $_directory/pcap.* $_directory/pcap_unmerged
	  _pcaps=`find $_directory/pcap_unmerged -type f | grep -v argus`
	  pcapmerge -o $_directory/pcap.merged $_pcaps
        else
          echo "No pcap merge necessary."
          echo
          return 0
        fi
}


# Function to read check config file to determine if packet analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO
                                                                                
do_packets() {
        local _configfile=$1 _do_packets
        if [ -f $_configfile ]
        then
          _do_packets=`grep DO_PACKETS $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_packets = YES ]
          then
            echo $_do_packets
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if telnet analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO
                                                                                
do_telnet() {
        local _configfile=$1 _do_telnet
        if [ -f $_configfile ]
        then
          _do_telnet=`grep DO_TELNET $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_telnet = YES ]
          then
            echo $_do_telnet
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if SSH analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO
                                                                                
do_ssh() {
        local _configfile=$1 _do_ssh
        if [ -f $_configfile ]
        then
          _do_ssh=`grep DO_SSH $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_ssh = YES ]
          then
            echo $_do_ssh
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if HTTP analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_http() {
        local _configfile=$1 _do_http
        if [ -f $_configfile ]
        then
          _do_http=`grep DO_HTTP= $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_http = YES ]
          then
            echo $_do_http
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if HTTPS analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO
                                                                                
do_https() {
        local _configfile=$1 _do_https
        if [ -f $_configfile ]
        then
          _do_https=`grep DO_HTTPS $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_https = YES ]
          then
            echo $_do_https
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if FTP analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_ftp() {
        local _configfile=$1 _do_ftp
        if [ -f $_configfile ]
        then
          _do_ftp=`grep DO_FTP $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_ftp = YES ]
          then
            echo $_do_ftp
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if SMTP analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_smtp() {
        local _configfile=$1 _do_smtp
        if [ -f $_configfile ]
        then
          _do_smtp=`grep DO_SMTP $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_smtp = YES ]
          then
            echo $_do_smtp
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if IRC analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_irc() {
        local _configfile=$1 _do_irc
        if [ -f $_configfile ]
        then
          _do_irc=`grep DO_IRC= $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_irc = YES ]
          then
            echo $_do_irc
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if summary IRC analysis
# is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_irc_summary() {
        local _configfile=$1 _do_irc_summary
        if [ -f $_configfile ]
        then
          _do_irc_summary=`grep DO_IRC_SUMMARY $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_irc_summary = YES ]
          then
            echo $_do_irc_summary
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if detailed IRC analysis
# is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_irc_detail() {
        local _configfile=$1 _do_irc_detail
        if [ -f $_configfile ]
        then
          _do_irc_detail=`grep DO_IRC_DETAIL $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_irc_detail = YES ]
          then
            echo $_do_irc_detail
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}


# Function to read check config file to determine if Sebek analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_sebek() {
        local _configfile=$1 _do_sebek
        if [ -f $_configfile ]
        then
          _do_sebek=`grep DO_SEBEK $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_sebek = YES ]
          then
            echo $_do_sebek
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if RRD analysis is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO

do_rrd() {
        local _configfile=$1 _do_rrd
        if [ -f $_configfile ]
        then
          _do_rrd=`grep DO_RRD $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_rrd = YES ]
          then
            echo $_do_rrd
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

# Function to read check config file to determine if file extraction is needed
#   Requires 1 input variable (name of config file)
#   Returns 1 output value:
#    - YES or NO
                                                                                
do_files() {
        local _configfile=$1 _do_files
        if [ -f $_configfile ]
        then
          _do_files=`grep DO_FILES $_configfile | awk -F= '{ print $2 }'`
          if [ $_do_files = YES ]
          then
            echo $_do_files
            return 0
          else
            echo NO
            return 0
          fi
        else
            echo Did not find file $_configfile
          return 1
        fi
}

#################################################################################
# Section 2 - Functions to do work on pcap files
#
################################################################################


# Function to parse pcap file and output number of packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot 
#   Returns 1 output value: count of packets

count_packets() {
        local _pcapfile=$1 _honeypot=$2 _count
	if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound IP packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and output number of telnet packets
# for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns 1 output value: count of telnet packets
                                                                                
count_telnet() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot and dst port 23 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound port 23 packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and output number of SSH packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns 1 output value: count of packets
                                                                                
count_ssh() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot and dst port 22 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound port 22 packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and output number of HTTP packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns 1 output value: count of HTTP packets
                                                                                
count_http_packets() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot and dst port 80 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound port 80 packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and output number of HTTPS packets 
# for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns 1 output value: count of HTTPS packets
                                                                                
count_https_packets() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot and dst port 443 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound port 443 packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and output number of FTP packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns 1 output value: count of FTP packets
                                                                                
count_ftp_packets() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot and dst port 21 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound port 21 packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and output number of SMTP packets for one honeypot#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns 1 output value: count of SMTP packets
                                                                                
count_smtp_packets() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot and dst port 25 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound port 25 packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and output number of IRC packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns 1 output value: count of IRC packets
                                                                                
count_irc_packets() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
	  `tcpdump -n -r $_pcapfile -w /tmp/$_honeypot.pcap host $_honeypot > /dev/null 2>&1` 
          _count=`tcpdump -n -r /tmp/$_honeypot.pcap src host $_honeypot and dst port 6667 2>&1 | wc -l`
	  `rm -f /tmp/$_honeypot.pcap`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count outbound port 6667 packets \($DATE\) ]
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file summarise  IRC privmsgs for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns count of all privmsgs plus individual keyword count

count_irc_summary() {
        local _pcapfile=$1 _honeypot=$2 _count _words _word _wordcount
	_words='0day 0-day access account admin auth bank bash \#\!\/bin binaries binary bot card cash cc cent connect crack credit dns dollar ebay e-bay egg flood ftp gid hackexploit http leech login money \/msg nologin owns ownz password paypal phish pirate pound probe prv putty remote resolved rlogin root rooted scam scan shell smtp sploit sterling sucess sysop sys-op trade uid uname uptime userid virus warez www xterm zeroday zero-day'

        if [ -f $_pcapfile ]
        then
	  `tcpdump -n -r $_pcapfile -w /tmp/$_honeypot.pcap host $_honeypot > /dev/null 2>&1`
	  `privmsg.pl -r /tmp/$_honeypot.pcap 2> /dev/null | grep -v "PRIVMSG colorized irc sniffer" > /tmp/privmsg.tmp`
	  `rm -f /tmp/$_honeypot.pcap`
          _count=`wc -l /tmp/privmsg.tmp | awk '{ print $1 }'`
          echo Honeypot: $_honeypot [ $_count IRC privmsgs ]
          if [ $_count -gt 0 ] && [ -f /tmp/privmsg.tmp ]
          then
            echo
            echo First 10 IRC messages:
            echo
            head -10 /tmp/privmsg.tmp
          fi
          for _word in $_words
          do
	    _wordcount=`grep $_word /tmp/privmsg.tmp | wc -l`
            if [ $_wordcount -gt 0 ]
            then
              printf " $_wordcount\t\t$_word\n" >> /tmp/privmsg_summary.tmp
            fi
          done
          if [ -f /tmp/privmsg_summary.tmp ]
          then
            echo
            echo IRC keyword summary:
            echo
            sort -rn /tmp/privmsg_summary.tmp
            echo
            rm -f /tmp/privmsg_summary.tmp
          fi
          if [ -f /tmp/privmsg.tmp ]
          then
            rm -f /tmp/privmsg.tmp
          fi
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and display IRC privmsgs for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns all privmsgs for individual keywords

count_irc_detail() {
        local _pcapfile=$1 _honeypot=$2 _count _words _word _wordcount
        _words='0day access account admin auth bank bash \#\!\/bin binaries binary bot card cash cc cent connect crack credit dns dollar ebay e-bay egg flood ftp hackexploit http leech login money \/msg nologin owns ownz password paypal phish pirate pound probe prv putty remote resolved root rooted scam scan shell smtp sploit sterling sucess sysop sys-op trade uid uname uptime userid virus warez'

        if [ -f $_pcapfile ]
        then
	  `tcpdump -n -r $_pcapfile -w /tmp/$_honeypot.pcap host $_honeypot > /dev/null 2>&1`
          `privmsg.pl -r /tmp/$_honeypot.pcap 2> /dev/null | grep -v "PRIVMSG colorized irc sniffer" | uniq > /tmp/privmsg.tmp`
	  `rm -f /tmp/$_honeypot.pcap`
          _count=`wc -l /tmp/privmsg.tmp | awk '{ print $1 }'`
          if [ $_count -gt 0 ] && [ -f /tmp/privmsg.tmp ]
          then
            echo Detailed report for IRC keyword matches:
            echo
            for _word in $_words
            do
              _wordcount=`grep $_word /tmp/privmsg.tmp | wc -l`
              if [ $_wordcount -gt 0 ]
              then
                echo IRC keyword $_word:
                echo 
                grep $_word /tmp/privmsg.tmp
                echo 
              fi
            done
          fi
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and extract files downloaded via HTTP for
# one honeypot
#   Requires 3 input variables:
#     name of pcap file
#     IP address of honeypot
#     name of output directory
#   Returns list of files
                                                                                
extract_http() {
        local _pcapfile=$1 _honeypot=$2 _outputdir=$3 _httpsessions _httpsession _httpsource _httpsourceport _httpdest _httpdestport _httpfile _size _type
        if [ -f $_pcapfile ]
        then
          if [ ! -d $_outputdir/tcpflows ]
          then
            mkdir -p $_outputdir/tcpflows
          fi
          cd $_outputdir/tcpflows
          tcpflow -b $MAX_TCPFLOW_BYTES -r $_pcapfile* src host $_honeypot and dst port 80
          _httpsessions=`find . -type f | grep 00080 | sed -e 's/^..//g' -e 's/\-/./g'`
          if [ $? -eq 0 ]
          then
            for _httpsession in $_httpsessions
            do
              _httpsource=`echo $_httpsession | awk -F. '{ print $1 "." $2 "." $3 "." $4 }'`
              _httpsourceport=`echo $_httpsession | awk -F. '{ print $5 }'`
              _httpdest=`echo $_httpsession | awk -F. '{ print $6 "." $7 "." $8 "." $9 }'`
              _httpdestport=`echo $_httpsession | awk -F. '{ print $10 }'`
              tcpflow -b $MAX_TCPFLOW_BYTES -r $_pcapfile* src host $_httpdest and src port 80
              _httpfile=`sed -e 's///g' "${_httpsource}.${_httpsourceport}-${_httpdest}.${_httpdestport}" | grep -i ^GET | awk '{ print $2 }' | sed -e 's#.*/##g'`
              if [ ! -d ../extracted_files/http ]
              then
                mkdir -p ../extracted_files/http
              fi
              if [ ! -d ../extracted_files/http/$_httpdest ]
              then
                mkdir -p ../extracted_files/http/$_httpdest
              fi
              cp "${_httpdest}.${_httpdestport}-${_httpsource}.${_httpsourceport}" ../extracted_files/http/$_httpdest/$_httpfile
              _type=`file ../extracted_files/http/$_httpdest/$_httpfile | awk '{ print $2 }'`
              _size=`du -sk ../extracted_files/http/$_httpdest/$_httpfile | awk '{ print $1 }'`
              echo extracted_files/http/$_httpdest/$_httpfile \(type $_type size $_size KBytes\) >> /tmp/.http-files
            done
          fi
          if [ -f /tmp/.http-files ]
          then
            echo
            echo Files downloaded using HTTP:
            echo
            sort -u /tmp/.http-files | grep -v "/$"
            echo
            rm -f /tmp/.http-files
          fi
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and extract files downloaded via FTP for
# one honeypot
#   Requires 3 input variables:
#     name of pcap file
#     IP address of honeypot
#     name of output directory
#   Returns list of files

extract_ftp() {
        local _pcapfile=$1 _honeypot=$2 _outputdir=$3 _ftpsessions _ftpsession _activesessions _activesession _passivesessions _passivesession _server _port256 _port1 _port _activeretrs _activeretr _passiveretrs _passiveretr _headnum _activecmd _activecmdtest _passivecmd _passivecmdtest _activefile _passivefile _type _size _portlines _portline _portretr _pasvlines _pasvlines _portretr _padpot _padserver
        if [ -f $_pcapfile ]
        then
          if [ ! -d $_outputdir ]
          then
            mkdir -p $_outputdir/tcpflows
          fi
          cd $_outputdir/tcpflows
          tcpflow -b $MAX_TCPFLOW_BYTES -r $_pcapfile* host $_honeypot and port 21
          _ftpsessions=`find . -type f | grep 00021$`
          
          if [ $? -eq 0 ]
          then
            for _ftpsession in $_ftpsessions
            do
              dos2unix $_ftpsession > /dev/null 2>&1

              # Extract active FTP sessions using the PORT command
              _activesessions=`grep -in ^PORT $_ftpsession | awk -F: '{ print $1 }'`
              if [ $? -eq 0 ]
              then 
                for _activesession in $_activesessions
                do
                  _portlines=`grep -ni ^PORT $_ftpsession | awk -F: '{ print $1 }'`
                  for _portline in $_portlines 
                  do
                    _padpot=`echo $_ftpsession | sed -e 's/\.\///g' | awk -F. '{ print $1 "." $2 "." $3 "." $4 }'`
                    _server=`head -$_portline $_ftpsession | tail -1 | awk '{ print $2 }' | awk -F, '{ print $1 "." $2 "." $3 "." $4 }' | dos2unix`
                    _padserver=`echo $_ftpsession | awk -F- '{ print $2 }' | awk -F. '{ print $1 "." $2 "." $3 "." $4 }'`
                    _port256=`head -$_portline $_ftpsession | tail -1 | awk '{ print $2 }' | awk -F, '{ print $5 }' | dos2unix`
                    _port1=`head -$_portline $_ftpsession | tail -1 | awk '{ print $2 }' | awk -F, '{ print $6 }' | dos2unix`
                    if [ ! -z $_port256 ] && [ ! -z $_port1 ]
                    then
                      _port=$((($_port256*256)+$_port1))
                      _retrline=$(($_portline+1))
                      _activefile=`head -$_retrline $_ftpsession | tail -1 | awk '{ print $2 }' | dos2unix`
 
                      tcpflow -b $MAX_TCPFLOW_BYTES -r $_pcapfile* host \($_server and $_honeypot\) and port $_port
                      if [ ! -d ../extracted_files/ftp ]
                      then
                        mkdir -p ../extracted_files/ftp
                      fi
                      if [ ! -d ../extracted_files/ftp/$_server ]
                      then
                        mkdir -p ../extracted_files/ftp/$_server
                      fi
                      cp $_padserver.00020-$_padpot.$_port ../extracted_files/ftp/$_server/$_activefile
                      _type=`file ../extracted_files/ftp/$_server/$_activefile | awk '{ print $2 }'`
                      _size=`du -sk ../extracted_files/ftp/$_server/$_activefile | awk '{ print $1 }'`
                      echo extracted_files/ftp/$_server/$_activefile \(type $_type size $_size KBytes\) >> /tmp/.ftp-files
                     fi
                  done
                done
              fi

              # Extract passive FTP sessions using the PASV command
              _passivesessions=`grep -in ^PASV $_ftpsession | awk -F: '{ print $1 }'`
              if [ $? -eq 0 ]
              then
                for _passivesession in $_passivesessions
                do
                  _pasvlines=`grep -ni ^PASV $_ftpsession | awk -F: '{ print $1 }'`
                  for _pasvline in $_pasvlines
                  do
                    _padpot=`echo $_ftpsession | sed -e 's/\.\///g' | awk -F. '{ print $1 "." $2 "." $3 "." $4 }'`
                    _server=`head -$_pasvline $_ftpsession | tail -1 | awk '{ print $2 }' | awk -F, '{ print $1 "." $2 "." $3 "." $4 }' | dos2unix`
                    _padserver=`echo $_ftpsession | awk -F- '{ print $2 }' | awk -F. '{ print $1 "." $2 "." $3 "." $4 }'`
                    _port256=`head -$_pasvline $_ftpsession | tail -1 | awk '{ print $2 }' | awk -F, '{ print $5 }' | dos2unix`
                    _port1=`head -$_pasvline $_ftpsession | tail -1 | awk '{ print $2 }' | awk -F, '{ print $6 }' | dos2unix`
                    if [ ! -z $_port256 ] && [ ! -z $_port1 ]
                    then 
                      _port=$((($_port256*256)+$_port1))
                      _pasvretr=$(($_pasvline+1))
                      _passivefile=`head -$_pasvretr $_ftpsession | tail -1 | awk '{ print $2 }' | dos2unix`
                      tcpflow -b $MAX_TCPFLOW_BYTES -r $_pcapfile* host \($_server and $_honeypot\) and port $_port
                      if [ ! -d ../extracted_files/ftp ]
                      then
                        mkdir -p ../extracted_files/ftp
                      fi
                      if [ ! -d ../extracted_files/ftp/$_server ]
                      then
                        mkdir -p ../extracted_files/ftp/$_server
                      fi
                      cp $_padserver.*-$_padpot.$_port ../extracted_files/ftp/$_server/$_passivefile
                      _type=`file ../extracted_files/ftp/$_server/$_passivefile | awk '{ print $2 }'`
                      _size=`du -sk ../extracted_files/ftp/$_server/$_passivefile | awk '{ print $1 }'`
                      echo extracted_files/ftp/$_server/$_passivefile \(type $_type size $_size KBytes\) >> /tmp/.ftp-files
                    fi
                  done
                done
              fi
            done
          fi
          if [ -f /tmp/.ftp-files ]
          then
            echo
            echo Files downloaded using FTP:
            echo
            sort -u /tmp/.ftp-files | grep -v "/$"
            echo
            rm -f /tmp/.ftp-files
          fi
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

# Function to parse pcap file and extract messages sent via SMTP for
# one honeypot
#   Requires 3 input variables:
#     name of pcap file
#     IP address of honeypot
#     name of output directory
#   Returns list of messages

extract_smtp() {
        local _pcapfile=$1 _honeypot=$2 _outputdir=$3 _smtpsessions _smtpsession _rcpt_to _subject _count
        if [ -f $_pcapfile ]
        then
          if [ ! -d $_outputdir/tcpflows ]
          then
            mkdir -p $_outputdir/tcpflows
          fi
          cd $_outputdir/tcpflows
          tcpflow -b $MAX_TCPFLOW_BYTES -r $_pcapfile* src host $_honeypot and dst port 25
          _smtpsessions=`find . -type f | grep 00025`

          _count=0
          for _smtpsession in $_smtpsessions
          do 
              if [ ! -d ../extracted_files/smtp ]
              then
                mkdir -p ../extracted_files/smtp
              fi
              let _count=_count+1
              cp $_smtpsession ../extracted_files/smtp/mail-message-$_count

            _rcpt_to=`grep -i "rcpt to" $_smtpsession`
            if [ $? -eq 0 ] 
            then
              echo $_rcpt_to >> /tmp/.smtp-messages
            fi
            _subject=`grep -i "subject" $_smtpsession`
            if [ $? -eq 0 ] 
            then
              echo $_subject >> /tmp/.smtp-messages
              echo >> /tmp/.smtp-messages
            fi
          done

          if [ -f /tmp/.smtp-messages ]
          then
            echo
            echo Outbound SMTP messages:
            echo
            cat /tmp/.smtp-messages
            rm -f /tmp/.smtp-messages
          fi
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}


# Function to parse pcap file and output sebek keystroke logs for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns count of all sebek keystokes plus listing of interesting ones

count_sebek() {
        local _pcapfile=$1 _honeypot=$2 _count
        if [ -f $_pcapfile ]
        then
          _count=`tcpdump -n -r $_pcapfile src host $_honeypot and udp port 1101 2>&1 | wc -l`
          let _count=_count-1
          echo Honeypot: $_honeypot [ $_count Sebek packets \($DATE\) ]
          if [ $_count -gt 0 ]
          then 
            echo
            sbk_extract -f $_pcapfile 2> /dev/null | sbk_ks_log.pl grep -v "[0-9]\]$" | grep $_honeypot | grep -v prelink
            echo
          fi
          return 0
        else
          echo Did not find pcap file $_pcapfile for honeypot $_honeypot
          return 1
        fi
}

#################################################################################
# Section 3 - Main Program Structure to call the functions
#
################################################################################

# Check config file exists, or display usage information

if [ ! -f $1 ] || [ -z $1 ]
then
  usage
fi

# Set up screen

clear
echo Starting honeysnap analysis at $(date)
echo
                                                                                
# Read configuration data and set variables

INPUT_DATA_DIRECTORY=`input_data_directory $1`
OUTPUT_DATA_DIRECTORY=`output_data_directory $1`
DATEMASK=`datemask $1`
HONEYPOTS=`honeypots $1`
DO_PACKETS=`do_packets $1`
DO_TELNET=`do_telnet $1`
DO_SSH=`do_ssh $1`
DO_HTTP=`do_http $1`
DO_HTTPS=`do_https $1`
DO_FTP=`do_ftp $1`
DO_SMTP=`do_smtp $1`
DO_IRC=`do_irc $1`
DO_IRC_SUMMARY=`do_irc_summary $1`
DO_IRC_DETAIL=`do_irc_detail $1`
DO_SEBEK=`do_sebek $1`
DO_RRD=`do_rrd $1`
DO_FILES=`do_files $1`

# Determine list of directories containing honeywall snort data for analysis,
# filtered by datemask

DATES=`ls $INPUT_DATA_DIRECTORY | grep $DATEMASK` 

# Main program loop to perform a series of actions for each date against each 
# honeypot 

for DATE in $DATES
do
  echo Analysing pcap data in $INPUT_DATA_DIRECTORY/$DATE
  echo

  echo Checking for multiple pcap files to merge, please wait.
  pcap_merge $INPUT_DATA_DIRECTORY/$DATE

  if [ $DO_PACKETS = YES ]
  then
    echo Counting outbound IP packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_packets $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
    done
    echo
  fi

  if [ $DO_TELNET = YES ]
  then
    echo Counting outbound Telnet packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_telnet $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
    done
    echo
  fi

  if [ $DO_SSH = YES ]
  then
    echo Counting outbound SSH packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_ssh $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
    done
    echo
  fi

  if [ $DO_HTTP = YES ]
  then
    echo Counting outbound HTTP packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_http_packets $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
      if [ $DO_FILES = YES ]
      then
        extract_http $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT $OUTPUT_DATA_DIRECTORY/$DATE/$HONEYPOT
      fi
    done
    echo
  fi

  if [ $DO_HTTPS = YES ]
  then
    echo Counting outbound HTTPS packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_https_packets $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
    done
    echo
  fi

  if [ $DO_FTP = YES ]
  then
    echo Counting outbound FTP packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_ftp_packets $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
      if [ $DO_FILES = YES ]
      then
        extract_ftp $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT $OUTPUT_DATA_DIRECTORY/$DATE/$HONEYPOT
      fi
    done
    echo
  fi

  if [ $DO_SMTP = YES ]
  then
    echo Counting outbound SMTP packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_smtp_packets $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
      if [ $DO_FILES = YES ]
      then
        extract_smtp $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT $OUTPUT_DATA_DIRECTORY/$DATE/$HONEYPOT
      fi

    done
    echo
  fi
                                                                                
  if [ $DO_IRC = YES ]
  then
    echo Counting outbound IRC packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_irc_packets $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
    done
    echo
  fi
               
  if [ $DO_IRC_SUMMARY = YES ]
  then
    echo Analysing IRC privsmgs:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_irc_summary $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
      if [ $DO_IRC_DETAIL = YES ]
      then
        count_irc_detail $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
      fi
    done
  fi

  if [ $DO_SEBEK = YES ]
  then
    echo
    echo Counting Sebek packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
      count_sebek $INPUT_DATA_DIRECTORY/$DATE/pcap.* $HONEYPOT
    done
    echo
  fi

  if [ $DO_RRD = YES ]
  then
    for HONEYPOT in $HONEYPOTS
    do
      echo RRD temporarily unavailable.
    done
    echo
  fi

done
   
echo
echo Completed honeysnap analysis at `/bin/date`
