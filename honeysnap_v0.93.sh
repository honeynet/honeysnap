#!/bin/bash

################################################################################
#
# Honeysnap -  simple snapshot summaries of outbound activity in a pcap file
#
# Version 0.9
# Release date 08/12/04
#
# (c) 2005, David Watson, Steve Mumford and Arthur Clune (UK Honeynet Project)
#
# $Id: honeysnap,v 1.25 2006/08/18 10:18:29 arthur Exp $
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
#    v0.93      17/09/06        Now uses latest privmsg.pl
#    v0.92      15/09/06        More bugs in FTP handling fixed AJC
#    v0.9       08/12/05        Final sh version. Changed input file handling AJC/DW
#    v0.8       13/11/05        Fixed ftp handling (I hope!)  AJC
#    v0.7a      16/09/05        Updated for new honeypot file locations, fixed check_file    AJC
#    v0.7       27/04/05        Change to config file handling. Other minor fixes AJC
#    v0.6	    06/02/05	    Internal alpha release DW
#
################################################################################
#
# Changes required before next release:
#
# This is the final sh release. A complete re-write in Python will replace this version
#
################################################################################
#
#################################################################################
# Pre-requisite Software
#
# TCPdump       http://www.tcpdump.org/
# tethereal     http://www.ethereal.com
# TCPflow       http://www.circlemud.org/~jelson/software/tcpflow/
# snort         http://www.snort.org (optional)
# privmsg       In this tarball or from http://www.honeynet.org/tools/danalysis/privmsg
# analyse_irc   In this tarball
#
################################################################################


#################################################################################
#
# Section 1 - Helper functions
#
################################################################################

DATE=`date  +"%d%m%y_%H%M"`

# Function to display usage information
#   No input variable required
#   Returns usage information and exits with return code of 1

usage() {
    echo "Usage: $0 <config_file> <output_dir> <pcap_file>"
    exit 1
}


# remember, this is sh. 0 = TRUE, non-zero = FALSE
check_file() {
    local _file=$1
    if [ -f $_file ]
    then
        return 0
    else
        return 1
    fi
}

# safely create a directory
safe_create_dir() {    
    local _dir=$1
    if [ -e $_dir ]
    then
	if [ ! -d $_dir ]
	then 
	    exit 1
	fi
    else
	mkdir -p $_dir
    fi    
}

# make a path absolute
# pass in a variable name and a path. Stores the absolute path in the variable
make_absolute() {
    local _path=$2
    local _base=`pwd`
    if [ ! `echo $_path | sed -n -e '/^\//p'` ]
    then
	_path="$_base/$_path"
    fi
    eval "$1=\$_path"
}

# md5sum (Linux) and md5 (BSD) return slightly different formats
# call as 
#_fred=`generic_md5 file`
# since bash doesn't do return values properly
generic_md5() {
    local _file=$1 _md5
    _md5=`$MD5SUM $_file`
    if [ `echo $_md5 | sed -e '/^MD5/n' | cut -d ' ' -f1` ]
    then
	# md5/bsd
	_md5=`echo $_md5 | cut -d'=' -f2|sed -e 's/^ //'`
    else
	# md5sum/linux
	_md5=`echo $_md5 | awk ' { print $1 } '  `
    fi
    echo $_md5
}


# check that a given binary exists and is executable
# pass in the name of a config variable as a string
check_exe() {
    local _file=$1 
    _file="\$${_file}"
    eval "_file=$_file"
    if [ -x $_file ]
    then
	return 0
    else
	echo Can\'t execute $_file !
	exit 1
    fi
}


# split a http download into header and data
# headfile is called <file.hdr>. Data is stored in original file
split_file() {
    local _file=$1
    # oh for a proper language!    
    $PERL -n -e 'if(/^$/ or /^\r$/) { $split=1;} print unless $split' $_file > $_file.hdr
    $PERL -n -e 'if(/^$/ or /^\r$/) { $split=1; next} print if $split' $_file > $_file.tmp
    mv $_file.tmp $_file
}
    
# return file info
file_info() {
    local _file=$2  
    _type=`file $_file | cut -d':' -f 2| sed -e 's/^ //'`
    _size=`du -sk $_file | $AWK '{ print $1 }'`
    _md5=`generic_md5 $_file | $AWK '{ print $1}'`
    eval "$1=\"$dstfile (type $_type size $_size KBytes md5 $_md5)\""
}

#################################################################################
# Section 2 - Functions to do work on pcap files
#
################################################################################

# Function to provide information on pcap files using capinfo

do_capinfo(){
    local _pcapfile=$1
    $CAPINFO $_pcapfile
}

# Function to run snort over the pcap file if required

do_snort(){
    local _pcapfile=$1 _output=$2 _snortnet=$3 
    safe_create_dir $_output/snort ] 
    echo Running snort over file $_pcapfile
    $SNORT $SNORT_OPTS -r $_pcapfile -l $_output/snort -h $_snortnet
}


# Function to parse pcap file and output number of packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot 
#   prints count of packets

count_packets() {
    local _pcapfile=$1 _honeypot=$2 _count
    _count=`$TCPDUMP -n -r $_pcapfile src host $_honeypot 2>&1 | wc -l`
    let _count=_count-1
    echo Honeypot: $_honeypot [ $_count outbound IP packets ]
}

# generic "Count packets on port N function
# requries three input vars : pcapfile, IP of honeypot and port
# print out count of packets on port
count_generic() {
    local _pcapfile=$1 _honeypot=$2 _port=$3 _count
     _count=`$TCPDUMP -n -r $_pcapfile src host $_honeypot and dst port $_port 2>&1 | wc -l`
    let _count=_count-1
    echo Honeypot: $_honeypot [ $_count outbound port $_port packets ]
}

# Function to parse pcap file and output number of telnet packets
#   Requires 2 input variables: name of pcap file and IP address of honeypot
count_telnet() {
    count_generic $1 $2 23
}

# Function to parse pcap file and output number of SSH packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
count_ssh() {
    count_generic $1 $2 22
}

# Function to parse pcap file and output number of HTTP packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
count_http_packets() {
    local _pcapfile=$1 _honeypot=$2 _count
    count_generic $1 $2 80
    _count=`$TCPDUMP -n -r $_pcapfile dst host $_honeypot and dst port 80 2>&1 | wc -l`
    let _count=_count-1
    echo Honeypot: $_honeypot [ $_count served port 80 packets ]
}
    
# Function to parse pcap file and output number of HTTPS packets 
# for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
    
count_https_packets() {
    local _pcapfile=$1 _honeypot=$2 _count
    count_generic $1 $2 443
    _count=`$TCPDUMP -n -r $_pcapfile dst host $_honeypot and dst port 443 2>&1 | wc -l`
    let _count=_count-1
    echo Honeypot: $_honeypot [ $_count served port 443 packets ]
}

# Function to parse pcap file and output number of FTP packets for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot

count_ftp_packets() {
    count_generic $1 $2 20
}

# Function to parse pcap file and output number of SMTP packets for one honeypo
#   Requires 2 input variables: name of pcap file and IP address of honeypot

count_smtp_packets() {
    count_generic $1 $2 25
}

# Function to parse pcap file and display IRC privmsgs for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns all privmsgs for individual keywords

do_irc() {
    local _pcapfile=$1 _honeypot=$2 _detail=$3 _count _words _word _wordcount
    _words=$IRC_WORDS
    $TCPDUMP -n -r $_pcapfile -w $TMP_DATA_DIRECTORY/$_honeypot.pcap host $_honeypot > /dev/null 2>&1
    $PRIVMSG -d -v 0 -i -r $TMP_DATA_DIRECTORY/$_honeypot.pcap > $TMP_DATA_DIRECTORY/privmsg.tmp
    rm -f $TMP_DATA_DIRECTORY/$_honeypot.pcap	
    _count=`wc -l $TMP_DATA_DIRECTORY/privmsg.tmp | awk '{ print $1 }'`
    echo Honeypot: $_honeypot [ $_count IRC privmsgs ]
    if [ $_detail = "YES" ]
    then
	if [ $_count -gt 0 ] && [ -f $TMP_DATA_DIRECTORY/privmsg.tmp ]
	then
	    echo Detailed report for IRC keyword matches:
	    $ANALYSE_IRC -s $TMP_DATA_DIRECTORY/privmsg_summary.tmp $TMP_DATA_DIRECTORY/privmsg.tmp > $TMP_DATA_DIRECTORY/irc.details
	    echo
	    cat $TMP_DATA_DIRECTORY/privmsg_summary.tmp
	    echo
	    if [ $PRINT_IRC = YES ] 
	    then
		echo
		cat $TMP_DATA_DIRECTORY/irc.details
		echo
	    fi

	    mv $TMP_DATA_DIRECTORY/privmsg.tmp $OUTPUT_DATA_DIRECTORY/privmsg.$HONEYPOT
	    mv $TMP_DATA_DIRECTORY/privmsg_summary.tmp $OUTPUT_DATA_DIRECTORY/privmsg_summary.$HONEYPOT
	    mv $TMP_DATA_DIRECTORY/irc.details $OUTPUT_DATA_DIRECTORY/irc_details.$HONEYPOT
	fi
    fi
    return 0
}

# Function to parse pcap file and extract files downloaded via HTTP for
# one honeypot
#   Requires 3 input variables:
#     name of pcap file
#     IP address of honeypot
#     name of output directory
#   Returns list of files

extract_http() {
    local _pcapfile=$1 _honeypot=$2 _outputdir=$3 _httpsessions _httpsession _httpsource _httpsourceport _httpdest \
	_httpdestport _httpfile _size _type _i _md5
    safe_create_dir $_outputdir/tcpflows
    cd $_outputdir/tcpflows
    $TCPFLOW -b $MAX_TCPFLOW_BYTES -r $_pcapfile src host $_honeypot and dst port 80
    _ext=0
    _httpsessions=`find . -type f -a -name '*00080' | sed -e 's/^..//g' -e 's/\-/./g'`
    if [ $? -eq 0 ]
    then
	    for _httpsession in $_httpsessions
    	do
    	    #echo httpsession $_httpsession
    	    _httpsource=`echo $_httpsession | $AWK -F. '{ print $1 "." $2 "." $3 "." $4 }'`
    	    _httpsourceport=`echo $_httpsession | $AWK -F. '{ print $5 }'`
    	    _httpdest=`echo $_httpsession | $AWK -F. '{ print $6 "." $7 "." $8 "." $9 }'`
    	    _httpdestport=`echo $_httpsession | $AWK -F. '{ print $10 }'`
    	    $TCPFLOW -b $MAX_TCPFLOW_BYTES -r $_pcapfile src host $_httpdest and src port 80
    	    _httpfile=`grep -i ^GET  ${_httpsource}.${_httpsourceport}-${_httpdest}.${_httpdestport} | $AWK '{ print $2 }'| $DOS2UNIX`
    	    # now tidy the filename. Replace / with "index.html" and subdir '/'s with '-DIR-'
    	    # also add a unique number on the end in case of multiple files with the same name
    	    if [ "$_httpfile" = "/" ]
    	    then
    		    _httpfile="index.html"
    	    else
    	       _httpfile=`echo $_httpfile | sed -e 's/\///' | sed -e 's/\//-DIR-/g'`
    	    fi
    	    safe_create_dir ../extracted_files/http
    	    safe_create_dir ../extracted_files/http/$_httpdest               
    	    if [ -f "../extracted_files/http/$_httpdest/$_httpfile" ]
    	    then                        
        	    let _ext=${_ext}+1    
    	        _httpfile=$_httpfile.${_ext}
            fi        
            dstfile="../extracted_files/http/$_httpdest/$_httpfile"
    	    cp "${_httpdest}.${_httpdestport}-${_httpsource}.${_httpsourceport}" $dstfile
    	    split_file $dstfile
    	    file_info info $dstfile 
    	    echo "    " $info >> $TMP_DATA_DIRECTORY/.http-files
    	done    
    fi
    if [ -f $TMP_DATA_DIRECTORY/.http-files ]
    then
    	echo
    	echo Files downloaded using HTTP:
    	echo
    	sort -u $TMP_DATA_DIRECTORY/.http-files | grep -v "/$" 
    	echo
    	rm -f $TMP_DATA_DIRECTORY/.http-files 
    fi
    return 0
}

# Function to parse pcap file and extract files downloaded via FTP for
# one honeypot
#   Requires 3 input variables:
#     name of pcap file
#     IP address of honeypot
#     name of output directory
#   Returns list of files

extract_ftp() {
    local _pcapfile=$1 _honeypot=$2 _outputdir=$3 _ftpsessions _ftpsession _activesessions _activesession _passivesessions \
	_passivesession _server _port256 _port1 _port _activeretrs _activeretr _passiveretrs _passiveretr _headnum _activecmd \
	_activecmdtest _passivecmd _passivecmdtest _activefile _passivefile _type _size _portlines _portline _portretr _pasvlines \
	_pasvlines _portretr _padpot _padserver _ip1 _ip2 _i _cmd _md5
    safe_create_dir $_outputdir/tcpflows
    cd $_outputdir/tcpflows
    $TCPFLOW -b $MAX_TCPFLOW_BYTES -r $_pcapfile host $_honeypot and port 21    
    _ftpsessions=`find . -type f -a -name '*00021'`
    
    if [ $? -eq 0 ]
    then
	for _ftpsession in $_ftpsessions
	do                                       
	    _ext=0
	    $DOS2UNIX $_ftpsession > /dev/null 2>&1
	    
	    # Extract active FTP sessions using the PORT command
	    _activesessions=`grep -in ^PORT $_ftpsession | $AWK -F: '{ print $1 }'`
	    if [ $? -eq 0 ]
	    then 
		    for _portline in $_activesessions
    		do      
    			_padpot=`echo $_ftpsession | sed -e 's/\.\///g' | $AWK -F. '{ print $1 "." $2 "." $3 "." $4 }'`
    			_server=`head -$_portline $_ftpsession | tail -1 | $AWK '{ print $2 }' | $AWK -F, '{ print $1 "." $2 "." $3 "." $4 }' | $DOS2UNIX`
    			_padserver=`echo $_ftpsession | $AWK -F- '{ print $2 }' | $AWK -F. '{ print $1 "." $2 "." $3 "." $4 }'`
    			_port256=`head -$_portline $_ftpsession | tail -1 | $AWK '{ print $2 }' | $AWK -F, '{ print $5 }' | $DOS2UNIX`
    			_port1=`head -$_portline $_ftpsession | tail -1 | $AWK '{ print $2 }' | $AWK -F, '{ print $6 }' | $DOS2UNIX`

    			if [ ! -z $_port256 ] && [ ! -z $_port1 ]
    			then
    			    _port=$((($_port256*256)+$_port1))
    			    _retrline=$(($_portline+1))
    			    _cmd=`head -$_retrline $_ftpsession | tail -1 | $AWK '{print $1}'`
    			    if [ $_cmd = RETR ]
    			    then
        				_activefile=`head -$_retrline $_ftpsession | tail -1 | $AWK '{ print $2 }' | $DOS2UNIX`
        				$TCPFLOW -b $MAX_TCPFLOW_BYTES -r $_pcapfile host \($_server and $_honeypot\) and port $_port
        				safe_create_dir ../extracted_files/ftp
        				safe_create_dir ../extracted_files/ftp/$_padserver
        				if [ -f $_padserver.00020-$_server.$_port ]
        				then                                                                                     
        				    if [ -f "../extracted_files/ftp/$_padserver/$_activefile" ]
    				        then
        				        let _ext=$_ext+1
        				        _activefile=$_activefile.$_ext
    				        fi                                  
    				        dstfile="../extracted_files/ftp/$_padserver/$_activefile"
        				    cp $_padserver.00020-$_server.$_port $dstfile
        				    file_info info $dstfile
        				    echo "    " $info >> $TMP_DATA_DIRECTORY/.ftp-files
        				else
        				    # call true here to stop syntax errors. Needed case we want to put the echo back in
        				    true
        				    #echo $_activefile : File not found - did the ftp download fail?
        				fi
    			    fi
    			fi  
		    done
	    fi
	    
        # Extract passive FTP sessions using the PASV command
	    _passivesessions=`grep -in ^PASV $_ftpsession | awk -F: '{ print $1 }'`
	    if [ $? -eq 0 ]
	    then    
	        _i=0
	        for _pasvline in $_passivesessions
    		do           
    		    let _i=$_i+1
    			# work out the filename of the other half of the ftp conversation
    			_ip1=`echo $_ftpsession  | sed -e 's/\.\///g'|  awk -F'-' '{print $1}'|awk -F. '{ print $1 "." $2 "." $3 "." $4 }' `
    			_port1=`echo $_ftpsession | sed -e 's/\.\///g' |  awk -F'-' '{print $1}'|awk -F. '{ print $5 }' `
    			_ip2=`echo $_ftpsession | sed -e 's/\.\///g' |  awk -F'-' '{print $2}'|awk -F. '{ print $1 "." $2 "." $3 "." $4 }' `
    			_port2=`echo $_ftpsession | sed -e 's/\.\///g' |  awk -F'-' '{print $2}'|awk -F. '{ print $5 }' `		
    			_ftpreply="$_ip2.$_port2-$_ip1.$_port1"  
			
    			# now work out the ports for the passive connection
    			# line like : 227 Entering Passive Mode (65,113,119,152,204,9)
    			# we need last two numbers
    			_port256=`cat $_ftpreply | grep "Entering Passive Mode" | sed -e 's/\.$//' | head -$_i | tail -1 |  $AWK '{ print $5 }' | $AWK -F, '{ print $5 }' ` 
    			_port1=`cat $_ftpreply | grep "Entering Passive Mode" | head -$_i | tail -1 |  $AWK '{ print $5 }' | $AWK -F, '{ print $6 }' | perl -p -e 's/\)\.?//' | $DOS2UNIX `
	
    			if [ ! -z $_port256 ] && [ ! -z $_port1 ]
    			then 
    			    _port=$((($_port256*256)+$_port1))
    			    _pasvretr=$(($_pasvline+1))
    			    _cmd=`head -$_pasvretr $_ftpsession | tail -1 | $AWK '{ print $1 }' | $DOS2UNIX`
    			    if [ $_cmd = "RETR" ]; then
    			        _passivefile=`head -$_pasvretr $_ftpsession | tail -1 | $AWK '{ print $2 }' | $DOS2UNIX`  
        			    $TCPFLOW -b $MAX_TCPFLOW_BYTES -r $_pcapfile host \($_ip2 and $_honeypot\) and port $_port
        			    safe_create_dir ../extracted_files/ftp
        			    safe_create_dir ../extracted_files/ftp/$_ip2                  
        			    if [ -f "../extracted_files/ftp/$_ip2/$_passivefile" ]
    			        then                         
        			        let _ext=${_ext}+1
        			        _passivefile=${_passivefile}.${_ext}
    			        fi                              
    			        dstfile="../extracted_files/ftp/$_ip2/$_passivefile"
        			    cp $_ip2.$_port-$_ip1.* $dstfile
        			    file_info info $dstfile
    				    echo "    " $info >> $TMP_DATA_DIRECTORY/.ftp-files
    		        fi
    			fi       
    	    done 
	    fi
	done
    fi
    if [ -f $TMP_DATA_DIRECTORY/.ftp-files ]
    then
	echo
	echo Files downloaded using FTP:
	echo
	sort -u $TMP_DATA_DIRECTORY/.ftp-files | grep -v "/$"
	echo
	rm -f $TMP_DATA_DIRECTORY/.ftp-files
    fi
    return 0
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
    safe_create_dir $_outputdir/tcpflows ]
    cd $_outputdir/tcpflows
    $TCPFLOW -b $MAX_TCPFLOW_BYTES -r $_pcapfile src host $_honeypot and dst port 25
    _smtpsessions=`find . -type f | grep 00025`
    
    _count=0
    for _smtpsession in $_smtpsessions
    do 
	safe_create_dir ../extracted_files/smtp

	let _count=_count+1
	cp $_smtpsession ../extracted_files/smtp/mail-message-$_count
	
	_rcpt_to=`grep -i "rcpt to" $_smtpsession`
	if [ $? -eq 0 ] 
	then
	    echo $_rcpt_to >> $TMP_DATA_DIRECTORY/.smtp-messages
	fi
	_subject=`grep -i "subject" $_smtpsession`
	if [ $? -eq 0 ] 
	then
	    echo $_subject >> $TMP_DATA_DIRECTORY/.smtp-messages
	    echo >> $TMP_DATA_DIRECTORY/.smtp-messages
	fi
    done
    
    if [ -f $TMP_DATA_DIRECTORY/.smtp-messages ]
    then
	echo
	echo Outbound SMTP messages:
	echo
	cat $TMP_DATA_DIRECTORY/.smtp-messages
	rm -f $TMP_DATA_DIRECTORY/.smtp-messages
    fi
    return 0
}


# Function to parse pcap file and output sebek keystroke logs for one honeypot
#   Requires 2 input variables: name of pcap file and IP address of honeypot
#   Returns count of all sebek keystokes plus listing of interesting ones

count_sebek() {
    local _pcapfile=$1 _honeypot=$2 _outputdir=$3 _count
    _count=`$TCPDUMP -n -r $_pcapfile src host $_honeypot and udp port 1101 2>&1 | wc -l`
    let _count=_count-1
    echo Honeypot: $_honeypot [ $_count Sebek packets ]
    
    if [ $_count -gt 0 ]
    then 
	safe_create_dir $_outputdir
	cd $_outputdir
	safe_create_dir extracted_files/sebek_keystrokes
	$TCPDUMP -n -r $_pcapfile -w $TMP_DATA_DIRECTORY/.sebek_tmp.$_honeypot src host $_honeypot and udp port 1101 > /dev/null 2>&1
	#echo writing to extracted_files/sebek_keystrokes/sebek.txt, honeypot $_honeypot
	$SBK_EXTRACT -f $TMP_DATA_DIRECTORY/.sebek_tmp.$_honeypot  2>/dev/null | $SBK_KS_LOG > extracted_files/sebek_keystrokes/sebek.txt 2>/dev/null
	rm  $TMP_DATA_DIRECTORY/.sebek_tmp.$_honeypot
	if [ $PRINT_SEBEK = YES ]
	then
	    echo
	    grep -v "[0-9]\]$" extracted_files/sebek_keystrokes/sebek.txt | grep $_honeypot | grep -v prelink | grep -v SSH-
	    echo
	fi
    fi
    return 0
}

#################################################################################
# Section 3 - Main Program Structure to call the functions
#
################################################################################

# Check config file exists, or display usage information

if  [ ${1:-"nondefined"} == "nondefined" ] ||  [ ${2:-"nondefined"} == "nondefined" ] ||  [ ${3:-"nondefined"} == "nondefined" ] || \
    [ ! -f $1 ] || [ ! -f $3 ]
then
    usage
fi

CONFIGFILE=$1
OUTPUT_DATA_DIRECTORY=$2
PCAPFILE=$3

# Read configuration data and set variables

source $CONFIGFILE

# too much of the code assumes absolute paths, so just fix it up here
make_absolute "PCAPFILE" $PCAPFILE
make_absolute "TMP_DATA_DIRECTORY" $TMP_DATA_DIRECTORY
make_absolute "OUTPUT_DATA_DIRECTORY" $OUTPUT_DATA_DIRECTORY

safe_create_dir $OUTPUT_DATA_DIRECTORY
safe_create_dir $TMP_DATA_DIRECTORY

for exefile in CAPINFO TETHEREAL TCPDUMP TCPFLOW DOS2UNIX AWK SBK_EXTRACT SBK_KS_LOG PRIVMSG ANALYSE_IRC PERL MD5SUM
do
    check_exe $exefile
done

echo Starting honeysnap analysis at `date`
echo

# Main program loop to perform a series of actions for each date against each 
# honeypot 

if ! check_file $PCAPFILE
    then
    echo Did not find pcap file $PCAPFILE
    exit
fi

if [ $DO_CAPINFO = YES ]
then
   echo
   echo Pcap file information:
   echo
   do_capinfo $PCAPFILE
   echo
fi

if [ $DO_SNORT = YES ]
then
    check_exe SNORT
    echo Running Snort
    do_snort $PCAPFILE "$OUTPUT_DATA_DIRECTORY" $SNORT_NET
fi

if [ $DO_PACKETS = YES ]
then
    echo Counting outbound IP packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	count_packets $PCAPFILE $HONEYPOT
    done
    echo
fi

if [ $DO_TELNET = YES ]
then
    echo Counting outbound Telnet packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	count_telnet $PCAPFILE $HONEYPOT
    done
    echo
fi

if [ $DO_SSH = YES ]
then
    echo Counting outbound SSH packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	count_ssh $PCAPFILE $HONEYPOT
    done
    echo
fi

if [ $DO_HTTP = YES ]
then
    echo Counting HTTP packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	count_http_packets $PCAPFILE $HONEYPOT
	if [ $DO_FILES = YES ]
	then
	    extract_http $PCAPFILE $HONEYPOT $OUTPUT_DATA_DIRECTORY/$HONEYPOT
	fi
    done
    echo
fi

if [ $DO_HTTPS = YES ]
then
    echo Counting HTTPS packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	count_https_packets $PCAPFILE $HONEYPOT
    done
    echo
fi

if [ $DO_FTP = YES ]
then
    echo Counting outbound FTP packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	count_ftp_packets $PCAPFILE $HONEYPOT
	if [ $DO_FILES = YES ]
	then
	    extract_ftp $PCAPFILE $HONEYPOT $OUTPUT_DATA_DIRECTORY/$HONEYPOT
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
	count_smtp_packets $PCAPFILE $HONEYPOT
	if [ $DO_FILES = YES ]
	then
	    extract_smtp $PCAPFILE $HONEYPOT $OUTPUT_DATA_DIRECTORY/$HONEYPOT
	fi
	
    done
    echo
fi

if [ $DO_IRC = YES ]
then
    echo Analysing IRC packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	do_irc $PCAPFILE $HONEYPOT $DO_IRC_DETAIL
    done
    echo
fi

if [ $DO_SEBEK = YES ]
then
    echo
    echo Counting Sebek packets:
    echo
    for HONEYPOT in $HONEYPOTS
    do
	count_sebek $PCAPFILE $HONEYPOT $OUTPUT_DATA_DIRECTORY/$HONEYPOT
    done
    echo
fi

#echo Cleaning temp files
rm -rf $TMP_DATA_DIRECTORY/*
    
echo
echo Completed honeysnap analysis at $DATE
