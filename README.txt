Honeysnap

What is it?
Honeysnap is a python application that can parse raw gzipped pcap files and perform a number of diagnostics on the data.  It has been designed to be easily extended to perform more diagnostic duties.  It has also been designed to be minimally dependent on third party executables like tcpflow, etc.

The primary intention is to give a quick first look into a directory full of pcap data that has been pulled from a roo or some honeynet.

Honeysnap.py is derived/inspired by honeysnap.sh by David Watson, Steve Mumford, and Arthur Clune of the UK Honeynet Project.  It is included in this distribution for reference, and it still has a couple of features I need to finish stealing (implementing).

This includes:
Outgoing packet counts for telnet, ssh, http, https, ftp, smtp, and irc. This can be easily extended.

Incoming and outgoing connection summaries

Binary extraction from http, smtp, irc, and ftp.

Word based inspection of IRC traffic.

Support for sebet data

Support for database output is also in progress.

Installation:

See the INSTALL file

Use:
Modify the honeynet.cfg file to do the operations you like, also modify it to point at your datafiles.  The included honeysnap.cfg file is well commented to help you get started.

to execute:
honeysnap -c honeysnap.cfg -r <pcapfile>


To Do:
Debug.  Please send any bugs, tracebacks, comments, or patches to jed.haile@thelogangroup.biz

Come up with a proper naming scheme for the results file

honeysnap could possibly drop the data for two different flows with the same srcip:srcport-dstip:dstport into the same file.  We need to look into this, an improved naming scheme could fix this problem.

We need to change the flow of program execution so each packet only gets decoded once.  Right now, depending on how honeysnap is configured, a packet might get decoded multiple times.  This is inefficient.

Add extracted data file summary to the results file.

Add RRD, or similar, functions

Copyright:
All code in honeysnap is copyright The Honeynet Project.

Contact Information:
Jed Haile
jed.haile@thelogangroup.biz