# $Id$

PURPOSE
=======
The purpose of this document is to give you a brief overview
of what Honeysnap is and how it works.  For more detailed 
information, and examples, please refer to the USAGE doc that
comes with the distribution.


WHAT IS IT?
==========
Honeysnap is a modular, python application that can parse 
raw or gzipped pcap files and perform a number of diagnostics 
on the data.  It has been designed to be easily extended to 
perform more diagnostic duties.  It has also been designed to 
be minimally dependent on third party executables like tcpflow, 
etc.

The primary value of Honeysnap is to give you an overview of a
single or multiple pcap data files that has been captured from
network activity.  Its primary design is for analyzing pcap data
recovered from a honeypot or compromised system.  What makes 
Honeysnap unique is it does not just focus on transactional data
(IP addresses, time/date stamps, etc) but also focuses on the 
packet payload.  It has the ability to decode and analyze a variety
of protocls, such as HTTP, SMTP, and IRC.  It can also recover 
files transfered.  In addition it has the ability to analyze 
honeypot specific data sets such as SEBEK.  Because of its 
modular nature, it is possible to add other protocols.

Honeysnap.py is derived/inspired by work of David Watson, 
Steve Mumford, and Arthur Clune of the UK Honeynet Project,
who wrote the first version in bash (!)

An overview of what Honeysnap includes:

* Outgoing packet counts for telnet, ssh, http, https, ftp, smtp, 
  and irc. This can be easily extended.
* Incoming and outgoing connection summaries
* Binary extraction from http, smtp, irc, and ftp.
* Word based inspection of IRC traffic.
* Support for sebek data

INSTALLATION
============

See the INSTALL file

USAGE
=====

Modify the honeynet.cfg file to execute the operations you like, 
and specify the output directory. The included honeysnap.cfg file 
is well commented to help you get started.

to execute:
honeysnap -c honeysnap.cfg <pcapfile>

For more information and examples, plesase refer to the USAGE 
document.

EFFICIENCY
==========

Increasing the max number of open files will make things faster. 
On most unix like OSs this can be done by executing the following.

$ ulimit -n 4096

BUGS/HELP
=========

Please send any bugs, tracebacks, comments, or patches to Arthur 
Clune (arthur@honeynet.org.uk) or Jed Haile 
(jed.haile@thelogangroup.biz)

COPYRIGHT
=========

All code in honeysnap is copyright The Honeynet Project.

Contact Information:
Jed Haile
jed.haile@thelogangroup.biz

Arthur Clune 
arthur@honeynet.org.uk