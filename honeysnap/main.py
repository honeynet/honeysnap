################################################################################
# (c) 2005, The Honeynet Project
#   Author: Jed Haile  jed.haile@thelogangroup.biz
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

# $Id$
   
VERSION="1.0.1"

import sys
import socket
from optparse import OptionParser, Option, OptionValueError
import re
import string
import gzip
import os
from fnmatch import fnmatch
import ConfigParser
from ConfigParser import SafeConfigParser
import tempfile
import pcap

# all the honeysnap imports
# eventually all these will become UDAF modules
# and you will get them all by importing DA
import httpDecode
import ftpDecode
import smtpDecode
import tcpflow
from hsIRC import HoneySnapIRC
from ircDecode import ircDecode
from singletonmixin import HoneysnapSingleton
from pcapinfo import pcapInfo
from packetSummary import Summarize
from base import Base
from output import outputSTDOUT, rawPathOutput
from packetCounter import Counter
from pcapRE import pcapRE, wordSearch, pcapReCounter
from sebekDecode import sebekDecode
from util import make_dir

class MyOption(Option):
    """
    A class that extends option to allow us to have comma delimited command line args.
    Taken from the documentation for optparse.
    """
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            lvalue = value.split(",")
            values.ensure_value(dest, []).extend(lvalue)
        else:
            Option.take_action(
                self, action, dest, opt, value, values, parser)

def setFilters(options):
    """Set filters for packet counts"""
    irc_ports = options["irc_ports"]
    if len(irc_ports)==1:
        irc_filter = "dst port %s" % irc_ports[0]
    else:
        irc_filter = "("
        port = [ 'dst port %s' % port for port in irc_ports ]
        irc_filter = irc_filter + " or ".join(port) + ")"
    return [ 
        ('All outbound IPv4 packets:', 'src host %s'),  
        ('All ICMP packets', 'host %s and icmp'),
        ('Outbound FTP packets:','src host %s and dst port 21'),
        ('Outbound SSH packets:','src host %s and dst port 22'),
        ('Outbound Telnet packets:','src host %s and dst port 23'),
        ('Outbound SMTP packets:','src host %s and dst port 25'),
        ('Outbound HTTP packets:','src host %s and dst port 80'),
        ('Outbound HTTPS packets:','src host %s and dst port 443'),        
        ('Outbound Sebek packets:','src host %s and udp port %s' % ('%s', options["sebek_port"])),
        ('Outbound IRC packets:','src host %s and tcp and %s' % ('%s', irc_filter)),
        ('Inbound FTP packets:','dst host %s and dst port 21'),
        ('Inbound SMTP packets:','dst host %s and dst port 25'),
        ('Inbound HTTP packets:','dst host %s and dst port 80'),
        ('Inbound HTTPS packets:','dst host %s and dst port 443'),
        ]

def processFile(file):
    """
    Process a pcap file.
    file is the pcap file to parse
    This function will run any enabled options for each pcap file
    """
    hs = HoneysnapSingleton.getInstance()
    options = hs.getOptions()   
    
    try:
        # This sucks. pcapy wants a path to a file, not a file obj
        # so we have to uncompress the gzipped data into
        # a tmp file, and pass the path of that file to pcapy
        tmph, tmpf = tempfile.mkstemp()
        tmph = open(tmpf, 'wb')
        gfile = gzip.open(file)
        tmph.writelines(gfile.readlines())
        gfile.close()
        del gfile
        tmph.close()
        deletetmp = 1
    except IOError:
        # got an error, must not be gzipped
        # should probably do a better check here
        tmpf = file
        deletetmp = 0
    options["tmpf"] = tmpf

    try:
        if options["filename"] is not None:
            out = rawPathOutput(options["filename"], mode="a+")
        else:
            out = outputSTDOUT()
    except IOError:
        # we have some error opening the file
        # there is something at that path. Is it a directory?
        if not os.path.isdir(options["output_data_directory"]):
            print "Error: output_data_directory exists, but is not a directory."
        else:
            print "Unknown Error creating output file"
            sys.exit(1)

    # quick and dirty check file is a valid pcap file
    try:
        if os.path.exists(tmpf) and os.path.getsize(tmpf)>0 and os.path.isfile(tmpf):
            p = pcap.pcap(tmpf)
        else:
            raise OSError
    except OSError:
        print "File %s is not a pcap file or does not exist" % file
        sys.exit(1)
                                   
    out("\n\nAnalysing file: %s\n\n" % file)  
                      
    if options["do_pcap"] == "YES":
        out("Pcap file information:\n")
        pi = pcapInfo(tmpf)
        pi.setOutput(out)
        pi.getStats()
        myout = rawPathOutput(options["output_data_directory"] +"/pcapinfo.txt")
        pi.setOutput(myout)
        pi.getStats()

    if options["do_packets"] == "YES":
        out("\nIP packet summary for common ports:\n\n")
        out("%-40s %10s\n" % ("Filter", "Packets"))
        filters = setFilters(options)
        for i in filters:
            key, filt = i
            out(key+"\n")
            for hp in options['honeypots']:
                p = pcap.pcap(tmpf)
                c = Counter(p)
                c.setOutput(out)
                f = filt % hp
                c.setFilter(f)
                c.count()
            out("\n")

    if options["do_incoming"] == "YES":
        for hp in options["honeypots"]:
            outdir = options["output_data_directory"] + "/%s/conns" % hp
            make_dir(outdir)
            p = pcap.pcap(tmpf)
            v = options["verbose_summary"]
            s = Summarize(p, verbose=v)
            filt = 'dst host %s' % hp
            s.setFilter(filt, file)
            s.start()
            if v=="YES":
                l = 0
            else:
                l = 10  
            fileout = rawPathOutput(outdir+"/incoming.txt", mode="w") 
            if options["print_verbose"] == "YES":
                outputs = (fileout, out)
            else:
                outputs = (fileout,)                  
            for output in outputs:
                s.setOutput(output)
                s.doOutput("\nINCOMING CONNECTIONS FOR %s\n" % hp)             
                s.writeResults(limit=l)
            del p


    if options["do_outgoing"] == "YES":
        for hp in options["honeypots"]:
            outdir = options["output_data_directory"] + "/%s/conns" % hp
            make_dir(outdir)
            p = pcap.pcap(tmpf)
            v = options["verbose_summary"]
            s = Summarize(p, verbose=v)
            filt = 'src host %s' % hp
            s.setFilter(filt, file)
            s.start()
            if v=="YES":
                l = 0
            else:
                l = 10  
            fileout = rawPathOutput(outdir+"/outgoing.txt", mode="w")  
            if options["print_verbose"] == "YES":
                outputs = (fileout, out)
            else:
                outputs = (fileout,)
            for output in outputs:
                s.setOutput(output) 
                s.doOutput("\nOUTGOING CONNECTIONS FOR %s\n" % hp)                 
                s.writeResults(limit=l)  
            del p
   
    if options["do_irc"] == "YES":
        """
        Here we will use PcapRE to find packets on irc_port with "PRIVMSG"
        in the payload.  Matching packets will be handed to wordsearch
        to hunt for any matching words.
        """   
        for hp in options["honeypots"]:
            out("\nLooking for packets containing PRIVMSG for %s\n\n" % hp)
            p = pcap.pcap(tmpf)
            r = pcapReCounter(p)
            r.setFilter("host %s and tcp" % hp)
            r.setRE('PRIVMSG') 
            r.setOutput(out)
            r.start()
            r.writeResults()
            del p 

    if options["do_irc"] == "YES":
        out("\nAnalysing IRC\n")          
        for hp in options["honeypots"]:
            outdir = options["output_data_directory"] + "/%s/irc" % hp 
            for port in options["irc_ports"] :
                out("\nHoneypot %s, port %s\n\n" % (hp, port))
                hirc = HoneySnapIRC()
                hirc.connect(tmpf, "host %s and tcp and port %s" % (hp, port))
                hd = ircDecode()
                hd.setOutput(out)
                hd.setOutdir(outdir)
                hd.setOutfile('irclog-%s.txt' % port) 
                hirc.addHandler("all_events", hd.decodeCB, -1)
                hirc.ircobj.add_global_handler("all_events", hd.printLines, -1)
                hirc.ircobj.process_once()
                hd.printSummary()
                del hd

    if options["all_flows"] == "YES":
        out("\nExtracting all flows\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        filt = "host "
        filt += " or host ".join(options["honeypots"])
        de.setFilter(filt)
        de.setOutdir(options["output_data_directory"]+ "/%s/flows")
        de.setOutput(out)
        de.start()
        de.dump_extract(options)
        del p

    if options["do_http"] == "YES":
        out("\nExtracting from HTTP\n\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        de.setFilter("port 80")
        de.setOutdir(options["output_data_directory"]+ "/%s/http")
        de.setOutput(out)
        decode = httpDecode.httpDecode()
        decode.setOutput(out)
        de.registerPlugin(decode.decode)
        de.start()
        de.dump_extract(options)
        del p


    if options["do_ftp"] == "YES":
        out("\nExtracting from FTP\n\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        de.setFilter("port 20 or port 21")
        de.setOutdir(options["output_data_directory"] + "/%s/ftp")
        de.setOutput(out)
        decode = ftpDecode.ftpDecode()
        decode.setOutput(out)
        de.registerPlugin(decode.decode)
        de.start()
        de.dump_extract(options)
        del p

    if options["do_smtp"] == "YES":
        out("\nExtracting from SMTP\n\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        de.setFilter("port 25")
        de.setOutdir(options["output_data_directory"] + "/%s/smtp")
        de.setOutput(out)
        decode = smtpDecode.smtpDecode()
        decode.setOutput(out)
        de.registerPlugin(decode.decode)
        de.start()
        de.dump_extract(options)
        del p

    if options["do_sebek"] == "YES":
        out("\nExtracting Sebek data\n")
        for hp in options["honeypots"]:
            out("\nHoneypot %s\n\n" % hp)
            sbd = sebekDecode(hp)
            sbd.setOutdir(options["output_data_directory"] + "/%s/sebek" % hp)
            sbd.setOutput(out)
            sbd.run()
            del sbd

    # delete the tmp file we used to hold unzipped data
    if deletetmp:
        os.unlink(tmpf)

def cleanup(options):
    """
    Clean up empty files, etc.
    """
    datadir = options["output_data_directory"]
    for root, dirs, files in os.walk(datadir, topdown=False):
        rootpath =  root.split(os.path.sep)
        for name in files:
            if os.stat(os.path.join(root, name)).st_size == 0:
                if rootpath[-1] != 'incoming' and rootpath[-1] != 'outgoing':
                    #print "removing %s" % os.path.join(root, name)
                    os.remove(os.path.join(root, name))
        for name in dirs:
            if not len(os.listdir(os.path.join(root, name))):
                #print "removing dir %s" % os.path.join(root, name)
                os.rmdir(os.path.join(root, name))
    """
    for dir in ["/irc", "/http", "/ftp", "/smtp", "/sebek"]:
        if os.path.isdir(datadir+dir):
            files = os.listdir(datadir+dir)
        else:
            continue
        for f in files:
            file = datadir + dir + "/" + f
            if os.stat(file).st_size == 0:
                os.unlink(file)
    """

def store_int_array(option, opt_str, value, parser):
    """Store comman seperated integer values from options into an array"""
    a = []
    a = value.split(",")
    try:
        a = [ int(n) for n in a ]
    except ValueError:
        raise OptionValueError("Argument %s not an integer!" % opt_str)
    setattr(parser.values, option.dest, a)

def parseOptions():
    """
    Read options from both config file and command line and merge
    Precedence order: Command line > config file > defaults 
    
    Returns a (help, options, args) tuple. Help is a function that prints help
    """
    
    # default values for all options.   
    defaults = {        
            'honeypots'         : None,
            'config'            : None,
            'filename'          : None,
        	'mask' 				: '*',
        	'wordfile'          : None,
        	'files'             : None,
    		'do_pcap' 			: 'YES',
    		'do_packets'		: 'YES',
    		'do_incoming'		: 'YES',
    		'do_outgoing'		: 'YES',
    		'verbose_summary'	: 'YES',
    		'print_verbose'		: 'NO',
    		'do_http'			: 'YES',
    		'print_http_served' : 'NO',
    		'do_ftp'			: 'YES',
    		'do_smtp'           : 'YES',
    		'do_irc'			: 'YES',
    		'irc_ports'			: [6667],
    		'irc_limit'			: 0,
    		'do_sebek'			: 'YES',
    		'sebek_port'		: 1101,
    		'all_flows'			: 'YES', 
    		'output_data_directory'   : '/tmp/analysis',
    		'tmp_file_directory': '/tmp'
    }  
         
    parser = OptionParser(option_class=MyOption, version="%sprog %s" % ('%', VERSION))         
        
    parser.add_option("-c", "--config", dest="config",type="string",
        help="Config file")
    parser.add_option("-f", "--file", dest="filename",type="string",
        help="Write report to FILE", metavar="FILE")
    parser.add_option("-o", "--output", dest="output_data_directory",type="string",
        help="Write output to DIR, defaults to /tmp/analysis", metavar="DIR")
    parser.add_option("-t", "--tmpdir", dest="tmp_file_directory",type="string",
        help="Directory to use as a temporary directory, defaults to /tmp")
    parser.add_option("-H", "--honeypots", dest="honeypots", action="extend", type="string",
        help="Comma delimited list of honeypots")
    parser.add_option("-d", "--dir", dest="files", type="string",
        help="Directory containing timestamped log directories. If this flag is set then honeysnap will run in batch mode. To limit which directories to parse, use -m (--mask)", metavar="FILE")
    parser.add_option("-m", "--mask", dest="mask", type="string",
        help = "Mask to limit which directories are recursed into.")
    parser.add_option("-w", "--words", dest="wordfile", type="string",
        help = "Pull wordlist from FILE", metavar="FILE")

    parser.add_option("--do-pcap", dest="do_pcap", action="store_const", const="YES",
        help = "Summarise pcap info")
    parser.add_option("--do-packets", dest="do_packets", action="store_const", const="YES",
        help = "Summarise packet counts")
    parser.add_option("--do-incoming", dest="do_incoming", action="store_const", const="YES",
        help = "Summarise incoming traffic flows")
    parser.add_option("--do-outgoing", dest="do_outgoing", action="store_const", const="YES",
        help = "Summarise outgoing traffic flows")
    parser.add_option("--verbose-summary", dest="verbose_summary", action="store_const", const="YES",
        help = "Do verbose flow counts, indexes flows by srcip, sport, dstip, dport")
    parser.add_option("--print-verbose", dest="print_verbose", action="store_const", const="YES",
        help = "Print verbose flow counts to screen as well as storing in a file") 
    parser.add_option("--do-http", dest="do_http", action="store_const", const="YES",
        help = "Extract http data")   
    parser.add_option("--print-http-served", dest="print_http_served", action="store_const", const="YES",
        help = "Print extracted files served by the honeypot(s)")
    parser.add_option("--do-ftp", dest="do_ftp", action="store_const", const="YES",
        help = "Extract FTP data")
    parser.add_option("--do-smtp", dest="do_smtp", action="store_const", const="YES",
        help = "Extract smtp data")
    parser.add_option("--do-irc", dest="do_irc", action="store_const", const="YES",
        help = "Summarize IRC and do irc detail (same as --do-irc-detail and --do-irc-summary)")
    parser.add_option("--irc-ports", action="callback", callback=store_int_array, dest="irc_ports", type="string",
        help = "Ports for IRC traffic")   
    parser.add_option("--irc-limit", dest="irc_limit", type="int", help = "Limit IRC summary to top N items")
    parser.add_option("--do-sebek", dest="do_sebek", action="store_const", const="YES",
        help = "Extract Sebek data")
    parser.add_option("--sebek-port", dest="sebek_port", type="int", help = "Port for sebek traffic")
    parser.add_option("--all-flows", dest="all_flows", action="store_const", const="YES",
        help = "Extract data from all tcp flows")
                    
    # parse command line  
    (cmdopts, args) = parser.parse_args()  
    
    # now pull in config file if defined
    fileopts = {}
    if cmdopts.config:
        fileparser = SafeConfigParser()
        if os.path.isfile(cmdopts.config): 
            try:  
                fileparser.read(cmdopts.config)
                for opts in fileparser.items('OPTIONS'), fileparser.items('IO'):
                    for i in opts:
                        if i[0] == 'irc_ports':
                            fileopts[i[0]] = [ int(n) for n in i[1].split(',') ]
                        elif i[0] == 'irc_limit': 
                            fileopts[i[0]] = int(i[1]) 
                        elif i[0] == 'honeypots':
                            fileopts[i[0]] = i[1].split()
                        else:
                            fileopts[i[0]] = i[1] 
            except ConfigParser.Error:
                print "Problem with the config file! Check format and permissions"
                sys.exit(1)
        else:
            print "Config file %s not found!" % options['config']
            sys.exit(1)
    
    options = {}
    # now merge defaults, config file and command line
    for opt in defaults.keys(): 
        options[opt] = defaults[opt]
        if fileopts.has_key(opt) and fileopts[opt]:
            options[opt] = fileopts[opt]
        if cmdopts.__dict__.has_key(opt) and cmdopts.__dict__[opt]:
            options[opt] = cmdopts.__dict__[opt]  
    
    if not options.has_key('honeypots'):
        print "No honeypots specified! Please use either -H or the config file to specify some"
        sys.exit(1)

    return (parser.print_help, options, args)

def main():
    """Set everything off and handle files/stdin etc"""
    
    print_help, options, args = parseOptions()
    
    if len(sys.argv)>1:
        if options['honeypots'] is None:
            print "No honeypots specified. Please use either -H or config file to specify honeypots.\n"
            sys.exit(2)
        hsingleton = HoneysnapSingleton.getInstance(options)
        if not os.path.exists(options['output_data_directory']):
            make_dir(options['output_data_directory'])
        if os.path.exists(options['output_data_directory']):
            for i in options["honeypots"]:
                make_dir(options["output_data_directory"]+"/"+i)
        # by default treat args as files to be processed
        # handle multiple files being passed as args
        if len(args):
            for f in args:
                if os.path.exists(f) and os.path.isfile(f):  
                    processFile(f)
                else:
                    print "File not found: %s" % f
                    sys.exit(2)
        # -d was an option
        elif options['files']:
            if os.path.exists(options['files']) and os.path.isdir(options['files']):
                for root, dirs, files in os.walk(options['files']):
                    #print root, dirs, files
                    if fnmatch(root, options['mask']):
                        # this root matches the mask function
                        # find all the log files
                        #f  = [j for j in files if fnmatch(j, "log*")]
                        f  = [j for j in files]
                        # process each log file
                        if len(f):
                            for i in f:
                                processFile(root+"/"+i)
            else:
                print "File not found: %s" % options['files']
                sys.exit(2)

        # no args indicating files, read from stdin
        else:
            # can't really do true stdin input, since we repeatedly parse
            # the file, so create a tempfile that is read from stdin
            # pass it to processFile
            fh = sys.stdin
            tmph, tmpf = tempfile.mkstemp()
            tmph = open(tmpf, 'wb')
            for l in fh:
                tmph.write(l)
            tmph.close()
            processFile(tmpf)
            # all done, delete the tmp file
            os.unlink(tmpf)

        cleanup(options)  
    else:    
        print_help()

if __name__ == "__main__":
    #import profile
    #profile.run('main()', 'mainprof')

    main()




