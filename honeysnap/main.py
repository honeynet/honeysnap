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

import sys
import socket
from optparse import OptionParser, Option, OptionValueError 
import re
import string
import time
import os
from fnmatch import fnmatch
import ConfigParser
from ConfigParser import SafeConfigParser
import tempfile
import pcap
import pkg_resources

# all the honeysnap imports
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
from util import make_dir, check_pcap_file
from dnsDecode import dnsDecode
from telnetDecode import telnetDecode
from socksDecode import SocksDecode



VERSION=pkg_resources.get_distribution('honeysnap')

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

    default_filters = []

    if options["disable_default_filters"] == "NO":

        irc_ports = options["irc_ports"]["global"]
        if len(irc_ports)==1:
            irc_filter = "dst port %s" % irc_ports.pop()
        else:
            irc_filter = "("
            port = [ 'dst port %s' % port for port in irc_ports ]
            irc_filter = irc_filter + " or ".join(port) + ")"
        
        default_filters = [
            ('Total IPv4 packets:', 'host %s and ip'),
            ('Total TCP packets:', 'host %s and tcp'),
            ('Total UDP packets (excluding sebek port):', 'host %s and udp and not port %s' % ('%s', options['sebek_port'])),
            ('Total ICMP packets:', 'host %s and icmp'),
            ('Total OTHER packets', 'host %s and not udp and not tcp and not icmp'),
            ('Outbound DNS packets:','src host %s and dst port 53'),
            ('Inbound DNS packets:','dst host %s and dst port 53'),
            ('Outbound FTP packets:','src host %s and dst port 21'),
            ('Inbound FTP packets:','dst host %s and dst port 21'),
            ('Outbound SSH packets:','src host %s and dst port 22'),
            ('Inbound SSH packets:','dst host %s and dst port 22'),
            ('Outbound Telnet packets:','src host %s and dst port 23'),
            ('Inbound Telnet packets:','dst host %s and dst port 23'),
            ('Outbound SMTP packets:','src host %s and dst port 25'),
            ('Inbound SMTP packets:','dst host %s and dst port 25'),
            ('Outbound HTTP packets:','src host %s and dst port 80'),
            ('Inbound HTTP packets:','dst host %s and dst port 80'),
            ('Outbound HTTPS packets:','src host %s and dst port 443'),
            ('Inbound HTTPS packets:','dst host %s and dst port 443'),
            ('Outbound IRC packets:','src host %s and tcp and %s' % ('%s', irc_filter)),
            ('Inbound IRC packets:','dst host %s and tcp and %s' % ('%s', irc_filter)),
            ('Sebek packets:','src host %s and udp port %s' % ('%s', options["sebek_port"])),
            ]

    if options["user_filter_list"]:
        if options["disable_default_filters"] == "YES":
            default_filters = options["user_filter_list"]
        else:
            default_filters.extend(options["user_filter_list"])

    return default_filters

def processFile(file):
    """
    Process a pcap file.
    file is the pcap file to parse
    This function will run any enabled options for each pcap file
    """
    hs = HoneysnapSingleton.getInstance()
    options = hs.getOptions()

    tmpf, deletetmp = check_pcap_file(file)
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

    out("\n\nAnalysing file: %s\n\n" % file)

    if options["do_pcap"] == "YES":
        out("Pcap file information:\n")
        pi = pcapInfo(tmpf)
        pi.setOutput(out)
        pi.getStats()
        myout = rawPathOutput(options["output_data_directory"] +"/pcapinfo.txt")
        pi.setOutput(myout)
        pi.getStats()
        out("\n")

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
                del p
            out("\n")

    if options["do_incoming"] == "YES":
        for hp in options["honeypots"]:
            out("Counting incoming connections for %s\n" % hp)
            outdir = options["output_data_directory"] + "/%s/conns" % hp
            make_dir(outdir)
            p = pcap.pcap(tmpf)
            s = Summarize(p)
            filt = 'dst host %s' % hp
            s.setFilter(filt)
            s.start()
            fileout = rawPathOutput(outdir+"/incoming.txt", mode="a")
            if options["print_verbose"] == "YES":
                outputs = (fileout, out)
            else:
                outputs = (fileout,)
            for output in outputs:
                s.setOutput(output)
                s.doOutput("\nIncoming connections for %s\n" % hp)
                s.writeResults(limit=options["flow_count_limit"])
            del p


    if options["do_outgoing"] == "YES":
        for hp in options["honeypots"]:
            out("\nCounting outgoing connections for %s\n" % hp)
            outdir = options["output_data_directory"] + "/%s/conns" % hp
            make_dir(outdir)
            p = pcap.pcap(tmpf)
            s = Summarize(p)
            filt = 'src host %s' % hp
            s.setFilter(filt)
            s.start()
            fileout = rawPathOutput(outdir+"/outgoing.txt", mode="a")
            if options["print_verbose"] == "YES":
                outputs = (fileout, out)
            else:
                outputs = (fileout,)
            for output in outputs:
                s.setOutput(output)
                s.doOutput("\nOutgoing connections for %s\n" % hp)
                s.writeResults(limit=options["flow_count_limit"])
            del p

    if options["do_dns"] == "YES":
        out("\nExtracting DNS data to file\n\n")
        for hp in options["honeypots"]:
            #out("\nHoneypot %s\n\n" % hp)
            dns = dnsDecode(hp, direction="queried")
            dns.setOutdir(options["output_data_directory"] + "/%s/dns" % hp)
            dns.setOutput(out)
            dns.run()
            del dns
            dns = dnsDecode(hp, direction="served")
            dns.setOutdir(options["output_data_directory"] + "/%s/dns" % hp)
            dns.setOutput(out)
            dns.run()
            del dns

    if options["do_telnet"] == "YES":
        out("\nExtracting telnet data to file\n")
        for hp in options["honeypots"]:
            #out("\nHoneypot %s\n\n" % hp)
            tel = telnetDecode(hp)
            tel.setOutdir(options["output_data_directory"] + "/%s/telnet" % hp)
            tel.setOutput(out)
            tel.run()
            del tel

    if options["do_irc"] == "YES":
        """
        Here we will use PcapRE to find packets on irc_port with "PRIVMSG"
        in the payload. 
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
            for port in r.server_ports(options['irc_ports'][hp]):
                if port not in options['irc_ports'][hp]:    
                    if port==80:
                        out("\nSaw PRIVMSG on port 80, but cowardly not adding it to IRC port list - check manually\n")
                    else:
                        out("\nAdding port %s to irc list for %s\n" % (port, hp)) 
                        options['irc_ports'][hp].add(port) 
            del p
            del r

        out("\nAnalysing IRC\n")
        for hp in options["honeypots"]:
            outdir = options["output_data_directory"] + "/%s/irc" % hp
            for port in options["irc_ports"][hp]:
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
                del hirc

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
        de.dump_extract()
        del de
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
        de.dump_extract()
        decode.print_summary()
        del de
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
        de.dump_extract()
        decode.print_summary() 
        del de
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
        de.dump_extract()
        decode.print_summary() 
        del de
        del p

    if options["do_sebek"] == "YES":
        out("\nExtracting Sebek data\n")
        for hp in options["honeypots"]:
            out("\nHoneypot %s\n\n" % hp)
            sbd = sebekDecode(hp)
            sbd.setOutdir(options["output_data_directory"] + "/%s/sebek" % hp)
            sbd.setOutput(out)
            sbd.run()
            sbd.print_summary()
            del sbd

    if options["do_socks"] == "YES":
        out("\nExtracting Socks proxy information:\n")
        for hp in options["honeypots"]:
            out("\nHoneypot %s\n\n" % hp)
            p = pcap.pcap(tmpf)
            socks = SocksDecode(p,hp)
            socks.setOutdir(options["output_data_directory"] + "/%s/socks" % hp)
            socks.setOutput(out)
            socks.start()

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
                    try:
                        os.remove(os.path.join(root, name))
                    except OSError:
                        continue
        for name in dirs:
            if not len(os.listdir(os.path.join(root, name))):
                #print "removing dir %s" % os.path.join(root, name)
                try:
                    os.rmdir(os.path.join(root, name))
                except OSError:
                    continue

def store_int_array(option, opt_str, value, parser):
    """Store comman seperated integer values from options into an array"""
    a = []
    a = value.split(",")
    try:
        a = [ int(n) for n in a ]
    except ValueError:
        raise OptionValueError("Argument %s not an integer!" % opt_str)
    setattr(parser.values, option.dest, a)

def store_filter_array(option, opt_str, value, parser):
    """Store comma/space separated filters from options into an array."""
    l_user_filter_list = []
    for option in re.findall('\[(.*?)\]', value):
        try:
            (l_label, l_filter_string) = option.split(",")
        except ValueError:
            raise OptionValueError("Cannot embed commas in text or filter string")
        l_filter_tuple = (l_label, l_filter_string) 
        l_user_filter_list.append(l_filter_tuple)
    setattr(parser.values, "user_filter_list", l_user_filter_list)

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
        'wordfile'          : None,
        'files'             : None,
        'use_utc'           : 'NO',
        'raw_time'          : 'NO',
        'do_pcap'           : 'YES',
        'do_packets'        : 'NO',
        'do_incoming'       : 'NO',
        'do_outgoing'       : 'NO',
        'print_verbose'     : 'NO',
        'flow_count_limit'  :  0,
        'do_dns'            : 'NO',
        'do_http'           : 'NO',
        'print_served'      : 'NO',
        'print_http_logs'   : 'NO',
        'do_ftp'            : 'NO',
        'do_smtp'           : 'NO',
        'do_irc'            : 'NO',
        'irc_ports'         : [],
        'irc_limit'         : 10,
        'do_sebek'          : 'NO',
        'do_telnet'         : 'NO',
        'sebek_port'        : 1101,
        'sebek_excludes'    : ["configure", "prelink", "sshd", "sa2", "makewhatis"],
        'sebek_all_data'    : 'NO',
        'all_flows'         : 'NO',
        'output_data_directory'   : 'output',
		'disable_default_filters'   : 'NO',
		'user_filter_list'	: None,
        'do_socks'          : 'NO',
    }

    parser = OptionParser(option_class=MyOption, version="%s" % VERSION)

    parser.add_option("-c", "--config", dest="config",type="string",
        help="Config file")
    parser.add_option("-f", "--file", dest="filename",type="string",
        help="Write report to FILE", metavar="FILE")
    parser.add_option("-o", "--output", dest="output_data_directory",type="string",
        help="Write output to DIR, defaults to 'output'", metavar="DIR")
    parser.add_option("-H", "--honeypots", dest="honeypots", action="extend", type="string",
        help="Comma delimited list of honeypots")
    parser.add_option("-w", "--words", dest="wordfile", type="string",
        help = "Pull wordlist from FILE", metavar="FILE")

    parser.add_option("--use-utc", dest="use_utc", action="store_const", const="YES",
        help = "Times in UTC? (Otherwise use localtime)")
    parser.add_option("--raw-time", dest="raw_time", action="store_const", const="YES",
        help = "Just print raw timestamps? (Overrides --use-utc)")

    #parser.add_option("--do-pcap", dest="do_pcap", action="store_const", const="YES",
    #    help = "Summarise pcap info")
    parser.add_option("--do-packets", dest="do_packets", action="store_const", const="YES",
        help = "Summarise packet counts")
    parser.add_option("--do-incoming", dest="do_incoming", action="store_const", const="YES",
        help = "Summarise incoming traffic flows")
    parser.add_option("--do-outgoing", dest="do_outgoing", action="store_const", const="YES",
        help = "Summarise outgoing traffic flows")
    parser.add_option("--print-verbose", dest="print_verbose", action="store_const", const="YES",
        help = "Print verbose flow counts to screen as well as storing in a file (needs --do-incoming or --do-outgoing)")
    parser.add_option("--flow-count-limit", dest="flow_count_limit", type="int",
        help = "Only print/write to file flows with more than N packets? 0 = all")
    parser.add_option("--do-dns", dest="do_dns", action="store_const", const="YES",
        help = "Extract DNS data")
    parser.add_option("--do-http", dest="do_http", action="store_const", const="YES",
        help = "Extract http data")
    parser.add_option("--print-served", dest="print_served", action="store_const", const="YES",
        help = "Print extracted files served by the honeypot(s)? (Requires --do-http, --do-ftp or --do-smtp)")
    parser.add_option("--print-http-logs", dest="print_http_logs", action="store_const", const="YES",
        help = "Print http requests in log file format? (Requires --do-http)")
    parser.add_option("--do-ftp", dest="do_ftp", action="store_const", const="YES",
        help = "Extract FTP data")
    parser.add_option("--do-smtp", dest="do_smtp", action="store_const", const="YES",
        help = "Extract smtp data")
    parser.add_option("--do-telnet", dest="do_telnet", action="store_const", const="YES",
        help = "Extract Telnet data")
    parser.add_option("--do-irc", dest="do_irc", action="store_const", const="YES",
        help = "Summarize IRC and extract irc detail")
    parser.add_option("--irc-ports", action="callback", callback=store_int_array, dest="irc_ports", type="string",
        help = "Ports for IRC traffic (default 6667)")
    parser.add_option("--irc-limit", dest="irc_limit", type="int", help = "Limit IRC summary to top N items")
    parser.add_option("--do-sebek", dest="do_sebek", action="store_const", const="YES",
        help = "Extract Sebek data")
    parser.add_option("--sebek-port", dest="sebek_port", type="int", help = "Port for sebek traffic (default 1101)")
    parser.add_option("--sebek-excludes", dest="sebek_excludes", action="extend", type="string",
        help = "Exclude these commands when printing sebek output")
    parser.add_option("--sebek-all-data", dest="sebek_all_data", action="store_const", const="YES",
        help = "Extract all sebek data? Warning - produces a very large amount of data (gigabytes)")
    parser.add_option("--all-flows", dest="all_flows", action="store_const", const="YES",
        help = "Extract data from all tcp flows")
    parser.add_option("--disable-default-filters", 
        dest="disable_default_filters", action="store_const", 
        const="YES", help="Disables default bpf filters")
    parser.add_option("--user-filter-list", dest="user_filter_list", 
        help="Appends a user defined bpf filter list. ex: \"[Total IPv4 packets:, host %s and ip],[Total TCP packets:, host %s and tcp\"]", action="callback",
        callback=store_filter_array, type="string")
    parser.add_option("--do-socks", dest="do_socks", action="store_const", const="YES",
        help = "Extract Socks proxy data")


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
                        elif i[0] == 'flow_count_limit' or i[0]=='irc_limit' or i[0]=='sebek_port':
                            fileopts[i[0]] = int(i[1])
                        elif i[0] == 'honeypots' or i[0]=='sebek_excludes':
                            fileopts[i[0]] = i[1].split()
                        elif i[0] == 'user_filter_list':
                            store_filter_array(None, None, i[1], parser)
                        else:
                            fileopts[i[0]] = i[1]
            except ConfigParser.Error:
                print "Problem with the config file! Check format and permissions"
                sys.exit(1)
        else:
            print "Config file %s not found!" % cmdopts.config
            sys.exit(1)

    options = {}
    # now merge defaults, config file and command line
    for opt in defaults.keys():
        options[opt] = defaults[opt]
        if fileopts.has_key(opt) and fileopts[opt]:
            options[opt] = fileopts[opt]
        if cmdopts.__dict__.has_key(opt) and cmdopts.__dict__[opt]:
            options[opt] = cmdopts.__dict__[opt]

    options['output_data_directory'] = os.path.abspath(options['output_data_directory'])

    if options['use_utc'] == "YES":
        options['time_convert_fn'] = lambda x: time.asctime(time.gmtime(x))
    else:
        options['time_convert_fn'] = lambda x: time.asctime(time.localtime(x))
    if options['raw_time'] == "YES":
        if options['use_utc'] != 'YES':
            options['time_convert_fn'] = lambda x: x
        else:
            print "Can't use --raw-time with --use-utc"
            sys.exit(1)
                                            
    if not options['honeypots']:                                                               
        if not cmdopts.honeypots:
            parser.print_help()
        else:
            print "No honeypots specified! Please use either -H or the config file to specify some"
        sys.exit(1)
    
    # make irc ports per-honeypot
    irc_port_list = options['irc_ports']
    options['irc_ports'] = {}  
    options['irc_ports']['global'] = set(irc_port_list)
    for hp in options['honeypots']:
        options['irc_ports'][hp] = set(irc_port_list)
        
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

def start():
    """This is nothing but an entry-point for setuptools in which we can trap ctrl-c"""
    try:
        main()
    except KeyboardInterrupt:
        print 'Caught KeyboardInterrupt - Goodbye!'
        sys.exit(0)

if __name__ == "__main__":
    main()





