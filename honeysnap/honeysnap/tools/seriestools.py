"""
seriestools.py

Copyright (c) 2007 Honeynet Project

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

"""

# $Id$
                   
import datetime 
from matplotlib import pylab 
from matplotlib.dates import YEARLY, MONTHLY, DAILY, HOURLY, DateFormatter, rrulewrapper, RRuleLocator, drange

class DateSeries(object):
    """
    Useful class for plotting trends over time. Summary:
    
    s1 = rand(31)
    s2 = rand(31)
    st = datetime(2007,01,01)
    ft = datetime(2007,02,01)
    d = DateSeries(st, ft)
    d.plot_dates(s1)
    d.plot_dates(s2, color='red')
    """
    def __init__(self, starttime, endtime, period=DAILY, interval=7, delta=datetime.timedelta(days=1)):
        """
        Set up axis and time periods
        starttime, endtime = datettime.datetime objects
        period = YEARLY | MONTHLY | DAILY | HOURLY
        interval = put axis labels every N periods.
        delta = time delta between data points (datetime.timedelta)
        """                                                     
        self.starttime = starttime
        self.endtime = endtime
        self.delta = delta
        rule = rrulewrapper(period, interval=interval)
        loc = RRuleLocator(rule)
        formatter = DateFormatter('%d/%m/%y')
        dates = drange(starttime, endtime, delta)
        ax = pylab.subplot(111)
        ax.xaxis.set_major_locator(loc)
        ax.xaxis.set_major_formatter(formatter)
        labels = ax.get_xticklabels()
        pylab.setp(labels, rotation=30, fontsize=10)

    def plot_dates(self, s, color='blue', marker='.', linestyle='-'):        
        """
        plot data series s e.g. s = [45,3,53]
        To plot two or more data series on the same graph, just call this function
        again with the other data set and specify suitable colours etc. 
        For details on the color, marker and linestyle options, see pylab.plot
        """    
        dates = drange(self.starttime, self.endtime, self.delta)
        pylab.plot_date(dates, s, color=color, marker=marker, linestyle=linestyle) 