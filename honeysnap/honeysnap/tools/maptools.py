"""
maptools.py

Copyright (c) 2007 Honeynet Porject

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

"""

# $Id$

from matplotlib.toolkits.basemap import Basemap  
from numpy.oldnumeric.functions import arange
       
class MaptoolsError(Exception):
    """generic error"""
    pass

class Worldmap(object):
    """helper class for plotting ip objects on a world map"""
    def __init__(self, meridians = False):
        """Setup a maptool class. Meridians: Plot meridians or not"""
        self.map = Basemap(projection = 'mill')
        self.map.drawcoastlines(linewidth=0.5)
        self.map.drawcountries()                        
        # next line should work with basemap svn 
        # to place points on top of continent fill
        #self.map.fillcontinents(color='coral', zorder=0)         
        if meridians:
            meridians = arange(-180, 180, 45,)
            self.map.drawmeridians(meridians, labels=[1,1,1,1])
        
    def plot_ips(self, ips, size=20, color='blue', marker='o'):
        """
        Add a marker to the map for each ip in ips
        Ips can be either a list of IP objects or a sqa resultproxy object
        color and size are passed though to Basemap.scatter
        """           
        lats = []
        longs = []
        for ip in ips:                    
            if ip.latitude and ip.longitude:
                lats.append(ip.latitude)
                longs.append(ip.longitude)
            else:
                raise MaptoolsError("Missing latitude or longitude for %s" % ip.ip_addr) 
        x, y = self.map(longs, lats)        
        self.map.scatter(x, y, s=size, color=color, marker=marker)

