# Copyright (c) 2004-2011 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

#regular expression support
import re

class URLMonitor:    

    # Start the arms race, and end up here...
    javascriptTrickery = [re.compile("http://.+\.etrade\.com/javascript/omntr/tc_targeting\.html")]
    _instance          = None

    def __init__(self):
		#A set object is an unordered collection of distinct hashable objects. . Common uses include membership testing, removing duplicates from a sequence, and computing mathematical operations such as intersection, union, difference, and symmetric difference. Like other collections, sets support x in set, len(set), and for x in set. Being an unordered collection, sets do not record element position or order of insertion. Accordingly, sets do not support indexing, slicing, or other sequence-like behavior. he set type is mutable the contents can be changed using methods like add() and remove(). Since it is mutable, it has no hash value and cannot be used as either a dictionary key or as an element of another set.
        self.strippedURLs       = set()
        self.strippedURLPorts   = {}

    def isSecureLink(self, client, url):
        for expression in URLMonitor.javascriptTrickery:
            if(re.match(expression, url)):
                return True

        return (client,url) in self.strippedURLs

    def getSecurePort(self, client, url):
        if (client,url) in self.strippedURLs:
            return self.strippedURLPorts[(client,url)]
        else:
            return 443

    def addSecureLink(self, client, url):
        methodIndex = url.find("//") + 2
        method      = url[0:methodIndex]

        pathIndex   = url.find("/", methodIndex)
        host        = url[methodIndex:pathIndex]
        path        = url[pathIndex:]

        port        = 443
        portIndex   = host.find(":")

        if (portIndex != -1):
            host = host[0:portIndex]
            port = host[portIndex+1:]
            if len(port) == 0:
                port = 443
        
        url = method + host + path

        self.strippedURLs.add((client, url))
        self.strippedURLPorts[(client, url)] = int(port)


    def getInstance():
        if URLMonitor._instance == None:
            URLMonitor._instance = URLMonitor()

        return URLMonitor._instance

    getInstance = staticmethod(getInstance)
