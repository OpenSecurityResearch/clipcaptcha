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

import logging, re, string

from ServerConnection import ServerConnection

class SSLServerConnection(ServerConnection):

    cssExpression      = re.compile(r"url\(([\w\d:#@%/;$~_?\+-=\\\.&]+)\)", re.IGNORECASE)
    linkExpression     = re.compile(r"<((a)|(link)|(img)|(script)|(frame)) .*((href)|(src))=\"([\w\d:#@%/;$()~_?\+-=\\\.&]+)\".*>", re.IGNORECASE)
    headExpression     = re.compile(r"<head>", re.IGNORECASE)

    def __init__(self, command, uri, postData, headers, client):
        ServerConnection.__init__(self, command, uri, postData, headers, client)

    def getLogLevel(self):
        return logging.INFO

    def getPostPrefix(self):
        return "SECURE POST"

    def handleHeader(self, key, value):
        ServerConnection.handleHeader(self, key, value)

    def stripFileFromPath(self, path):
        (strippedPath, lastSlash, file) = path.rpartition('/')
        return strippedPath

