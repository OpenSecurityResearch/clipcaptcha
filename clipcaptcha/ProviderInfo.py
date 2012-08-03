# Copyright (c) 2012 Gursev Singh Kalra McAfee, Foundstone
#
# This class contains information for all CAPTCHA providers that this tool targets

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


import sys
from xml.etree.ElementTree import ElementTree

class ProviderInfo:
	_bypassString = None
	_providers = []
	
	def __init__(self, name, hostname, path):
		self.name = name
		self.hostname = hostname
		self.path = path

	@staticmethod
	def exxit(msg):
		print msg
		sys.exit()

	def addSuccessFailure(self, responseType, sOrF):
		responseType = responseType[0]
		rcode = responseType.findall("rcode")
		rcodestr = responseType.findall("rcodestr")
		if(len(rcode) == 0 or len(rcodestr) == 0):
			ProviderInfo.exxit("[-] Success response codes not found for a CAPTCHA provider. Exiting")
		rcode = rcode[0]
		rcodestr = rcodestr[0]
		
		if(rcode.text == None or rcode.text.strip() == ''or rcodestr.text == None or rcodestr.text.strip() == ''):
			ProviderInfo.exxit("[-] Invalid rcode or rcodestr elements. Exiting")
		
		rbody = responseType.findall("rbody")
		if(len(rbody) == 0):
			rbody = ''
		else:
			rbody = rbody[0]
			if(rbody.text == None):
				rbody = ''
			else:
				rbody = rbody.text.strip()
		rbody = rbody.replace("\\n","\n")
		
		rheaders = responseType.findall("rheaders")
		headerDict = {}
		if(len(rheaders) != 0):
			rheaders = rheaders[0]
			headers = rheaders.findall("header")
			for header in headers:
				name = header.findall("name")
				value = header.findall("value")
				if(len(name) !=0 and len(value) != 0 and name[0].text != None and name[0].text.strip() != '' and value[0].text != None and value[0].text.strip() != '' ):
					headerDict[name[0].text.strip()] = value[0].text.strip()
		try:
			if(sOrF == "success"):
				self.setSuccessResp(int(rcode.text.strip()), rcodestr.text.strip(), headerDict, rbody)
			elif(sOrF == "failure"):
				self.setFailureResp(int(rcode.text.strip()), rcodestr.text.strip(), headerDict, rbody)
		except ValueError:
			ProviderInfo.exxit("[-] Invalid Response code in config XML")
	
	def setSuccessResp(self, sCode, sCodeStr, sHeaders, sBody):
		self.sCode = sCode
		self.sCodeStr = sCodeStr
		self.sHeaders = sHeaders
		self.sBody = sBody

	def setFailureResp(self, fCode, fCodeStr, fHeaders, fBody):
		self.fCode = fCode
		self.fCodeStr = fCodeStr
		self.fHeaders = fHeaders
		self.fBody = fBody
	
	@staticmethod
	def getProviders():
		return ProviderInfo._providers

	@staticmethod
	def setBypassString(bypass):
		ProviderInfo._bypassString = bypass

	@staticmethod
	def getBypassString():
		return ProviderInfo._bypassString
	
	@staticmethod
	def initProviders(configFile = "config.xml"):
		if(configFile == None):
			temp = ProviderInfo('reCAPTCHA', 'www.google.com', '/recaptcha/api/verify')	
			temp.setSuccessResp(200, "OK", {}, "true")
			temp.setFailureResp(200, "OK", {}, "false\nincorrect-captcha-sol")
			ProviderInfo._providers.append(temp)

			temp = ProviderInfo('OpenCAPTCHA', 'www.opencaptcha.com', '/validate.php')	
			temp.setSuccessResp(200, "OK", {}, "pass")
			temp.setFailureResp(200, "OK", {}, "fail")
			ProviderInfo._providers.append(temp)

			temp = ProviderInfo('Captchator', 'captchator.com', '/captcha/check_answer/')	
			temp.setSuccessResp(200, "OK", {}, "1")
			temp.setFailureResp(200, "OK", {}, "0")
			ProviderInfo._providers.append(temp)

		else:
			try:
				with open(configFile) as f: pass
			except IOError as e:
				ProviderInfo.exxit("[-] Configuration file not found. Exiting")

			tree = ElementTree()
			tree.parse(configFile)


			providers = tree.findall("provider")
			if( len(providers) == 0):
				ProviderInfo.exxit("[-] No CAPTCHA providers found in config file")

			for provider in providers:
				name = provider.findall("name")
				hostname = provider.findall("hostname")
				path = provider.findall("path")
				success = provider.findall("success")
				failure = provider.findall("failure")

				if(len(name) == 0 or len(hostname) == 0 or len(path) == 0 or len(success) == 0 or len(failure) == 0 ):
					ProviderInfo.exxit("[-] One among name, hostname, path, success or failure elements not found for a CAPTCHA provider. Exiting")
	
				name = name[0]
				hostname = hostname[0]
				path = path[0]
	
				if(name.text == None or name.text.strip() == '' or hostname.text == None or hostname.text.strip() == '' or path.text == None or path.text.strip() == ''):
					ProviderInfo.exxit("[-] One or more of name, hostname or path elements has a blank value")
	
				tprovider = ProviderInfo(name.text.strip(), hostname.text.strip(), path.text.strip())
				tprovider.addSuccessFailure(success, "success")
				tprovider.addSuccessFailure(failure, "failure")
				ProviderInfo._providers.append(tprovider)
