#!/usr/bin/env python
"""clipcaptcha is a CAPTCHA Provider masquerading tool based off Moxie Marlinspike's SSLStrip codebase"""
# Copyright (c) 2012 Gursev Singh Kalra @ McAfee Foundstone
# Copyright (c) 2004-2011 Moxie Marlinspike
 
__author__ = "Gursev Singh Kalra"
__email__  = "gursev.kalra@foundstone.com"
__license__= """
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA
"""

from twisted.web import http
from twisted.internet import reactor

from clipcaptcha.StrippingProxy import StrippingProxy
from clipcaptcha.URLMonitor import URLMonitor
from clipcaptcha.ProviderInfo import ProviderInfo
from clipcaptcha.Mode import Mode
from clipcaptcha.ClientRequest import ClientRequest

import sys, getopt, logging, traceback, string, os

gVersion = "0.1"

def usage():
	print "=>> clipcaptcha " + gVersion + " by Gursev Singh Kalra"
	print "Usage: clipcaptcha <mode> <options>"
	print "Modes(choose one):"
	print "\t-m , --monitor				Listen and log. No changes made (default)"
	print "\t-a , --avalanche			Return success for all CAPTCHA validations"
	print "\t-s <secret> , --stealth <secret>  	Stealth mode with secret string to approve our own submissions"
	print "\t-d , --dos			 	Return failure for all CAPTCHA validations"
	print "\t-r , --random				Return random success or failures for CAPTCHA validations"
	print "Options:"
	print "\t-c <filename> , --config=<filename> 	clipcaptcha Config file with CAPTCHA provider signatures (optional)"
	print "\t-p <port> , --port=<port>	 	Port to listen on (default 7777)."
	print "\t-f <filename> , --file=<filename> 	Specify file to log to (default clipcaptcha.log)."
	print "\t-l , --list			 	List CAPTCHA providers available"
	print "\t-h , --help			 	Print this help message."
	print ""
#	print "-p , --post					   Log only SSL POSTs. (default)"
#	print "-s , --ssl						Log all SSL traffic to and from server."
#	print "-a , --all						Log all SSL and HTTP traffic to and from server."
#	print "-k , --killsessions			   Kill sessions in progress."

def pickProvidersToClip():
	providers = ProviderInfo.getProviders()
	pIndexes = []
	providersToClip = []
	print "[+] Available CAPTCHA Providers =>"
	i = 0
	for provider in providers:
		print "\t" + str(i) + ": \t" + provider.name
		i = i+1
	indexes = raw_input("[?] Choose CAPTCHA Providers by typing space separated indexes below or press enter to clip all : ")
	indexes = indexes.split()
	for i in indexes:
		try:
			idx = int(i)
			if(idx > len(providers) - 1 or idx < 0):
				print "[-] Indexes must represent a valid CAPTCHA provider. Exiting!"
				sys.exit()
			pIndexes.append(idx)
		except ValueError:
			print "[-] Indexes must be integers. Exiting!"
			sys.exit()
	pIndexes = list(set(pIndexes))
	pIndexes.sort()
	for i in pIndexes:
		providersToClip.append(providers[i])
	if(len(providersToClip) == 0):
		return providers

	return providersToClip

	
def parseOptions(argv):
	modes 	 = 0
	logFile	  = 'clipcaptcha.log'
	logLevel = logging.WARNING
	listenPort   = 7777
	killSessions = False
	operationMode = Mode.MONITOR
	providersToClip = []
	runningMode = ""
	

	secretString 		= None	
	listProviders 		= False
	configFile		= "config.xml"

	
	try:				
		#Parse the arguments and store the options in opts. args basically gets ignored.
		# the ':' indicates that the option expects an argument to be passed.
		opts, args = getopt.getopt(argv, "s:amdrf:p:lhc:", ["secret=", "monitor", "avalanche", "dos", "random", "file=", "port=", "list", "help", "config="])

		# go over each option, store individual options in opt and arg. Then go through the ifelse structure and initialize various options.
		for opt, arg in opts:
			if opt in ("-h", "--help"):
				usage()
				sys.exit()
			elif opt in ("-m", "--monitor"):
				operationMode = Mode.MONITOR
				runningMode = "Monitor"
				modes = modes + 1
			elif opt in ("-a", "--avalanche"):
				operationMode = Mode.AVALANCHE
				runningMode = "Avalanche"
				modes = modes + 1
			elif opt in ("-s", "--stealth"):
				secretString = arg
				operationMode = Mode.STEALTH
				runningMode = "Stealth"
				modes = modes + 1
			elif opt in ("-d", "--dos"):
				operationMode = Mode.DOS
				runningMode = "DoS"
				modes = modes + 1
			elif opt in ("-r", "--random"):
				operationMode = Mode.RANDOM
				runningMode = "Random"
				modes = modes + 1
			elif opt in ("-c", "--config"):
				configFile = arg
			elif opt in ("-f", "--file"):
				logFile = arg
			elif opt in ("-p", "--port"):
				listenPort = arg
			elif opt in ("-l", "--list"):
				listProviders = True				
#			elif opt in ("-p", "--post"):
#				logLevel = logging.WARNING
#			elif opt in ("-s", "--ssl"):
#				logLevel = logging.INFO
#			elif opt in ("-a", "--all"):
#				logLevel = logging.DEBUG
#			elif opt in ("-k", "--killsessions"):
#				killSessions = True

		if(modes > 1):
			print "[-] Choose only one mode."
			print ""
			usage()
			sys.exit()

		if(modes < 1):
			print "[+] No mode selected. Defaulting to Monitor mode "
			runningMode = "Monitor"

		ProviderInfo.initProviders(configFile)

		if(listProviders == True):
			providers = ProviderInfo.getProviders()
			print "Available CAPTCHA Providers:"
			i = 0
			for provider in providers:
				print "\n\n######################################################################"
				print "\t" + str(i) + ": \t" + provider.name
				#print provider.hostname
				#print provider.path
				#print "============================ success =="
				#print provider.sCode
				#print provider.sCodeStr
				#print provider.sHeaders
				#print provider.sBody
				#print "============================ failure =="
				#print provider.fCode
				#print provider.fCodeStr
				#print provider.fHeaders
				#print provider.fBody
				i = i+1
			sys.exit()

		providersToClip = pickProvidersToClip()


		clippedNames = []
		for p in providersToClip:
			clippedNames.append(p.name)
		clipped = ", ".join(clippedNames)
		print "[+] Cool, I am clipping these CAPTHA providers => "+ clipped 
		print "[+] Running in " + runningMode + " mode"

		#return all options
		return (logFile, logLevel, listenPort, killSessions, secretString, operationMode, providersToClip)
	
	#Catch the exception, show usage and exit
	except getopt.GetoptError:		   
		usage()						  
		sys.exit(2)						 

def main(argv):
	(logFile, logLevel, listenPort, killSessions, secretString, operationMode, providersToClip) = parseOptions(argv)
		
	logging.basicConfig(level=logLevel, format='%(asctime)s %(message)s', filename=logFile, filemode='w')

	ClientRequest.setProvidersToClip(providersToClip)
	ClientRequest.setOperationModeAndSecret(operationMode, secretString) 


	strippingFactory		 = http.HTTPFactory(timeout=10)
	strippingFactory.protocol	 = StrippingProxy

	reactor.listenTCP(int(listenPort), strippingFactory)
	reactor.run()

if __name__ == '__main__':
	main(sys.argv[1:])
