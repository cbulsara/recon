##Imports
import argparse
import time

##Conditional import for older versions of python not compatible with subprocess
##Set compatmode = 0 if new, 0 if old
try:
    import subprocess as sub
    compatmode = 0  #newer version of python, no need for compatibility mode
except ImportError:
    import os   #older version of python, need to use os instead
    compatmode = 1



##define arguments and return namespace
def initArgParser():                    

    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Host IP to be reconnoitered")
    parser.add_argument("-n", "--nmap", help="Run standard port scan",
                            action="store_true")
    parser.add_argument("-nC", "--nmapC", help="Run a port scan with user-defined options",
                            action="store_true")                            
    parser.add_argument("-d", "--dirb", help="Initiate dirb with the wordlist at the specified path")
    parser.add_argument("-k", "--nikto", help="Standard Nikto scan",action ="store_true")
    parser.add_argument("-kC", "--niktoC", help="Custom Nikto scan with user-defined options",action="store_true")
    parser.add_argument("-o", "--outfile", help="Write to file with user-defined prefix")
    parser.add_argument("-v", "--verbosity", type=int, choices=[0,1,2], 
                            help="Silence or increase verbosity")
    parser.add_argument("-D", "--debug", help="Print debug info",
                            action="store_true")
    parser.add_argument("-Y", "--Yes", help="Don't ask permission",
                        action="store_true")                    
  
    return parser.parse_args()
##/
# execute commands in a dictionary
##
def execCmd(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
    if compatmode == 0:
            out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
            results = out.split('\n')
    else:
    	    echo_stdout = os.popen(cmd, 'r')
            results = echo_stdout.read().split('\n')
    cmdDict[item]["results"]=results
    return cmdDict

##/
#print results stored in a cmdDict
##
def printResults(cmdDict):
    for item in cmdDict:
	msg = cmdDict[item]["msg"]
	results = cmdDict[item]["results"]
        print "[+] " + msg
        for result in results:
	    if result.strip() != "":
	        print "    " + result.strip()
	print
    return

##/
# Drop services from nmap scan into a list
##
def getTCP(results):    
    services = []
    for result in results:
        if result and "/tcp" in result.split()[0] and "open" in result:
            #services.append(result.split()[2])   
            services.append(result)
    return services

##/
# Web Recon
##
def webRecon(result, host, outfile, wordlist="/usr/share/wordlists/dirb/small.txt"):
    results = []
    
    if 'https' in result:
        cmdDirb = {"DIRB":{"cmd":"dirb " + "https://" +"%s %s -S -w >> %s_https.dirb" % (host, wordlist, outfile),
                    "msg":"Dirb Scan", "results":resulhttps}}
        print(cmdDirb["DIRB"]["cmhttps"])
        cmdDirb = execCmd(cmdDhttps)
        printResults(cmdDirb)    

    else:
        cmdDirb = {"DIRB":{"cmd":"dirb " + "http://" +"%s %s -S -w >> %s_http.dirb" % (args.host, wordlist, args.host),
                    "msg":"Dirb Scan", "results":results}}
        print(cmdDirb["DIRB"]["cmd"])
        cmdDirb = execCmd(cmdDirb)
        printResults(cmdDirb)

    cmdNmapScript = {"NMAP Script":{"cmd":"nmap -sV -Pn -vv --host-timeout 10m -p %s --script='(http* or ssl*) and not (broadcast or dos or external or http-slowloris* or fuzzer)' %s >> %s_web.nmap"
                    % (result.split("/")[0], host, outfile),"msg":"NMAP Web Scripts","results":results}}
    print(cmdNmapScript["NMAP Script"]["cmd"])
    cmdNmapScript = execCmd(cmdNmapScript)
    printResults(cmdNmapScripts)

    cmdNikto = {"NIKTO":{"cmd":"nikto -F csv -o '%s_nikto.csv' -h '%s'" % (outfile, host), 
                "msg":"Nikto Web Vulnerability Scan", "results":results}}
    cmdNikto = execCmd(cmdNikto)
    printResults(cmdNikto)

##/
#SMB Recon
##
def smbRecon(result, host, outfile):
    results = []

    cmdNmapScript = {"NMAP Script":{"cmd":"nmap -sV -Pn -vv -p %s --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 %s >> %s_smb.nmap"
                    % (result.split("/")[0], host, outfile),"msg":"NMAP SMB Scripts","results":results}}
    print(cmdNmapScript["NMAP Script"]["cmd"])
    cmdNmapScript = execCmd(cmdNmapScript)
    printResults(cmdNmapScript)

##/
# Main
##

#Start the clock
start_time = time.time()

#Declarations
args = initArgParser()
results = []						#results array	

#parse args
if args.debug:        					#debug mode
    for k in args.__dict__:
        if args.__dict__[k] is not None:
            print (args.__dict__[k])
    print ("Compatibility Mode: " + str(co1mpatmode))

if args.nmap:
    ##cmdNmap = {"SCAN":{"cmd":"nmap -vv -Pn -A -sC -sV -T4 -p- -oN '%s.nmap' -oX '%s.xml' %s" 		##full for PROD	
                ##% (args.outfile, args.outfile, args.host),"msg":"NMap Port Scan","results":results}}
    cmdNmap = {"SCAN":{"cmd":"nmap -vv -T4 -F -oN '%s.nmap' -oX '%s.xml' %s" 			##quickie for debug
                % (args.outfile, args.outfile, args.host),"msg":"NMap Port Scan","results":results}}
    cmdNmap = execCmd(cmdNmap)
    printResults(cmdNmap)
    tcpServices = getTCP(cmdNmap["SCAN"]["results"])
    if tcpServices:
        for result in tcpServices:
            print(result)
            #if 'http' or 'https' in result:
                #webRecon(result, args.host, args.outfile)
            if '139' in result:
                smbRecon(result, args.host, args.outfile)
            if '445' in result:
                smbRecon(result, args.host, args.outfile)
    else:
        print ("No open exploitable services found.")
        
if args.nmapC:
    options = raw_input('Enter options: ')
    cmdNmapC = {"SCAN":{"cmd":"nmap " + options + " " + args.host,"msg":"Custom NMap Scan","results":results}}
    cmdNmapC = execCmd(cmdNmapC)
    printResults(cmdNmap)
    tcpServices = getTCP(cmdNmap["SCAN"]["results"])
    if tcpServices:
        for result in tcpServices:
            if 'http' or 'https' in result:
                webRecon(result, args.host, args.outfile)    
    else:
        print ("No open exploitable services found.")

if args.nikto:
    cmdNikto = {"NIKTO":{"cmd":"nikto -F csv -o '%s_nikto.csv' -h '%s'" % (args.outfile, args.host), 
                "msg":"Nikto Web Vulnerability Scan", "results":results}}
    cmdNikto = execCmd(cmdNikto)
    printResults(cmdNikto)

if args.niktoC:
    options = raw_input('Enter options: ')
    cmdNiktoC = {"NIKTO":{"cmd":"nikto " + options + " -h " + args.host, 
                "msg":"Nikto Web Vulnerability Scan", "results":results}}
    print(cmdNiktoC["NIKTO"]["cmd"])
    cmdNiktoC = execCmd(cmdNiktoC)
    printResults(cmdNiktoC)

if args.dirb:
    cmdDirb = {"DIRB":{"cmd":"dirb " + "http://" +"%s %s -S -w >> %s.dirb" % (args.host, args.dirb, args.host),
                "msg":"Dirb Scan", "results":results}}
    print(cmdDirb["DIRB"]["cmd"])
    cmdDirb = execCmd(cmdDirb)
    printResults(cmdDirb)

#stop the clock and print elapsed time
print ("%s seconds elapsed" % (time.time() - start_time))