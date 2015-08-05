#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Rewirtten / Modified / Personalized: Chris Clark ~ Palo Alto Networks
# API Key Setup / Multiple MD5 Lookup (and load balancing for free API): Chris Thurber
# If things are broken let me know chris@xenosec.org
# No License or warranty expressed or implied, use however you wish!

import time, datetime, json, urllib, urllib2, argparse, hashlib, re, sys, os
from pprint import pprint

homeDirectory = str(os.path.expanduser('~'))
def keySetup(apikey):
    if len(apikey) == 64:
        apiPath = homeDirectory+'/.vt_apikey'
        with open(apiPath,'w') as keyfile:
            pprint(apikey,keyfile)
        print "\n\tAPI key stored.\n"
    else:
        print "\n\t Error: Invalid API key"
        sys.exit(1)

def loadAPIKey():
    try:
        apiPath = homeDirectory+'/.vt_apikey'
        with open(apiPath,'r') as keyfile:
            key = keyfile.readline().strip('\n').strip("''")
            return key
    except:
        print "\n\t Error: Could not read API key."
        print "\t Please run again with '-k' to setup your API key.\n"
        sys.exit(1)

def dateParse():
    dt = datetime.datetime.now()
    day = str(dt.day)
    month = str(dt.month)
    if len(day) < 2:
        day = "0"+day
    if len(month) < 2:
        month = "0"+month
    return month+day+str(dt.year)

class vtAPI():
    def __init__(self):
        self.api = loadAPIKey()
        self.base = 'https://www.virustotal.com/vtapi/v2/'

    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata

    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"

# Md5 Function
def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else:
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest()

def parse(it, md5, verbose, jsondump, cleandump):
  dumpArray = []
  if it['response_code'] == 0:
    notfoundstr = str("\n\t"+md5 + " -- Not Found in VT")
    print notfoundstr
    dumpArray.append(notfoundstr)
    return 0
  resultstr = str("\n\tResults for MD5: "+str(it['md5']))
  detectedstr = str("\tDetected by: "+str(it['positives'])+'/'+str(it['total']))

  detectedline = detectedstr+'\n'
  resultsline = resultstr+'\n'
  print resultstr
  print detectedstr

  scans = []
  for scan in it['scans']:
    if str(it['scans'][scan]['result']) != "None":
      scanStr = str('\t' + scan + ': ' + str(it['scans'][scan]['result']))
      scans.append(scanStr)
    else:
      print "\t Nothing found from "+scan

  scannedonstr = str('\tScanned on:'+str(it['scan_date']))
  print scannedonstr

  if int(it['positives']) > 0:
    for scanned in scans:
      dumpArray.append(scanned)
    blank = " "
    dumpArray.append(blank)

  if jsondump == True:
    jsondumpfile = open("./VTDL-" + md5 + ".json", "w")
    pprint(it, jsondumpfile)
    jsondumpfile.close()
    print "\n\tJSON Written to File -- " + "/VTDL" + md5 + ".json"

  spacerLine = '----------------------------------------------------'
  if cleandump == True:
    dumpfile = "./VTDL-"+dateParse()+".txt"
    with open(dumpfile,'a') as df:
      dumpArray.append(resultsline)
      dumpArray.append(detectedstr)
      dumpArray.append(spacerLine)
      for item in dumpArray:
        line = item.strip('\t\n')
        pprint(line.strip("'"),df)
      dumpArray.append(scannedonstr)
    df.close()

  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

def getHashes(mdFile):
  hashes = []
  with open(mdFile, 'r') as mdf:
    for line in mdf:
      row = line.strip('\n').strip(',')
      hashes.append(row)
  mdf.close()
  return hashes

def parseMultipleMDF(hashArray, verbose, jsondump, cleandump):
  calls = 0
  for keyhash in hashArray:
    if calls == 0 or (calls%4) != 0:
      vt = vtAPI()
      parse(vt.getReport(keyhash), keyhash, verbose, jsondump, cleandump)
      calls += 1
    else:
      seconds = 61
      while seconds > 0:
        sys.stdout.write('\r\n\t --- Waiting '+str(seconds)+' seconds... ---')
        sys.stdout.flush()
        time.sleep(1)
        seconds -= 1
      sys.stdout.flush()
      parseMultipleMDF(hashArray[calls:], verbose, jsondump, cleandump)

def main():
  opt=argparse.ArgumentParser(description="Search and Download from VirusTotal")
  opt.add_argument("HashorPath", help="Enter the MD5/SHA1/256 Hash or Path to File")
  opt.add_argument("-s", "--search", action="store_true", help="Search VirusTotal for MD5/SHA hash")
  opt.add_argument("-m", "--multisearch", action="store_true", help="Search VirusTotal for multiple MD5/SHAs")
  opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
  opt.add_argument("-c", "--cleandump", action="store_true",help="Dumps the clean VT report to file (VTDL-XXX.txt)")
  opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDL-XXX.json)")
  opt.add_argument("-r", "--rescan",action="store_true", help="Force Rescan with Current A/V Definitions")
  opt.add_argument("-k", "--addkey",action="store_true", help="Add your api key")
  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)
  options= opt.parse_args()
  if options.addkey:
    keySetup(options.HashorPath)
  vt=vtAPI()
  md5 = checkMD5(options.HashorPath)
  if options.search and options.multisearch and ".csv" in str(options.HashorPath):
    parseMultipleMDF(getHashes(options.HashorPath), options.verbose, options.jsondump, options.cleandump)
  elif options.search or options.jsondump or options.verbose:
    parse(vt.getReport(md5), md5 ,options.verbose, options.jsondump, options.cleandump)
  if options.rescan:
    vt.rescan(md5)

if __name__ == '__main__':
    main()
