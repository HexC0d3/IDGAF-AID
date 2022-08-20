import os
from src.abuseIPDB import AbuseIpDb
import argparse
import textwrap
import concurrent.futures
from datetime import datetime
import base64


#----- Argument Handling -------
parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-db', \
    default='abusedb', \
    choices=['abusedb','all',],\
    help=textwrap.dedent('''Which database to use to check IP Reputation. Default: AbuseIPDB
    Available options: 
        abusedb\t\tAbuseIPDB 
        all\t\tAll Databases 
        New DBs\t\tComing Soon ;)'''))
group_parser = parser.add_mutually_exclusive_group(required=True)                   # To Force Either IP or Input File
group_parser.add_argument('-i','--ip',help='Single IP to check')
group_parser.add_argument('-f','--file', help='Text file containing IPs separated by linefeed')
parser.add_argument('-age','--lastSeen',help='Check IP reputation not older than <age> days | Default: 90 Days | Applicable to some databases only')

args = parser.parse_args()

#------------------- ****** ---------------------#

# ---------------- BANNER --------------------
BANNER = """
IDGAF-IpR
Coded by:
-----------
  ___        ____ ___      _ _____ 
 / _ \__  __/ ___/ _ \  __| |___ / 
| | | \ \/ / |  | | | |/ _` | |_ \ 
| |_| |>  <| |__| |_| | (_| |___) |
 \___//_/\_\\\\____\___/ \__,_|____/ 
                                   
   
---------- """

print(BANNER)
#------------------ CONSTANT Variables ----------
ip_database = 'abusedb'

#----------------- Env Setup ------------------------
# Set age or default to 90 days
if args.lastSeen:
    age = args.lastSeen
else:
    age = 90

# ip_database = 'abusedb'

if args.db:
    pass
    ip_database = args.db
    # print ("DB override")
    #------------ TODO -----------------
    # 1. Nothing for now
    # 2. Once new modules out populate config here


# ----------------------- Operation for Single IP search --------------------------------------------
if args.ip:
    if ip_database == 'abusedb' or ip_database == 'all':
        db_obj = AbuseIpDb()
        suspect_ip = args.ip
        
        try:
            suspect_ip_result = db_obj.checkIP(suspect_ip,age)
            if suspect_ip_result:
                print('Suspect IP Lookup: '+suspect_ip_result['data']['ipAddress'])
                print('DB Used: '+ip_database)
                print('Confidence Score: '+ str(suspect_ip_result['data']['abuseConfidenceScore']))
                print('Usage: '+ str(suspect_ip_result['data']['usageType']))

        except:
            print("No result found")


# --------------------------------  ******************  ----------------------------------------------

# ------------------------ Operations for File based inputs ------------------------------------------
elif args.file:
    #------ TODO -------
    # 1. Add input file validation/sanitisation

    try:                    # Try to get Input File
        in_file = open (args.file,'r')
        ip_list = in_file.read().split()
        #print (ip_list)
    except Exception:
        print (Exception)
        exit()

    # -- Check for Output directory, if not exist it creates --
    if os.path.exists('Outputs') == 0:
        os.makedirs('Outputs') 
    
    # Once gets input file check for DB and execute
    if ip_database == 'abusedb' or ip_database == 'all':
        # -- Open a write mode file --
        rep_abusedb_out_file = open('Outputs/abusedb_'+ datetime.now().strftime("%d-%b-%Y_%H-%M-%S")+'.csv','w')
        rep_abusedb_out_file.write('Suspect IP,Database used,Abuse Confidence Score,Domain,Country Code,Usage Type,ISP,Hostnames\n')
    
        db_obj = AbuseIpDb()
        # multiprocess 
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(db_obj.checkIP,ip_list)

            #Check for abuseConfidence:

            # ---------- TODO -------
            # 1. Add exception handling while writing output
            # 2. Add API Key Rotation [Not sure if this actually required, but its a good way to kill time writing this module]
            # 2.a Check for Auth error
            # 2.b If auth error hit: rotate key and continue process
            # 3. Get an actual life {FML}

            for rep in results:
                if int(rep['data']['abuseConfidenceScore']) == 0:
                    pass
                else:
                    rep_abusedb_out_file.write(rep['data']['ipAddress']+','+\
                        ip_database+','+\
                        str(rep['data']['abuseConfidenceScore'])+','+\
                        str(rep['data']['domain'])+','+\
                        str(rep['data']['countryCode'])+','+\
                        str(rep['data']['usageType'])+','+\
                        str(rep['data']['isp'])+','+\
                        str(rep['data']['hostnames'])+'\n')
                        
        
        print("Abuse IP DB Check Done. Output saved")

