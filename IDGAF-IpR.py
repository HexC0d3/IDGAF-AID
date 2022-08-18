import textwrap
from src.abuseIPDB import AbuseIpDb
import argparse
import sys

##### ToDO
# Arg parsing:
#   Args - IP | File | lastSeen | 


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
# parser.set_defaults(Database='abusedb')
group_parser = parser.add_mutually_exclusive_group(required=True)                   # To Force Either IP or Input File
group_parser.add_argument('-ip',help='Single IP to check')
group_parser.add_argument('-f','-file',choices=['file_name'], help='Text file containing IPs separated by linefeed')
parser.add_argument('-age','--lastSeen',help='Check IP reputation not older than <age> days | Default: 90 Days | Applicable to some databases only')

args = parser.parse_args()

#------------------- ****** ---------------------#


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


if args.ip:
    db_obj = AbuseIpDb()
    suspect_ip = args.ip
    
    try:
        suspect_ip_result = db_obj.checkIP(suspect_ip,age)
        if suspect_ip_result:
            print('Suspect IP Lookup: '+suspect_ip_result['data']['ipAddress'])
            print('DB Used: '+ip_database)
            print('Confidence Score: '+suspect_ip_result['data']['abuseConfidenceScore'])
            print('Usage: '+suspect_ip_result['data']['usageType'])

       

    except Exception:
        print("No result found")

elif args.f:
    print(args.f)



# print(ip_database)



