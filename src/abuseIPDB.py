import requests
import configparser
import sys
# Read Config file from current location to set API keys

class AbuseIpDb:

    def __init__(self):
        pass

    def getAuthToken(self):
        # CONFIG_PATH = config
        # CONFIG_PATH = '../configfile.ini'
        config_obj = configparser.ConfigParser()
        config_obj.read('./config.ini')
        AIPDB_KEY = config_obj["abusedb"]
        # print (AIPDB_KEY["API_KEY"])

        try:
            default_api_key = AIPDB_KEY["API_KEY"]
            return default_api_key

        except:
            print ("Error at parsing ConfigFile.ini")
            print ("Default key not set. Check your config file")
            exit()

        


#--------------------------------------------
#
#   ___        ____ ___      _ _____ 
#  / _ \__  __/ ___/ _ \  __| |___ / 
# | | | \ \/ / |  | | | |/ _` | |_ \ 
# | |_| |>  <| |__| |_| | (_| |___) |
#  \___//_/\_\\____\___/ \__,_|____/ 
#
#--------------------------------------------


    # Request API for AbuseIPDB [Check Endpoint]

    def checkIP(self,IP,lastSeen=90):
        # global default_api_key
        default_api_key = self.getAuthToken() 
        payload = {'ipAddress':IP,'maxAgeInDays':lastSeen}
        custom_headers = {"Key":default_api_key,"Accept": 'application/json'}
        endpoint_url = "https://api.abuseipdb.com/api/v2/check"                 # API Endpoint
        # print("In Check IP "+str(custom_headers))

        try:
            ip_check = requests.get(endpoint_url,params=payload,headers=custom_headers)

        except Exception:
            print (Exception + ' for IP: '+ IP)
            exit()
        
        finally:
            return ip_check.json()


# Direct Script Calls

# abuse_ipdb = AbuseIpDb()
# abuse_ipdb.getAuthToken()
# print(abuse_ipdb.checkIP(sys.argv[1]))

