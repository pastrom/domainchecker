"""
Info?
"""

from datetime import datetime
import pytz
from tld import get_fld
from requests import get
import socket 

def getDomain(host):
    if(host.startswith('http://') or host.startswith('https://')):
        return get_fld(host)
    else:
        hst = 'http://'+host
        return get_fld(hst)

def prepare_datetime(epoch_time):
    # SSL Labs returns an 13-digit epoch time that contains milliseconds. utcfromtimestamp expects 10 digits.
    return datetime.utcfromtimestamp(float(str(epoch_time)[:10])).strftime("%Y-%m-%d")

def printLocalTime(current_location):
    return datetime.now(tz=pytz.timezone(current_location)).replace(microsecond=0).isoformat()

def getHostInfo(): 

    host = {}

    try: 
        host["analysis_host_hostname"] = socket.gethostname() 
        host["analysis_host_local_ip"] = socket.gethostbyname(host["analysis_host_hostname"])
    except Exception as e: 
        host["analysis_host_hostname"] = "could not obtain hostname"
        host["analysis_host_local_ip"] = "could not obtain local ip"
        print("Unable to get Hostname and local IP.") 
        print(format(e))

    # Separate execution of fetching public ip since this is the most likely to fail.
    try: 
        host["analysis_host_public_ip"] = format(get('https://api.ipify.org').text)
    except Exception as e: 
        host["analysis_host_public_ip"] = "could not obtain public ip"
        print("Unable to get public IP using ipify.org (service or API might have changed).") 
        print(format(e))

    return host