"""
Info?
"""

from datetime import datetime
import pytz
from tld import get_fld

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