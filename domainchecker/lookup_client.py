"""
INFO?
"""

import requests
import socket
from urllib.parse import urlparse

from domainchecker.domain_checker_utils import printLocalTime
from domainchecker.domain_checker_utils import getDomain

class LookupClient():

    def __init__(self, current_location):
        
        print("Lookup-client initiated.")
        self.__current_location = current_location

    def analyze(self, host, url_timeout, current_location, ports):
        
        print("Performing endpoint lookup: {} ...".format(host))
        
        # Check URL before initiating SSL Labs scan
        endpointCheck = {}
        endpointCheck["lookupTime"] = printLocalTime(self.__current_location)
        endpointCheck.update(self.checkRedirect(host, url_timeout))
        endpointCheck.update(self.nsLookup(host))
        endpointCheck.update(self.portLookup(host, ports))        
       
        #if "finalurl" in endpointCheck:
        #    print('Host lookup - http://' + host + ' redirects to ' + endpointCheck["finalurl"])
        #else:
        #    print('Host lookup - http://' + host + ' failed...')

        return endpointCheck


    # Check URL before initiating SSL Labs analysis
    def checkRedirect(self, url, url_timeout):
        
        result = {}
        result["domain"] = getDomain(url)
        result["request_url"] = 'http://' + url
        
        # Performing URL lookup
        try:
            
            response = requests.get(result["request_url"], timeout=url_timeout)
            result["status_code"] = response.status_code

            # Consider any status other than 2xx an error
            if not response.status_code // 100 == 2:
                result["url_error_msg"] = format(response)
                
            else:
                urlStruct = urlparse(response.url)
                result["finalurl"] = urlStruct.scheme+'://'+urlStruct.netloc

        except requests.exceptions.RequestException as e:
            # A serious problem happened, like an SSLError or InvalidURL
            result["status_code"] = "000"
            result["url_error_msg"] = format(e)
                    
        return result

    # Performing NS lookup
    def nsLookup(self, url):
        
        result = {}
        
        #lookupSocket = socket.socket()                 <------------------- FIX! What is going on?
        #lookupSocket.settimeout(5)   # 5 seconds
        
        try:
            result["ns_lookup_ip"] = socket.gethostbyname(url)

        except socket.error as e:
            
            result["ns_lookup_ip"] = "x.x.x.x"
            result["ns_error_msg"] = format(e)

        return result
    
    # Performing lookup of open ports defined in settings of main
    def portLookup(self, url, portsToCheck):
        
        checkedPorts = {}

        for p in portsToCheck:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((url,p))
                
                if result == 0:
                    checkedPorts['port_'+str(p)] = "open"
                else:
                    checkedPorts['port_'+str(p)] = "closed"
                
                sock.close()
                
            except socket.error as e:
                format(e)
            
        return checkedPorts