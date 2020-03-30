"""
App main
"""

import sys
import traceback
from datetime import datetime

from domainchecker.elasticsearch_client import ElasticSearchClient
from domainchecker.lookup_client import LookupClient
from domainchecker.ssllabs_client import SSLLabsClient
from domainchecker.domain_checker_utils import getHostInfo

##################################
## General settings ##############
##################################

# Location, TZ DB (used in analysis timestamp)
CURRENT_LOCATION = 'Europe/Oslo'  

##################################
## Output settings ###############
##################################

# ElasticSearch settings
ES_IP_ADDRESS = "localhost"
ES_PORT = "9200"
ES_INDEX_PREFIX = "domainchecker"

##################################
## Endpoint lookup settings ######
##################################

# URL Lookup settings
URL_TIMEOUT = 10

# Port lookup settings
PORTS = [80,443,20]

##################################
######## SSL Labs settings #######
##################################

# Enable SSLLabs scan? (True/False)
SSL_SCAN_ENABLED = True

# SSL Labs API settings
SSL_CHECK_PROGRESS_INTERVAL_SECS = 30
API_URL = "https://api.ssllabs.com/api/v2/analyze"
RESULT_PUBLISH = "off"
START_NEW_SCAN = "off"
SCAN_ALL = "done"
IGNORE_MISMATCH = "on"

# Enable storage of SSLLabs JSON results to disk
# STORE_JSON_REPORTS_TO_FILE = False        <---------------- to be implemented

# Enable storage of raw scan results to ElasticSearch? (True/False)
STORE_RAW_TO_ES = True
STORE_RAW_TO_ES_INDEX_PREFIX = "raw"

# Enable storage of certificate results to ElasticSearch? (True/False)
STORE_CERT_TO_ES = True
STORE_CERT_TO_ES_INDEX_PREFIX = "cert"

class DomainChecker():
    
    def __init__(self):
        #Create ElaticSearch-client instance with details set above
        self.elasticClientInstance = ElasticSearchClient(ES_IP_ADDRESS, ES_PORT, ES_INDEX_PREFIX)
        self.lookupClientInstance = LookupClient(CURRENT_LOCATION)
        self.sslClientInstance = SSLLabsClient(CURRENT_LOCATION, API_URL, SSL_CHECK_PROGRESS_INTERVAL_SECS, RESULT_PUBLISH, START_NEW_SCAN, SCAN_ALL, IGNORE_MISMATCH)
        
        print('All clients initiated successfully!')
    
    def process(self, server_list_file):
        
        ret = 0
        # read from input file
        with open(server_list_file) as f:
            content = f.readlines()
        servers = [x.strip() for x in content]

        for server in servers:
            
            # Performing endpoint lookup
            try:
                
                lookupResult = self.lookupClientInstance.analyze(server, URL_TIMEOUT, CURRENT_LOCATION, PORTS)
                lookupResult.update(getHostInfo())
                indexDate = datetime.now()
                index = "lookup-" + indexDate.strftime("%Y-%m-%d")
        
                self.elasticClientInstance.index_to_es(index, lookupResult)

            except Exception as e:
                traceback.print_stack()
                ret = 1
            
            # Performing SLL Labs analysis if enabled 
            if SSL_SCAN_ENABLED:
                if "finalurl" in lookupResult:
                    if lookupResult["status_code"] == 200:
                        
                        try:
                            print("Performing SSL scan: {} ...".format(server))
                            
                            sslResult = self.sslClientInstance.start_new_scan(server)
                            
                            if sslResult["status"]  == "READY":
                                
                                # Processes and stores SSL scan results
                                sslPrepped = self.sslClientInstance.prepare_ssl_for_es(server, sslResult)
                                sslIndex = "ssl-"+sslPrepped["domain"].replace(".","-")
                                self.elasticClientInstance.index_to_es(sslIndex, sslPrepped)
                                
                                # Stores raw reports in separate ElasticSearch-index if enabled in settings
                                if STORE_RAW_TO_ES:
                                    now = datetime.now()
                                    rawIndex = "ssl-"+STORE_RAW_TO_ES_INDEX_PREFIX + "-" + now.strftime("%Y-%m-%d")
                                    self.elasticClientInstance.index_to_es(rawIndex, sslResult)
                                
                                # Stores certificate info in separate ElasticSearch-index if enabled in settings
                                if STORE_CERT_TO_ES:
                                    certPrepped = self.sslClientInstance.prepare_cert_for_es(server, sslResult)
                                    certIndex = STORE_CERT_TO_ES_INDEX_PREFIX + "-" + sslPrepped["domain"].replace(".","-")
                                    self.elasticClientInstance.index_to_es(certIndex, certPrepped)
                                
                            else:
                            
                                summary = {}
                                summary["analysisTime"] = self.printLocalTime()
                                summary["host"] = server
                                summary["domain"] = self.getDomain(server)
                                if "status" in data: summary["analysisStatus"] = data["status"]
                                if "statusMessage" in data: summary["statusMessage"] = data["statusMessage"]
                                index = "ssl-"+sslPrepped["domain"].replace(".","-")
                                self.elasticClientInstance.index_to_es(index, summary)

                        except Exception as e:
                            traceback.print_stack()
                            ret = 1
            
        return ret
    
    @staticmethod
    def endpointLookup(self, server):
        result = self.lookupClientInstance.analyze(server, URL_TIMEOUT, CURRENT_LOCATION, PORTS)
                
        indexDate = datetime.now()
        index = "lookup-" + indexDate.strftime("%Y-%m-%d")
        
        self.elasticClientInstance.index_to_es(index, result)
    
    @staticmethod
    def sslChecker(self, server):
        result = self.sslClientInstance.analyze(server, URL_TIMEOUT, CURRENT_LOCATION, PORTS)
                
        indexDate = datetime.now()
        index = "ssl-" + indexDate.strftime("%Y-%m-%d")
        
        self.elasticClientInstance.index_to_es(index, result)

def main():

    domainCheckerInstance = DomainChecker()
    
    if len(sys.argv) != 2:
        print("{} [SERVER_LIST_FILE]".format(sys.argv[0]))
        return 1
    return domainCheckerInstance.process(server_list_file=sys.argv[1])

if __name__ == "__main__":
    sys.exit(main())
