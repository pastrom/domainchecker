"""
INFO?
"""

import json
import requests
from requests.exceptions import HTTPError
import datetime
import hashlib
import hmac
import base64
import argparse
import string
from tqdm import tqdm
from time import sleep
import os
import glob
import sys
#import logging

# import json
# from elasticsearch import Elasticsearch

class LogAnalyticsClient():
    def __init__(self, WORKSPACE_ID, WORKSPACE_SHARED_KEY):
        self.__la_ws_id = WORKSPACE_ID
        self.__la_ws_key = WORKSPACE_SHARED_KEY
#        self.__la_log = LOG_TYPE
        print('Azure Log Analytics client initiated. Outputs to workspace ID \'' + self.__la_ws_id + '\'')
           
    # Build the API signature
    def build_signature(self, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8") 
        decoded_key = base64.b64decode(self.__la_ws_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = f"SharedKey {self.__la_ws_id}:{encoded_hash}"
        return authorization

    # Build and send a request to the POST API
    def post_data(self, logTable, bodyInput):

        body = str(json.dumps(bodyInput))

        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self.build_signature(rfc1123date, content_length, method, content_type, resource)
        uri = 'https://' + self.__la_ws_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': logTable,
            'x-ms-date': rfc1123date
        }
        
        try:
            response = requests.post(uri,data=body, headers=headers)
            response.raise_for_status()
        except HTTPError as http_err:
            print(f'Response code: {response.status_code}')
            print(f'HTTP error occurred: {http_err}')
        except Exception as err:
            print(f'Response code: {response.status_code}')
            print(f'Other error occurred: {err}')
        else:
            return True