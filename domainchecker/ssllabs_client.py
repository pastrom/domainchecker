"""
See APi doc: https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md
"""

import time
import json
import os
import requests

from domainchecker.domain_checker_utils import printLocalTime
from domainchecker.domain_checker_utils import getDomain
from domainchecker.domain_checker_utils import prepare_datetime

CHAIN_ISSUES = {
    "0": "none",
    "1": "unused",
    "2": "incomplete chain",
    "3": "chain contains unrelated or duplicate certificates",
    "4": "the certificates form a chain (trusted or not) but incorrect order",
    "16": "contains a self-signed root certificate",
    "32": "the certificates form a chain but cannot be validated",
}

# Forward secrecy protects past sessions against future compromises of secret keys or passwords.
FORWARD_SECRECY = {
    "1": "With some browsers WEAK",
    "2": "With modern browsers",
    "4": "Yes (with most browsers) ROBUST",
}

PROTOCOLS = [
    "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0 INSECURE", "SSL 2.0 INSECURE"
]

VULNERABLES = [
    "Vuln Beast", "Vuln Drown", "Vuln Heartbleed", "Vuln FREAK",
    "Vuln openSsl Ccs", "Vuln openSSL LuckyMinus20", "Vuln POODLE", "Vuln POODLE TLS"
]

SUMMARY_COL_NAMES = [
    "Host", "Grade", "HasWarnings", "Cert Expiry", "Chain Status", "Forward Secrecy", "Heartbeat ext"
] + VULNERABLES + PROTOCOLS


class SSLLabsClient():
    def __init__(self, current_location, host_api, check_progress_interval_secs, result_publish, start_new_scan, scan_all, ignore_mismatch):
        
        self.__host_api = host_api
        self.__check_progress_interval_secs = check_progress_interval_secs
        self.__result_publish = result_publish
        self.__start_new_scan = start_new_scan
        self.__scan_all = scan_all
        self.__ignore_mismatch = ignore_mismatch
        self.__current_location = current_location
        
        print("SSL Labs-client initiated.")

    @staticmethod
    def request_api(url, payload, waitinterval):
        response = requests.get(url, params=payload)
        while response.status_code != 200:
            print('SSL Labs API - Error requesting API! Status code ' + str(response.status_code) + '. Waiting ' + str(waitinterval) + ' sec until next retry...')
            time.sleep(waitinterval)
            response = requests.get(url, params=payload)
        print('SSL Labs API - The request was accepted by the server and is being processed. Status code ' + str(response.status_code) + '. Checking if results are ready in ' + str(waitinterval) + ' sec.')
        return response.json()

    #def saveJsonReport(self, data, host):
    #    json_file = os.path.join(os.path.dirname(summary_csv_file), f"{host}.json")
    #    with open(json_file, "w") as outfile:
    #        json.dump(data, outfile, indent=2)

    def start_new_scan(self, host):
        path = self.__host_api
        payload = {
            "host": host,
            "publish": self.__result_publish,
            "startNew": self.__start_new_scan,
            "all": self.__scan_all,
            "ignoreMismatch": self.__ignore_mismatch
        }
        results = self.request_api(path, payload, self.__check_progress_interval_secs)
        payload.pop("startNew")
        
        while results["status"] != "READY" and results["status"] != "ERROR":
            time.sleep(self.__check_progress_interval_secs)
            results = self.request_api(path, payload, self.__check_progress_interval_secs)
        return results

    def prepare_ssl_for_es(self, host, data, ep):
        
        summary = {}
        summary["analysisTime"] = printLocalTime(self.__current_location)
        summary["host"] = host
        summary["domain"] = getDomain(host)
        if "status" in data: summary["analysisStatus"] = data["status"]
        if "statusMessage" in ep: summary["endpointAnalysisStatus"] = ep["statusMessage"]
        if "ipAddress" in ep: summary["ipAddress"] = ep["ipAddress"]
        if "serverName" in ep: summary["serverName"] = ep["serverName"]
        if "serverSignature" in ep["details"]: summary["serverSignature"] = ep["details"]["serverSignature"]
        if "grade" in ep: summary["grade"] = ep["grade"]
        if "hasWarnings" in ep: summary["hasWarnings"] = ep["hasWarnings"]
        if "cert" in ep["details"]: summary["certNotAfter"] = prepare_datetime(ep["details"]["cert"]["notAfter"])
        if "chain" in ep["details"]: summary["chain_issues"] = CHAIN_ISSUES[str(ep["details"]["chain"]["issues"])]
        if "forwardSecrecy" in ep: summary["forward_secrecy"] = FORWARD_SECRECY[str(ep["details"]["forwardSecrecy"])]
        if "heartbeat" in ep["details"]: summary["heartbeat"] = ep["details"]["heartbeat"]
        if "vulnBeast" in ep["details"]: summary["vulnBeast"] = ep["details"]["vulnBeast"]
        if "drownVulnerable" in ep["details"]: summary["drownVulnerable"] = ep["details"]["drownVulnerable"]
        if "heartbleed" in ep["details"]: summary["heartbleed"] = ep["details"]["heartbleed"]
        if "freak" in ep["details"]: summary["freak"] = ep["details"]["freak"]
        if "openSslCcs" in ep["details"]: summary["openSslCcs"] = False if ep["details"]["openSslCcs"] == 1 else True
        if "openSSLLuckyMinus20" in ep["details"]: summary["openSSLLuckyMinus20"] = False if ep["details"]["openSSLLuckyMinus20"] == 1 else True
        if "poodle" in ep["details"]: summary["poodle"] = ep["details"]["poodle"]
        if "poodleTls" in ep["details"]: summary["poodleTls"] = False if ep["details"]["poodleTls"] == 1 else True
        if "hstsPolicy" in ep["details"]:
            if "status" in ep["details"]["hstsPolicy"]:
                summary["hstsPolicy"] = ep["details"]["hstsPolicy"]["status"]
            else:
                summary["hstsPolicy"] = "N/A"
        
        for protocol in PROTOCOLS:
            found = False
            for p in ep["details"]["protocols"]:
                if protocol.startswith(f"{p['name']} {p['version']}"):
                    found = True
                    break
            summary[protocol] = [True if found is True else False]

        suitesStr = ""
        for algo in ep["details"]["suites"]["list"]:
            suitesStr += algo["name"] + " "
        summary["suites"] = suitesStr
        
        return summary

    def prepare_cert_for_es(self, host, data, ep):

        #for ep in data["endpoints"]:
        if "cert" in ep["details"]:

            summary = {}
            summary["analysisTime"] = printLocalTime(self.__current_location)
            summary["host"] = host
            summary["domain"] = getDomain(host)

            if "serverName" in ep: summary["serverName"] = ep["serverName"]
            if "grade" in ep: summary["grade"] = ep["grade"]
            if "hasWarnings" in ep: summary["hasWarnings"] = ep["hasWarnings"]
            if "ipAddress" in ep: summary["ipAddress"] = ep["ipAddress"]
            if "subject" in ep["details"]["cert"]: summary["subject"] = ep["details"]["cert"]["subject"]
            if "notBefore" in ep["details"]["cert"]: summary["notBefore"] = prepare_datetime(ep["details"]["cert"]["notBefore"])
            if "notAfter" in ep["details"]["cert"]: summary["notAfter"] = prepare_datetime(ep["details"]["cert"]["notAfter"])
            if "issuerSubject" in ep["details"]["cert"]: summary["issuerSubject"] = ep["details"]["cert"]["issuerSubject"]
            if "issuerLabel" in ep["details"]["cert"]: summary["issuerLabel"] = ep["details"]["cert"]["issuerLabel"]
            if "sha1Hash" in ep["details"]["cert"]: summary["sha1Hash"] = ep["details"]["cert"]["sha1Hash"]
            if "pinSha256" in ep["details"]["cert"]: summary["pinSha256"] = ep["details"]["cert"]["pinSha256"]
            if "sigAlg" in ep["details"]["cert"]: summary["sigAlg"] = ep["details"]["cert"]["sigAlg"]
            if "commonNames" in ep["details"]["cert"]: summary["commonNames"] = ep["details"]["cert"]["commonNames"]
            if "altNames" in ep["details"]["cert"]: summary["altNames"] = ep["details"]["cert"]["altNames"]
            if "issues" in ep["details"]["chain"]: summary["chain_issues"] = CHAIN_ISSUES[str(ep["details"]["chain"]["issues"])]
            
            return summary