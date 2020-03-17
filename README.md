# Domain checker framework

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](http://en.wikipedia.org/wiki/MIT_License)

Support Python >= 3.6

Framework for automating collection of domain information and status. Outputs results to ElasticSearch.

This project is built on another [SSL Labs Scanner project created by kyhau](https://github.com/kyhau/ssllabs-scan)

Modules and clients implemented:

1. Endpoint lookup 
- Checks if domain resolves to IP (nslookup)
- Checks if common ports are open (default: 80, 443, 20)
- Checks redirects of http requests on default http/https ports.

2. SSL configuration (based on the free [Qualys SSL Labs API](https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md))
- Stores raw results from SSL Labs to ElasticSearch (in JSON structure)
- Stores a selection of highlights from the SSL Labs results in separate ElasticSearch index
- Stores information regarding certificates used for SSL in separate

## Input and Output

Input: [domainchecker/domains.txt](domainchecker/domains.txt). One domain per line.

Output: ElasticSearch node and indexes are configurable in the settings of main class.

## Build and Run

### Linux
```
virtualenv domaincheckerenv
source domaincheckerenv/bin/activate
pip install -e .
domainchecker domains.txt
```

