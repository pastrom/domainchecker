"""
INFO?
"""

import json
from elasticsearch import Elasticsearch

class ElasticSearchClient():
    def __init__(self, es_address, es_port, es_index_prefix):
        self.__es_address = es_address
        self.__es_port = es_port
        self.__es_index_prefix = es_index_prefix
        print('ElasticSearch-client initiated. Outputs to node \'' + self.__es_address + ':' + self.__es_port + '\' with index prefix \'' + self.__es_index_prefix +'\'')

    def index_to_es(self, index, data):
        dataOut = json.dumps(data)
        try:
            es = Elasticsearch([{'host': self.__es_address, 'port': self.__es_port}])
            res = es.index(index=self.__es_index_prefix + "-" + index, doc_type='_doc', body=dataOut)
        except Exception as e:
            print('Output - Error indexing to ElasticSearch... Is ES-client configured correctly and ES-node running? (printing error below)')
            print(str(e))
            

