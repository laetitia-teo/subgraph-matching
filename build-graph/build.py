# Reading the CERT data and generating a graph of the recorded activity
#
#
#
#

import numpy as np
import pandas as pd
import re
from tqdm import tqdm

class CERTVertex():
    '''
    A vertex of the CERT dataset graph.
    '''
    
    def __init__(self, name, vertex_type):
        self.name = name
        self.vertex_type = vertex_type
    
    def __repr__(self):
        return "CERTVertex {}, type={}".format(self.name, self.vertex_type)

class CERTEdge():
    '''
    An edge of the CERT dataset graph.
    '''
    
    def __init__(self, name, timestamp, tail, head, edge_type):
        self.name = name
        self.timestamp = timestamp
        self.tail = tail
        self.head = head
        self.edge_type = edge_type
    
    def __repr__(self):
        return "CERTEdge {}, timestamp={}, tail={}, head={}, type={}".format(
            self.name, 
            self.timestamp,
            self.tail,
            self.head,
            self.edge_type)

class CERTGraph():
    '''
    A graph representation of the CERT Insider threat dataset.
    '''
    def __init__(self):
        self.vertices = []
        self.edges = []
        self.n = 0 # Number of edges for generating edge name
        self.email_dict = {} 
        # A dictionnary for storing the email content : since we lack an email 
        # identifier in the log data, we assume two emails to be the same if the
        # email content matches.
    
    def get_vertex(self, name):
        for v in self.vertices:
            if v.name == name:
                return v
    
    def add_vertex(self, vertex_name, vertex_type):
        # Check if vertex already exists
        for v in self.vertices:
            if v.name == vertex_name:
                return
        vertex = CERTVertex(vertex_name, vertex_type)
        self.vertices.append(vertex)
    
    def add_edge(self, name, timestamp, tail, head, edge_type):
        # We assume each edge creation is unique, to save time at edge creation
        edge = CERTEdge(name, timestamp, tail, head, edge_type)
        self.edges.append(edge)
        self.n += 1
    
    def _generate_email_name(self, typ, row):
        if typ == 'email':
            # search in the email dict for matching email content
            for name, content in self.email_dict.items():
                if row['email_content'] == content:
                    return name
            # not found : create new email
            name = 'email' + str(len(self.email_dict))
            self.email_dict[name] = row['email_content']
            return name
        else:
            raise TypeError('type must be email')
    
    def _generate_edge_name(self, typ):
        name = typ + str(self.n)
        return name
    
    def _isnull(self, val):
        # isnan extended to strings
        if type(val) == type('foo'):
            return not bool(val)
        elif np.isnan(val):
            return True
    
    def _parse_row(self, row):
        if not self._isnull(row['email_activity']): # TODO : add email action 'Attach'
            # tail vertex
            tail_vertex_name = row['host']
            tail_vertex_type = 'pc'
            # head vertex
            head_vertex_name = self._generate_email_name('email', row)
            head_vertex_type = 'email'
            # edge
            edge_type = row['email_activity']
            edge_time = row['date']
            edge_tail = tail_vertex_name
            edge_head = head_vertex_name
            edge_name = self._generate_edge_name(row['email_activity'])
            # Since email : 'Attach' does not exist we create it
            if not self._isnull(row['email_attachments']) and row['email_activity'] == 'Send':
                self._create_attach(row, head_vertex_name)
        elif not self._isnull(row['file_activity']):
            # tail vertex
            tail_vertex_name = row['host']
            tail_vertex_type = 'pc'
            # head vertex
            head_vertex_name = row['file_filename']
            head_vertex_type = 'file'
            # edge
            edge_type = row['file_activity']
            edge_time = row['date']
            edge_tail = tail_vertex_name
            edge_head = head_vertex_name
            edge_name = self._generate_edge_name(row['file_activity'])
        elif not self._isnull(row['device_activity']):
            # tail vertex
            tail_vertex_name = row['user']
            tail_vertex_type = 'employee'
            # head vertex
            head_vertex_name = row['host']
            head_vertex_type = 'pc'
            # edge
            edge_type = row['device_activity']
            edge_time = row['date']
            edge_tail = tail_vertex_name
            edge_head = head_vertex_name
            edge_name = self._generate_edge_name(row['device_activity'])
        elif not self._isnull(row['http_activity']):
            # tail vertex
            tail_vertex_name = row['host']
            tail_vertex_type = 'pc'
            # head vertex
            head_vertex_name = row['http_url']
            head_vertex_type = 'http'
            # edge
            edge_type = row['http_activity']
            edge_time = row['date']
            edge_tail = tail_vertex_name
            edge_head = head_vertex_name
            edge_name = self._generate_edge_name(row['http_activity'])
        elif not self._isnull(row['logon_activity']):
            # tail vertex
            tail_vertex_name = row['user']
            tail_vertex_type = 'employee'
            # head vertex
            head_vertex_name = row['host']
            head_vertex_type = 'pc'
            # edge
            edge_type = row['logon_activity']
            edge_time = row['date']
            edge_tail = tail_vertex_name
            edge_head = head_vertex_name
            edge_name = self._generate_edge_name(row['logon_activity'])
        else:
            return
        edge_name = str(self.n + 1)
        self.add_vertex(tail_vertex_name, tail_vertex_type)
        self.add_vertex(head_vertex_name, tail_vertex_type)
        self.add_edge(edge_name, edge_time, edge_tail, edge_head, edge_type)
    
    def _create_attach(self, row, email_name):
        files = re.findall('C:\\\\.*\....', row['email_attachments'])
        for f in files:
            # tail vertex
            tail_vertex_name = f
            tail_vertex_type = 'file'
            # head vertex
            head_vertex_name = email_name
            head_vertex_type = 'email'
            # edge
            edge_type = 'Attach'
            edge_time = row['date']
            edge_tail = tail_vertex_name
            edge_head = head_vertex_name
            edge_name = self._generate_edge_name('Attach')
            self.n += 1 # maybe define this in generate_edge_name ?
            self.add_vertex(tail_vertex_name, tail_vertex_type)
            self.add_vertex(head_vertex_name, tail_vertex_type)
            self.add_edge(edge_name, edge_time, edge_tail, edge_head, edge_type)
    
    def read_data(self, data_path):
        df = pd.read_csv(data_path)
        print('reading data ...')
        for idx, row in tqdm(df.iterrows()):
            self._parse_row(row)











































