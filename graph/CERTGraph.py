# Reading the CERT data and generating a graph of the recorded activity
#
#
#
#

import numpy as np
import pandas as pd
import re
from copy import copy
from tqdm import tqdm

class Vertex():
    '''
    A vertex of the CERT dataset graph.
    '''
    
    def __init__(self, name, vertex_type=None):
        # consider adding an index to speed up the search in to_vertices
        self.name = name
        self.vertex_type = vertex_type
    
    def __repr__(self):
        return "Vertex {}, type={}".format(self.name, self.vertex_type)
    
    def elements_as_str(self):
        return self.name + ',' + self.vertex_type

class Edge():
    '''
    An edge of the CERT dataset graph.
    '''
    
    def __init__(self, name, timestamp, tail, head, edge_type=None):
        self.name = name
        self.timestamp = int(timestamp)
        self.tail = tail
        self.head = head
        self.edge_type = edge_type
    
    def __repr__(self):
        return "Edge {}, timestamp={}, tail=({}), head=({}), type={}".format(
            self.name, 
            self.timestamp,
            self.tail,
            self.head,
            self.edge_type)
    
    def elements_as_str(self):
        s = ''
        s += self.name + ','
        s += str(self.timestamp) + ','
        s += self.tail + ','
        s += self.head + ','
        s += self.edge_type
        return s

class Graph():
    '''
    A graph representation of the CERT Insider threat dataset.
    '''
    def __init__(self, g_file=None, data=None):
        self.vertices = []
        self.edges = []
        self.n = 0 # Number of edges for generating edge name
        self._email_dict = {} 
        # A dictionnary for storing the email content : since we lack an email 
        # identifier in the log data, we assume two emails to be the same if the
        # email content matches.
        if g_file:
            self.read_graph_file(g_file)
        if data:
            self.vertices = data[0]
            self.edges = data[1]
            self.n = len(self.edges)
        self.eGtrace = []
        self.eMtrace = []
        self.estacktrace = []
        self.sort_edges()
    
    def __repr__(self):
        return "Graph: %s vertices, %s edges" % (len(self.vertices), len(self.edges))
    
    def get_vertex(self, name):
        for v in self.vertices:
            if v.name == name:
                return v
    
    def get_edge(self, name):
        for e in self.edges:
            if e.name == name:
                return e
    
    def get_vertex_index(self, name):
        for i, v in enumerate(self.vertices):
            if v.name == name:
                return i
    
    def add_vertex(self, vertex_name, vertex_type):
        # Check if vertex already exists
        for v in self.vertices:
            if v.name == vertex_name:
                return
        vertex = Vertex(vertex_name, vertex_type)
        self.vertices.append(vertex)
    
    def add_edge(self, name, timestamp, tail, head, edge_type):
        # We assume each edge creation is unique, to save time at edge creation
        edge = Edge(name, timestamp, tail, head, edge_type)
        self.edges.append(edge)
        self.n += 1
    
    def sort_edges(self):
        """
        Sorts edges by timestamp.
        """
        try:
            import operator
            keyfun = operator.attrgetter("timestamp")
        except:
            keyfun = lambda e: e.timestamp
            
        self.edges.sort(key=keyfun)
    
    def _generate_email_name(self, typ, row):
        if typ == 'email':
            # search in the email dict for matching email content
            for name, content in self._email_dict.items():
                if row['email_content'] == content:
                    return name
            # not found : create new email
            name = 'email' + str(len(self._email_dict))
            self._email_dict[name] = row['email_content']
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
        self.add_vertex(head_vertex_name, head_vertex_type)
        self.add_edge(edge_name, edge_time, edge_tail, edge_head, edge_type)
    
    def _create_attach(self, row, email_name):
        files = row['email_attachments'].split(sep=';')
        for f in files:
            # tail vertex
            f = f.replace(re.findall('\(.*\)', f)[0], '') # get rid of the parenthesis
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
        print('sorting edges ...')
        self.sort_edges
        print('done')
    
    def temporal_match(self, M, delta):
        # Initialize necessary variables :
        edgecount = [0] * len(self.vertices)
        mapGM = [-1] * len(self.vertices)
        mapMG = [-1] * len(M.vertices)
        results = []
        estack = []
        eG = 0
        eM = 0
        t = float('inf')
        i = 0
        # Loop until all matching subgraphs are found
        while True:
            i += 1
            eG = self.find_next_match(M, eM, eG, mapMG, mapGM, t)
            print("eM : %s" % eM)
            print("eG : %s" % eG)
            if eG < len(self.edges):
                # Test if all edges in M are matched
                if eM == len(M.edges)-1:
                    print('YAYAYAYYYAY!!111!1!')
                    estack.append(eG) # ! Not in algo
                    elist = [self.edges[e] for e in estack]
                    vlist = [self.vertices[v] for v in self.to_vertex_list(elist)]
                    H = Graph(data=(vlist, elist))
                    results.append(H)
                    print(H)
                    estack.pop() # ! Not in algo
                    #print('results %s' % results)
                else:
                    uG, vG = self.to_vertices(eG) # TODO check 
                    uM, vM = M.to_vertices(eM) 
                    mapGM[uG] = uM
                    mapGM[vG] = vM
                    mapMG[uM] = uG
                    mapMG[vM] = vG
                    edgecount[uG] += 1
                    #print("vg : %s" % vG)
                    edgecount[vG] += 1
                    if not estack:
                        t = self.edges[eG].timestamp + delta
                    estack.append(eG)
                    eM += 1
            eG += 1
            # Backup or quit if we run out of egdes
            while eG >= len(self.edges) or self.edges[eG].timestamp >= t:
                if estack:
                    eG = estack.pop() + 1
                    #uG, vG = self.to_vertices(eG)
                    #self.estacktrace.append(-eG+1)
                    if not estack:
                        t = float('inf')
                    edgecount[uG] -= 1
                    edgecount[vG] -= 1
                    # Unassign nodes if needed
                    if edgecount[uG] == 0:
                        uM = mapGM[uG]
                        mapMG[uM] = -1
                        mapGM[uG] = -1
                    if edgecount[vG] == 0:
                        vM = mapGM[vG]
                        mapMG[vM] = -1
                        mapGM[vG] = -1
                    eM -= 1
                else:
                    return results
    
    def find_next_match(self, M, eM, eG, mapMG, mapGM, t):
        '''
        Subroutine for finding the next matching temporal that matches edge eM
        in our motif M.
        '''
        print("find next match")
        uM, vM = M.to_vertices(eM)
        uG = mapMG[uM]
        vG = mapMG[vM]
        #print('uG : %s' %uG)
        #print('vG : %s' %vG)
        # Determine the potential edges to try :
        S = range(len(self.edges))
        if uG >= 0 and vG >= 0:
            S = [e for e, edge in enumerate(self.edges) if e >= eG 
                                                        and edge.timestamp <= t
                                                        and edge.tail == self.vertices[uG].name 
                                                        and edge.head == self.vertices[vG].name]
        elif uG >= 0:
            S = [e for e, edge in enumerate(self.edges) if e >= eG 
                                                        and edge.timestamp <= t
                                                        and edge.tail == self.vertices[uG].name] 
        elif vG >= 0:
            S = [e for e, edge in enumerate(self.edges) if e >= eG 
                                                        and edge.timestamp <= t
                                                        and edge.head == self.vertices[vG].name]
        # Try each edge until a match is made :
        for e in S:
            u1G, v1G = self.to_vertices(e)
            # The mappings must match, or be unassigned :
            if uG == u1G or (uG < 0 and mapGM[u1G] < 0):
                if vG == v1G or (vG < 0 and mapGM[v1G] < 0):
                    #if (self.vertices[uG] ): #TODO
                    print("matched : %s " % e)
                    return e
        print("matched : %s " % len(self.edges))
        return len(self.edges)
    
    def to_vertices(self, e): #TODO : optimize this !
        edge = self.edges[e]
        #print(edge)
        u, v = self.get_vertex_index(edge.tail), self.get_vertex_index(edge.head)
        #print(u)
        #print(v)
        return u, v
    
    def to_vertices_obj(self, edge): #TODO : optimize this !
        u, v = self.get_vertex_index(edge.tail), self.get_vertex_index(edge.head)
        return u, v
    
    def to_vertex_list(self, elist):
        vlist = []
        for edge in elist:
            t, h = self.to_vertices_obj(edge)
            if t not in vlist:
                vlist.append(t)
            if h not in vlist:
                vlist.append(h)
        return vlist
    
    def save(self, path):
        """
        Function for saving the graph data to a file after it has been built.
        
        Args :
        path (str) : a valid path to save the graph.
        """
        with open(path, 'w') as f:
            f.write("Graph %s, %s\n" % (len(self.vertices), len(self.edges)))
            f.write("vertices\n")
            for v in self.vertices:
                f.write(v.elements_as_str())
                f.write("\n")
            f.write("edges\n")
            for e in self.edges:
                f.write(e.elements_as_str())
                f.write("\n")
    
    def read_graph_file(self, path):
        """
        Reads a graph directly from file.
        Fills the lists of vertices and edges from the file.
        
        Args:
        path (str) : a valid path to a graph file
        """
        mode = ''
        with open(path, 'r') as f:
            for line in f:
                if line == 'vertices\n':
                    mode = 'v'
                elif line == 'edges\n':
                    mode = 'e'
                elif mode == 'v':
                    self.vertices.append(Vertex(*line.replace('\n', '').split(',')))
                elif mode == 'e':
                    self.edges.append(Edge(*line.replace('\n', '').split(',')))
    
    











































