import sys
import CERTGraph as cg
import time
import matplotlib.pyplot as plt
import numpy as np

sys.path.append('..')

data_path = '../data/cert_b_users/insiders/CDE1846-logs.csv'
save_path = '../data/graphs/CDE1846.txt'

# define matching pattern

vlist = []
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 3))
edgelist.append(cg.Edge(3, 3, 3, 1))

M = cg.Graph(data=(vlist, edgelist))

# define graphs

G = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print('=====')
print(len(result))

# ========================

vlist = []
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 3))
edgelist.append(cg.Edge(3, 3, 1, 3))

G = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print('=====')
print(len(result))

# =========================
# TODO : fix
# infinite loop

vlist = []
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))
vlist.append(cg.Vertex(4))

edgelist = []
edgelist.append(cg.Edge(1, 2, 2, 3))
edgelist.append(cg.Edge(2, 1, 2, 1))
edgelist.append(cg.Edge(3, 3, 3, 1))
edgelist.append(cg.Edge(4, 4, 3, 4))
edgelist.append(cg.Edge(5, 5, 4, 2))

G = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print(len(result))
print(result[0].vertices)

# =========================


vlist = []
vlist.append(cg.Vertex(0))
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))

edgelist = []
edgelist.append(cg.Edge(0, 0, 0, 1))
edgelist.append(cg.Edge(1, 1, 0, 2))
edgelist.append(cg.Edge(2, 2, 1, 2))
edgelist.append(cg.Edge(3, 3, 0, 3))


G = cg.Graph(data=(vlist, edgelist))


vlist = []
vlist.append(cg.Vertex(0))
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))

edgelist = []
edgelist.append(cg.Edge(0, 0, 0, 1))
edgelist.append(cg.Edge(1, 1, 0, 2))
edgelist.append(cg.Edge(2, 2, 0, 3))

M = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print(len(result))
print(result[0].vertices)

# ============================


vlist = []
vlist.append(cg.Vertex(0))
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))

edgelist = []
edgelist.append(cg.Edge(0, 0, 0, 1))
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 0))
edgelist.append(cg.Edge(3, 3, 2, 3))
edgelist.append(cg.Edge(4, 4, 3, 1))


G = cg.Graph(data=(vlist, edgelist))


vlist = []
vlist.append(cg.Vertex(0))
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))

edgelist = []
edgelist.append(cg.Edge(0, 0, 0, 1))
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 0))

M = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print(len(result))
print(result)

'''
vlist = []
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))
vlist.append(cg.Vertex(4))

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 3))
edgelist.append(cg.Edge(3, 3, 3, 1))
edgelist.append(cg.Edge(4, 4, 4, 3))
edgelist.append(cg.Edge(5, 5, 4, 2))

G = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print(len(result))
print(result[0].vertices)

# =========================

vlist = []
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))
vlist.append(cg.Vertex(4))

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 3))
edgelist.append(cg.Edge(3, 3, 1, 3))
edgelist.append(cg.Edge(4, 4, 4, 3))
edgelist.append(cg.Edge(5, 5, 4, 2))

G = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print(len(result))

# =========================

vlist = []
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 3))
edgelist.append(cg.Edge(3, 3, 3, 1))
edgelist.append(cg.Edge(4, 4, 3, 1))
edgelist.append(cg.Edge(5, 5, 3, 1))
edgelist.append(cg.Edge(6, 6, 3, 1))
edgelist.append(cg.Edge(7, 7, 1, 3))

G = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print(len(result))

# =========================
'''
'''
vlist = []
vlist.append(cg.Vertex(1))
vlist.append(cg.Vertex(2))
vlist.append(cg.Vertex(3))

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2))
edgelist.append(cg.Edge(2, 2, 2, 3))
edgelist.append(cg.Edge(3, 3, 3, 1))
edgelist.append(cg.Edge(4, 4, 1, 3))
edgelist.append(cg.Edge(5, 5, 3, 2))
edgelist.append(cg.Edge(6, 6, 2, 1))

G = cg.Graph(data=(vlist, edgelist))

result = G.temporal_match(M, 100)
print(len(result))

# =========================
'''













































