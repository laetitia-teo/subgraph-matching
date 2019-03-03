import sys
import CERTGraph as cg
import time
import matplotlib.pyplot as plt
import numpy as np

sys.path.append('..')

data_path = '../data/cert_b_users/insiders/CDE1846-logs.csv'
save_path = '../data/graphs/insiders/CDE1846.txt'

#graph = cg.Graph(g_file=save_path)

graph = cg.Graph()
graph.read_data(data_path)

v1 = cg.Vertex(1, None)
v2 = cg.Vertex(2, None)
v3 = cg.Vertex(3, None)
v4 = cg.Vertex(4, None)
#v5 = cg.CERTVertex(5, None)
vlist = [v1, v2, v3, v4]

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2, None))
edgelist.append(cg.Edge(2, 2, 2, 4, None))
edgelist.append(cg.Edge(3, 3, 4, 3, None))
edgelist.append(cg.Edge(4, 4, 2, 3, None))
edgelist.append(cg.Edge(5, 5, 1, 2, None))

M = cg.Graph(data=(vlist, edgelist))
print(M.vertices)

result = graph.temporal_match(M, 36000000)
print('result : ')
print(result)
print(len(result))
print(len(graph.edges))

#graph.save(save_path)

'''
#graph = cg.Graph()
#graph.read_data(data_path)
#graph.save(save_path)
graph = cg.Graph(g_file=save_path)

v1 = cg.Vertex(1, None)
v2 = cg.Vertex(2, None)
v3 = cg.Vertex(3, None)
v4 = cg.Vertex(4, None)
v5 = cg.Vertex(5, None)
vlist = [v1, v2, v3, v4, v5]

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2, None))
edgelist.append(cg.Edge(2, 2, 2, 3, None))
edgelist.append(cg.Edge(3, 3, 2, 4, None))
edgelist.append(cg.Edge(4, 4, 2, 5, None))
edgelist.append(cg.Edge(5, 5, 1, 2, None))

M = cg.Graph(data=(vlist, edgelist))
print(M.vertices)

result = graph.temporal_match(M, 3600000)
print('result : ')
print(result)
if result:
    print(len(result))
    print(len(graph.edges))
'''
'''
deltas = (np.arange(2) + 1) * 36000000 # hour slices
t0 = time.time()
list_of_results = []
a = []
for delta in deltas:
    print("delta : %s" % delta)
    list_of_results.append(graph.temporal_match(M, delta))
    t = time.time()
    a.append(t - t0)
    t0 = t
plt.plot(a)
plt.show()
#plt.plot([len(results) for results in list_of_results])
#plt.show()
'''
'''
t0 = time.time()
result = graph.temporal_match(M, 1500000000000)
print(time.time() - t0)
print(len(result))
'''
