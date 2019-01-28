import sys
import CERTGraph as cg

sys.path.append('..')

data_path = '../data/cert_b_users/insiders/CDE1846-logs.csv'
save_path = '../data/graphs/CDE1846.txt'

graph = cg.CERTGraph()
graph.read_data(data_path)

v1 = cg.CERTVertex(1, None)
v2 = cg.CERTVertex(2, None)
v3 = cg.CERTVertex(3, None)
v4 = cg.CERTVertex(4, None)
v5 = cg.CERTVertex(5, None)
vlist = [v1, v2, v3, v4, v5]

edgelist = []
edgelist.append(cg.CERTEdge(1, 1, 1, 2, None))
edgelist.append(cg.CERTEdge(2, 2, 2, 3, None))
edgelist.append(cg.CERTEdge(3, 3, 2, 4, None))
edgelist.append(cg.CERTEdge(4, 4, 2, 5, None))

M = cg.CERTGraph(data=(vlist, edgelist))
print(M.vertices)

#result = graph.temporal_match(M, 500000)
#print('result : ')
#print(result)
#print(len(result))
#print(len(graph.edges))

graph.save(save_path)

graph2 = cg.CERTGraph(g_file=save_path)
