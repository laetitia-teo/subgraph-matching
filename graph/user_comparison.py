import CERTGraph as cg
import matplotlib.pyplot as plt
import time
from glob import glob
import os.path as op


# =============================================================================
# Define users to test :
# =============================================================================

users = ['CDE1846', 'ACM2278', 'MAB1775']

userfiles = ['../data/graphs/insiders/' + u + '.txt' for u in users]

userfiles = sorted(glob(op.join('..', 'data', 'graphs', 'insiders', \
    '*.txt')))

# =============================================================================
# Define pattern to test :
# =============================================================================

v1 = cg.Vertex(1, None)
v2 = cg.Vertex(2, None)
v3 = cg.Vertex(3, None)
v4 = cg.Vertex(4, None)
vlist = [v1, v2, v3, v4]

edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2, None))
edgelist.append(cg.Edge(2, 2, 2, 4, None))
edgelist.append(cg.Edge(3, 3, 4, 3, None))
edgelist.append(cg.Edge(4, 4, 2, 3, None))
edgelist.append(cg.Edge(5, 5, 1, 2, None))

M = cg.Graph(data=(vlist, edgelist))

delta = 36000000 # 10 hour

# =============================================================================
# Run algorithm on the user graphs
# =============================================================================

num_match = []
times = []
t0 = time.time()

for i, path in enumerate(userfiles):
    graph = cg.Graph(g_file=path)
    t0 = time.time()
    num_match.append(len(graph.temporal_match(M, delta)))
    times.append(time.time() - t0)

plt.plot(num_match)
plt.show()


