# subgraph-matching

Subgraph matching for insider threat detection.
Implementation of https://arxiv.org/pdf/1801.08098.pdf

requires numpy and pandas to run.

## Exploring the data

cd data-exploration/

run the jupyter notebook

## Testing the graph builder

go in the graph subdirectory and run Python 3

```Python
import CERTGraph as cg

graph = cg.Graph()
graph.read_file('../data/cert_b_users/insiders/CDE1846-logs.csv') # loads the graph from file
print(graph)

# Motif :
edgelist = []
edgelist.append(cg.Edge(1, 1, 1, 2, None))
edgelist.append(cg.Edge(2, 2, 2, 4, None))
#edgelist.append(cg.Edge(3, 3, 4, 3, None))
edgelist.append(cg.Edge(4, 4, 2, 3, None))
edgelist.append(cg.Edge(5, 5, 1, 2, None))
M = cg.Graph(elist=edgelist)

d = 36000000
result = graph.temporal_match(M, d)
```
