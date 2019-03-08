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
>>> import CERTGraph as cg
>>> graph = cg.Graph()
>>> graph.read_file('../data/cert_b_users/insiders/CDE1846-logs.csv') # loads the graph from file
>>> print(graph)
```
