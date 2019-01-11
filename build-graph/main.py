import sys
import build as bd

sys.path.append('..')

data_path = '../data/cert_b_users/insiders/CDE1846-logs.csv'

graph = bd.CERTGraph()
graph.read_data(data_path)
