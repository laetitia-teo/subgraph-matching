import CERTGraph as cg
import os.path as op
from glob import glob

filenames_ins = sorted(glob(op.join('..', 
                                    'data', 
                                    'cert_b_users', 
                                    'insiders', 
                                    '*-logs.csv')))

filenames_safe = sorted(glob(op.join('..', 
                                     'data', 
                                     'cert_b_users', 
                                     'safe', 
                                     '*-logs.csv')))

for filename in filenames_ins:
    graph = cg.Graph()
    print('reading file "%s"' % filename)
    graph.read_data(filename)
    savepath = '../data/graphs/insiders/' + filename[-16:-9] + '.txt'
    print('saving at "%s"' % savepath)
    graph.save(savepath)



