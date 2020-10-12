import os
from pathlib import Path
from networkx.drawing.nx_agraph import write_dot


def magic_graph_print(filename, dependency_graph):
    path_and_filename = os.path.join(Path.home(), 'tmp', filename)
    write_dot(dependency_graph, "%s.dot" % path_and_filename)
    os.system("dot -Tsvg -o %s.svg %s.dot" % (path_and_filename, path_and_filename))
