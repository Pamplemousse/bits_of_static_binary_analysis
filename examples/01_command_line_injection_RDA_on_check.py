import os
from pathlib import Path
from networkx.drawing.nx_agraph import write_dot

from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE


project = Project('build/command_line_injection', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True)

# Run the RDA on the `check` function to gather informations.
check_function = project.kb.functions.function(name='check')
function_rda = project.analyses.ReachingDefinitions(
    subject=check_function,
    observe_all=True,
    dep_graph=DepGraph()
)

# Manually retrieve the state at the sink location.
call_to_system_address = 0x401185
state_before_call_to_system = function_rda.observed_results[('insn', call_to_system_address, OP_BEFORE)]

# What does interest us? The first parameter of the function `system`!
rdi_offset = project.arch.registers['rdi'][0]
rdi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(rdi_offset))[0]

# In fact, we want its predecessors, its predecessors' predecessors, ... all the way up!
rdi_dependencies = function_rda.dep_graph.transitive_closure(rdi_definition)


# Let's print to a file, so we can look at it.
path_and_filename = os.path.join(Path.home(), 'tmp', os.path.basename(__file__)[:-3])
write_dot(rdi_dependencies, "%s.dot" % path_and_filename)
os.system("dot -Tsvg -o %s.svg %s.dot" % (path_and_filename, path_and_filename))


import ipdb; ipdb.set_trace()
pass
