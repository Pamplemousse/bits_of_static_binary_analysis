import os

from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE

# Local handy function to print a graph to a file.
from utils import magic_graph_print as m_g_p
magic_graph_print = lambda dependencies: m_g_p(os.path.basename(__file__)[:-3], dependencies)


project = Project('build/command_line_injection', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True)

# We are only interested at the state at the sink `call` location.
call_to_system_address = 0x401185
observation_point = ('insn', call_to_system_address, OP_BEFORE)

# Run the RDA on the `check` function to gather informations.
check_function = project.kb.functions.function(name='check')
function_rda = project.analyses.ReachingDefinitions(
    subject=check_function,
    observation_points=[observation_point],
    dep_graph=DepGraph()
)

# What does interest us? The first parameter of the function `system`!
state_before_call_to_system = function_rda.observed_results[observation_point]
rdi_offset = project.arch.registers['rdi'][0]
rdi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(rdi_offset))[0]

# In fact, we want its predecessors, its predecessors' predecessors, ... all the way up!
rdi_dependencies = function_rda.dep_graph.transitive_closure(rdi_definition)


# Let's print to a file, so we can look at it.
magic_graph_print(rdi_dependencies)


import ipdb; ipdb.set_trace()
pass
