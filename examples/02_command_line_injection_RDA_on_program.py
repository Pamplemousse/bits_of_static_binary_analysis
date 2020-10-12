import os

from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.procedures.definitions.glibc import _libc_decls

# Local handy function to print a graph to a file.
from utils import magic_graph_print as m_g_p
magic_graph_print = lambda dependencies: m_g_p(os.path.basename(__file__)[:-3], dependencies)

# This is part of ongoing research and cannot be released at the moment :'(
from argument_resolver.handlers import handler_factory, StdioHandlers


project = Project('build/command_line_injection', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True, data_references=True)

# Extra step: recover the calling convention informations.
_ = project.analyses.CompleteCallingConventions(recover_variables=True)

sink_name = 'system'
sink_function = project.kb.functions.function(name=sink_name)

# We know that it is the first parameter of `system` that is "vulnerable".
parameter_position = 0
# `angr` has a bunch of pre-declared information about libc functions.
parameter_type = _libc_decls[sink_name].args[parameter_position]
# Get the `Atom` corresponding to the first parameter; Here, on x86_64, this is `<rdi>`.
parameter_atom = Atom.from_argument(
    sink_function.calling_convention.arg_locs()[parameter_position],
    project.arch.registers
)

# Pass it to the handlers to allow the analysis to return the `Definition` corresponding to the vulnerable `Atom` when the sink is reached.
# Type is needed to perform some extra steps in handlers for certain kind of parameters
#   (in particular for string pointers pointing to static memory region, and never "defined" in the binary).
vulnerable_atoms_and_types = [(parameter_atom, parameter_type)]

# Handlers are the "pieces" of the analysis used to simulate the effects of (local or external) function calls on the state.
# The simplest handler deals only with local functions, but we can add some more if needed.
# Pass it the sink function (and the vulnerable `Atom`s informations - see above) to know when to stop the recursive analysis.
Handler = handler_factory([
    # `sprintf` is a function of declared in the `stdio.h` header.
    StdioHandlers,
])

# So, `Handler` has been created using unreleased code; But anything respecting the abstract base class
# `angr.analyses.reaching_definitions.function_handler.FunctionHandler` would work!
# Pass the sink, and the atoms our `Handler` implementation to record the states we are interested in, when they get used!
handler = Handler(project, sink_function, vulnerable_atoms_and_types)

# This time:
#   * Start the RDA from `main`;
#   * Provide handlers to deal with function calls;
#   * No need to record a specific state (see comment above).
main_function = project.kb.functions.function(name='main')
program_rda = project.analyses.ReachingDefinitions(
    subject=main_function,
    function_handler=handler,
    dep_graph=DepGraph()
)

# Now, the `Definition`s corresponding to the vulnerable `Atom` has been put in the handler as a side-effect of the analysis.
rdi_definition = list(
    handler.sink_atom_defs[parameter_atom]
)[0]

# In fact, we want its predecessors, its predecessors' predecessors, ... all the way up!
rdi_dependencies = program_rda.dep_graph.transitive_closure(rdi_definition)


# Let's print to a file, so we can look at it.
magic_graph_print(rdi_dependencies)


import ipdb; ipdb.set_trace()
pass
