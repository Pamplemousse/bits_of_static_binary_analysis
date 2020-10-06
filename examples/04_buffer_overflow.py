import os
import re
from pathlib import Path
from networkx.drawing.nx_agraph import write_dot

from angr.project import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph

# This is part of ongoing research and cannot be released at the moment :'(
from argument_resolver.handlers import handler_factory
from argument_resolver.utils import Utils


project = Project('build/buffer_overflow_strcpy', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True)

# Ugly hack (part I):
# Because `angr` does not yet support storing some information we need in the RDA's state;
# We will store it globally to have access to it during the script execution.
# Make it a dictionary of `Definition` -> `List[MemoryLocation]` (there could be several calls to `strcpy`,
# several source definitions, and all might have different stack portions to overwrite!).
OVERWRITTEN_STACK_VARIABLES = {}

# This time, we don't want to simulate `strcpy`: We want to analyse what's flowing into it!
# So, this will be used to monkey-patch `handle_strcpy`.
def handle_strcpy(self, state, code_location):
    # Retrieve the representation of the arguments from the calling convention analysis results.
    cc = self._calling_convention_resolver.get_cc('strcpy')
    (destination_argument, source_argument) = cc.args

    # Get the definitions from these arguments out of the state.
    # (via `Utils`, just to simplify the code here)
    destination_definitions = Utils.get_definitions_from_cc_arg(destination_argument, state, state.arch)
    source_definitions = Utils.get_definitions_from_cc_arg(source_argument, state, state.arch)

    # Generate a single DataSet that includes all possible sources / destinations
    # (again, via `Utils`, just to simplify the code here)
    destination_pointers = Utils.get_data_from_definitions(destination_definitions, state.arch)
    source_pointers = Utils.get_data_from_definitions(source_definitions, state.arch)

    # Get the size of the source string.
    # (again, via `Utils`, just to simplify the code here)
    source_content = Utils.get_strings_from_pointers(source_pointers, state)
    source_size = source_content._bits // 8

    def _atom_can_be_overwritten(atom):
        """ Tell if the given `atom` can be overwritten by the copy:
            If it is "earlier" on the stack, and "within reach" of the copy length.
            *NOTE* that this function is not pure: It uses `destination_pointers`!
        """
        return any(list(map(
            lambda p: p.offset <= atom.addr.offset and atom.addr.offset <= p.offset + source_size,
            destination_pointers
        )))

    # Get the list of all the stack variables, defined at the moment of the call to `strcpy`,
    # that can be overwritten by it.
    overwritten_stack_variables = list(filter(
        lambda v: _atom_can_be_overwritten(v.atom),
        state.stack_definitions.get_all_variables()
    ))

    # If some stack variables are overwritten: :scream:, and allow the rest of the script to know!
    if len(overwritten_stack_variables) > 0:
        # Ugly hack (part 2):
        # Because `angr` does not yet support storing these information in the RDA's state;
        # Store that in a global so we can access it later in the script.
        # For each source `Definition`, associate the list of overwritten stack variables.
        OVERWRITTEN_STACK_VARIABLES.update(dict(map(
            lambda d: (d, overwritten_stack_variables),
            source_definitions
        )))

    # Necessary `return` for a working interprocedural RDA.
    return False, state

# Same as previous example; Except this time, we don't need to simulate anything.
Handler = handler_factory()
# This is where the monkey-patching happens.
Handler.handle_strcpy = handle_strcpy

# This time, the mechanics of reporting are handled manually in our `handle_strcpy`,
handler = Handler(project)

main_function = project.kb.functions.function(name='main')

# Because of the "Ugly hack", there is no need to record any states as they are saved in a global
# variable whenever necessary.
rda = project.analyses.ReachingDefinitions(
    subject=main_function,
    function_handler=handler,
    dep_graph=DepGraph()
)

# Ugly hack (part III):
# Because `angr` does not yet support storing some information we need in the RDA's state;
# We need to retrieve data following the analysis from the global scope.
# For all the `OVERWRITTEN_STACK_VARIABLES`, print the dependencies of the source definition to a file.
if OVERWRITTEN_STACK_VARIABLES != {}:
    for source_definition, overwritten_stack_variables in OVERWRITTEN_STACK_VARIABLES.items():
        source_dependencies = rda.dep_graph.transitive_closure(source_definition)

        definition_name = re.sub(
            r"<|>",
            '',
            "%s@%#x" % (source_definition.atom, source_definition.codeloc.ins_addr)
        )
        path_and_filename = os.path.join(Path.home(), 'tmp', "%s_%s" % (os.path.basename(__file__)[:-3], definition_name))
        write_dot(source_dependencies, "%s.dot" % path_and_filename)
        os.system("dot -Tsvg -o %s.svg %s.dot" % (path_and_filename, path_and_filename))


import ipdb; ipdb.set_trace()
pass
