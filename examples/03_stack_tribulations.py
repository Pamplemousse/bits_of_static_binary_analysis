from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.project import Project


project = Project('build/buffer_overflow_strcpy', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True, data_references=True, show_progressbar=True)

obviously_problematic_function = project.kb.functions.function(name='obviously_problematic')

# This time, let's observe everything, and we will look for what is of interests to us.
rda = project.analyses.ReachingDefinitions(
    subject=obviously_problematic_function,
    observe_all=True,
)

# Look at how the instruction `call strcpy` translates to in VEX: the return value is explicitely pushed on the stack.
obviously_problematic_function_first_block = rda.project.factory.block(obviously_problematic_function.addr).vex

# Manually retrieve the state at the "sink" location, before and after the `call` instruction is analysed.
call_to_strcpy_address = 0x4011af
state_before_strcpy_call = rda.observed_results[('insn', call_to_strcpy_address, OP_BEFORE)]
state_after_strcpy_call = rda.observed_results[('insn', call_to_strcpy_address, OP_AFTER)]

# There are three things on the stack right before the `call`:
#   * the previous value of `rbp`,
#   * the pointer to the static string `src`,
# The pointer to `dest` is not here; Because no code assigns anything to it, it is not "defined" yet!
stack_variables_before_call = state_before_strcpy_call.stack_definitions.get_all_variables()
# There is something more once the `call` instruction is analysed: the return value of the call to `strcpy`.
stack_variables_after_call = state_after_strcpy_call.stack_definitions.get_all_variables()


import ipdb; ipdb.set_trace()
pass
