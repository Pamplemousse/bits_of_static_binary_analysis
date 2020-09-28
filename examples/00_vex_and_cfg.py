from angr import Project


project = Project('build/vex_and_cfg', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True, data_references=True)

main_function = project.kb.functions.function(name='main')

# `main` contains several basic blocks.
blocks_of_main = list(main_function.blocks)

# Get the first node (basic block) of `main` from the CFG.
main_entry_node = cfg.model.get_any_node(main_function.addr)

# VEX of the first block of the function `main`.
main_vex = main_entry_node.block.vex

# ???
mystery_node = main_entry_node.successors[0]

# Simprocedure!?
mystery_simprocedure = mystery_node.successors[0]

# The mystery returns to `main`.
main_other_node = mystery_simprocedure.successors[0]


import ipdb; ipdb.set_trace()
pass
