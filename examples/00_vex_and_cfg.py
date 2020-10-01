from angr import Project


project = Project('build/vex_and_cfg', auto_load_libs=False)
architecture = project.arch
cfg = project.analyses.CFGFast()

main_function = project.kb.functions.function(name='main')

# `main` contains several basic blocks.
blocks_of_main = list(main_function.blocks)

# VEX of the first block of the `main` function.
main_vex = blocks_of_main[0].vex

# Get the first node (basic block) of `main` from the CFG.
main_entry_node = cfg.model.get_any_node(main_function.addr)

# ???
mystery_node = main_entry_node.successors[0]

# Simprocedure!?
mystery_simprocedure = mystery_node.successors[0]

# The mystery returns to `main`.
main_other_node = mystery_simprocedure.successors[0]


import ipdb; ipdb.set_trace()
pass
