# guest lecture CSE545

## Examples

Sources are located under [source/](source/), and the binaries will be built in [build/](build/) using `make`.

| program                  | usage                           | exploit                                                 |
| ------------------------ | ------------------------------- | ------------------------------------------------------- |
| `vex_and_cfg`            | `./vex_and_cfg`                 | N/A                                                     |
| `command_line_injection` | `./command_line_injection /tmp` | `./command_line_injection "/tmp; whoami"`               |


Scripts using `angr` are in [examples/](examples/).
