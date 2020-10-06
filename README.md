# bits of static binary analysis

Material and examples used during a guest lecture I gave as part of the [CSE545 class at ASU](https://www.tiffanybao.com/courses/cse545/).

Slides available at: <a href='https://docs.google.com/presentation/d/13SDNRKHblo2xenczp9m6rQahigtwygmUcrBhZ-G3gvo' target='_blank'>docs.google.com/presentation/d/13SDNRKHblo2xenczp9m6rQahigtwygmUcrBhZ-G3gvo</a> .

## Examples

Sources are located under [source/](source/), and the binaries will be built in [build/](build/) using `make`.

| program                  | usage                           | exploit                                                 |
| ------------------------ | ------------------------------- | ------------------------------------------------------- |
| `vex_and_cfg`            | `./vex_and_cfg`                 | N/A                                                     |
| `command_line_injection` | `./command_line_injection /tmp` | `./command_line_injection "/tmp; whoami"`               |
| `buffer_overflow_strcpy` | `./buffer_overflow_strcpy AAA`  | `./buffer_overflow_strcpy $(python -c 'print("a"*10)')` |


Scripts using <a href='https://angr.io/' target='_blank'>`angr`</a> are in [examples/](examples/).
