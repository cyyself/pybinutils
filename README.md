# pybinutils

This is a Python wrapper for the GNU Binutils. It is a work in progress and is not yet ready for use.

## Pre-requisites

You need {arch}-linux-gnu-binutils installed on your system. You can install it using the following command:

For Debian / Ubuntu:

```bash
apt install binutils-riscv64-linux-gnu binutils-aarch64-linux-gnu
```


## Example usecase:

### Draw cfg of a function in a elf binary

argv[1]: path to the binary

argv[2]: function name

argv[3]: output cfg dot file

argv[4]: output dom tree dot file

```bash
./src/draw_cfg.py -e ~/spec_run/CPU2006LiteWrapper/456.hmmer/build/456.hmmerrv64gc -s P7Viterbi -c rv64gc.dot -d rv64gc_dom.dot
```

The information on the cfg node is the dom tree path. Can be modified to dwarf position  or any other information.
