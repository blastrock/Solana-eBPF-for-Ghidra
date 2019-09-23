# eBPF Solana

This is a rebase of https://github.com/Toizi/eBPF-for-Ghidra which is a fork of https://github.com/Nalen98/eBPF-for-Ghidra.

It adds support to Ghidra to decompile Solana eBPF files. It supports Ghidra 11.0.3.

# Installation

- Download Release version of extension and install it in Ghidra `File → Install Extensions...`
- Use gradle to build extension: `GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle` and use Ghidra to install it: `File → Install Extensions...`

# Known Issues
- Rebasing after a program has been imported might lead to messed up relocations.
  Everything should work as expected when specifying base address in import options.
- Functions with more than 5 parameters are not correctly decompiled. See data/languages/eBPFSol.cspec.

# Useful links

* [Main source for how solana eBPF works](https://github.com/solana-labs/rbpf).
  Contains a disassembler, implements relocations, etc.
* [General Ghidra processor module resource](https://swarm.ptsecurity.com/creating-a-ghidra-processor-module-in-sleigh-using-v8-bytecode-as-an-example/).
  Covers implementing a processor module for V8 bytecode with lots of background
  info.

