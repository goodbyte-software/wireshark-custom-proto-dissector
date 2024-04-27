# Custom protocol dissection in Wireshark

This repository contains code related to a blog post demonstrating how to implement of a Wireshark dissector for a custom protocol.
The dissector is written in Lua and the "custom protocol" (excom - EXample COMmunication protocol) is defined by `protocol.h` (client-server = request-response).

The history can be traced to see different steps of the implementation, marked with tags (`v1`, `v2`, ...), e.g. [v1](https://github.com/goodbyte-software/wireshark-custom-proto-dissector/tree/v1).
The tags are linked in the matching blog post sections.

## Running

The example can be compiled under Linux. You will need:

* GCC
* the standard [socat](https://linux.die.net/man/1/socat) command (install depending on distro)
* [Wireshark](https://www.wireshark.org/download.html) compiled with Lua support (should be the default)
* (optional) [just](https://github.com/casey/just) command runner

To run, either:
* use commands from the blog post,
* run the wrappers with commands [just](https://github.com/casey/just), e.g. `just client`, `just wireshark`,
* or examine the `justfile` for to see the commands to run.
