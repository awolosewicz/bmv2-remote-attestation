1) bcc: https://github.com/iovisor/bcc/blob/master/INSTALL.md

BCC makes BPF programs easier to write, with kernel instrumentation in C (and includes a C wrapper around LLVM), and front-ends in Python and lua. It is suited for many tasks, including performance analysis and network traffic control.

2) bpftool: https://github.com/libbpf/bpftool

Bpftool can be used for loading ebpf programs and also for querying the system for ebpf status and deeper introspection into bpf object files and executables.

3) iproute2: https://github.com/shemminger/iproute2

iproute2 can be built from source and the later versions have support for loading ebpf programs with global variables onto the tc hook point. 

4) llvm-project: https://clang.llvm.org/get\_started.html

bpftool requires clang version > 13.0.0 . The latest clang source must be built and installed system-wide

