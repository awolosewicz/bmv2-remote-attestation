
STEPS:

1. Install the framework dependencies mentioned in ebpf\_framework/README.md

2. Build ebpf object file by running make in switch\_tput directory.

3. Run ebpf\_framework/add\_tc\_egress.sh script

4. bpftool net list: check if ebpf program was loaded at tc hook point

5. Run switch\_tput/user\_space.py to read map values in user space and calculate average throughput.

