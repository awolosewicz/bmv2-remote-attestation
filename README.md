# BEHAVIORAL MODEL (bmv2) WITH REMOTE ATTESTATION

This is a fork of the BMv2 P4 software reference switch implementing Remote Attestation features as discussed in "A Case for Remote Attestation in Programmable Dataplanes" by Nik Sultana, Deborah Shands, and Vinod Yegneswaran. The simple_switch target has been modified to generate an MD5 hash of the registers, table entries, and program whenever the respective structure is modified. These MD5 hashes can then be retrieved by running `get_ra_data` in the control plane or through inspection of IPv6 packets that have traversed the switches.

IPv6 packets which traverse the switch have hop-by-hop entries added which contain the MD5 hashes for the registers, table entries, and program of that switch, as well as structures which reflect on the entire path (the data of every switch XOR'd together). This is identified as hop-by-hop option 0x37, and the data is of the form
- ID: 0x37
- Length: 100
- 16 bits of padding
then the following six 16-byte entries:
- switch registers
- switch tables
- switch program
- route registers
- route tables
- route program.

This modification should be installed on top of an existing BMv2 installation. See ra_to_base.sh for installing this after compiling.

## Dependencies

On Ubuntu 20.04, the following packages are required:

- automake: 1:1.16.1-4ubuntu6
- cmake: 3.16.3-1ubuntu1.20.04.1
- libjudy-dev: 1.0.5-5
- libgmp-dev: 6.2.0+dfsg-4ubuntu0.1
- libpcap-dev: 1.9.1-3
- libboost-dev: 1.71.0.0ubuntu2
- libboost-test-dev: 1.71.0.0ubuntu2
- libboost-program-options-dev: 1.71.0.0ubuntu2
- libboost-system-dev: 1.71.0.0ubuntu2
- libboost-filesystem-dev: 1.71.0.0ubuntu2
- libboost-thread-dev: 1.71.0.0ubuntu2
- libevent-dev: 2.1.11-stable-1
- libtool: 2.4.6-14
- flex: 2.6.4-6.2
- bison: 3.5.1+dfsg-1
- pkg-config: 0.29.1-0ubuntu4
- g++: 9.3.0-1ubuntu2
- libssl-dev: 1.1.1f-1ubuntu2.17
- libffi-dev: 3.3-4
- python3-dev: 3.8.2-0ubuntu2
- python3-pip: 20.0.2-5ubuntu1.8
- wget: 1.20.3-1ubuntu1


You also need to install the following from source. Feel free to use the
install scripts under travis/.

- [thrift 0.13.0](https://github.com/apache/thrift/releases/tag/0.13.0)
- [nanomsg 1.1.5](https://github.com/nanomsg/nanomsg/releases/tag/1.1.5) or
  later

To use the CLI, you will need to install the
[nnpy](https://github.com/nanomsg/nnpy) Python package. Feel free to use
travis/install-nnpy.sh

To make your life easier, we provide the *install_deps.sh* script, which will
install all the dependencies needed on Ubuntu 20.04.

## Building the code

    1. ./autogen.sh
    2. ./configure
    3. make

In addition, on Linux, you may have to run `sudo ldconfig` after installing
bmv2, to refresh the shared library cache.

Debug logging is enabled by default. If you want to disable it for performance
reasons, you can pass `--disable-logging-macros` to the `configure` script.

In 'debug mode', you probably want to disable compiler optimization and enable
symbols in the binary:

    ./configure 'CXXFLAGS=-O0 -g'

The new bmv2 debugger can be enabled by passing `--enable-debugger` to
`configure`.

