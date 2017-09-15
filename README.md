MinIperf
=========

What is MinIperf?
------------------

MinIperf is an iperf compatible server based on Mini-OS. It is intended
for network performance measurments involving TCP.


Building MinIperf
-----------------

### Preparations
It is recommended that you create a target directory first (e.g., ~/workspace).
It will be used to store all required sources and builds for MinIperf.

    export WORKSPACE=$HOME/workspace
    mkdir -p $WORKSPACE
    cd $WORKSPACE

I recommend to add this export line to your shell profile (e.g., via .bashrc if
you are using bash).


### Download and Build Xen (here: 4.4)
Please follow Xen's build instructions - it should be something like the
following:

    git clone git://xenbits.xen.org/xen.git
    cd xen
    git checkout stable-4.4
    ./configure
    make xen tools
    cd ..

Note: If Xen is not installed on your system yet, please install it as well.
You might need to restart your computer.
After that, please ensure that you set the following environment variables set
(I also recommend to add this to your shell profile):

    export XEN_ROOT=$WORKSPACE/xen


### Download dependencies
Our toolchain is required to comile and link the MinIperf VM binary:

    git clone  git://github.com/sysml/toolchain.git

Also, Mini-OS, the base OS for MinIperf, is required:

    git clone  git://github.com/sysml/mini-os.git

After that, please ensure that you set the following environment variables
(I also recommend to add this to your shell profile):

    export TOOLCHAIN_ROOT=$WORKSPACE/toolchain
    export MINIOS_ROOT=$WORKSPACE/mini-os


### Build toolchain
Please follow the build procedure as described in 'toolchain/README'.
In principle it should be:

    cd toolchain
    make
    cd ..


### Download and Build MinIperf
#### Clone the MinIperf repository

    git clone  git://github.com/sysml/miniperf.git
    cd miniperf

#### Configure (optional)
You can configure your build by enabling/disabling features in MinIperf.
This can be done by placing a file called .config.mk in your MinIperf
source directory. You can have a look in Config.mk which is the managed
configuration file (do not change this one).

#### Build

    make


### Getting Started

#### Create a Xen Guest Configuration
In order to boot MinIperf, create a Xen guest configuration file. You can use the
following example as a basis and save it under ```miniperf.cfg```:

    kernel        = 'build/miniperf_x86_64'
    vcpus         = '1'
    memory        = '64'

    name          = 'miniperf'
    extra         = '-i 192.168.0.2/24 -g 192.168.0.1 -d 192.168.0.1'

    vif           = [ 'mac=00:16:3e:ba:be:12,bridge=virbr0' ]

For now, just a single VIF is supported by MinIperf.
The `extra` option in the configuration specifies the parameters
that you pass to the guest. Possible options for MinIperf are listed
in the last paragraph.


#### Boot the VM
The VM is booted with the xl command:

    xl create -c miniperf.cfg


When your networking setup is correct, you should be able now to run
an iperf test:

    iperf -i 1 -r -c 192.168.0.2

You should also be able to ping it:

    ping 192.168.0.2


### MinIperf Parameters

    -i [IPv4/Route prefix] Host IP address in CIDR notation
                           (if not specified, DHCP client is enabled)
    -g [IPv4]              Gateway IP address
    -d [Num]               Interval for debug output (milliseconds)
    -a [hwaddr]/[IPv4]     Static ARP entry
                           (multiple tokens possible)
