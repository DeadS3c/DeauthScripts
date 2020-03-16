# TCP-RST Hijack 

Simple script for doing rst hijack

## Getting Started

Grab the compiled file and execute with root to make a tcp-rst hijack to one ip, just use the bad_rst_hijack, the rst_hijack doesnt work properly

Or grab the c file and compile yourself with something like this:

```
gcc $(libnet-config --defines) -o bad_rst_hijack bad_rst_hijack.c -lnet -lpcap
```

### Prerequisites

This scripts need C installed and the pcap and libnet libraries

### Installing Dependencies

It depends on your OS:

Debian\Ubuntu: ``` sudo apt install libpcap-dev libnet ```

Arch: ``` sudo pacman -S libpcap libnet ```

Windows: ``` Don't use it, use Linux ```

### Usage

Just run the script and follow instructions if needed (run as sudo)
