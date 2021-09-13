# PhOeNiX
Linux console tool to mislead internet packets in the local network targeting the gateway.

**Disclaimer!! This tool will send ARP response packets stating, that the gateway ip is at a MAC address that does not exist. No device except the device running the attack will have a working connection to the internet. Only use this tool if you know what you are doing and only run this on your own network. I wont take any responsiblity for your actions.**

## Compile with gcc

The gcc compiler is preinstalled on many distributions.

To compile the program with gcc open a command line in the project folder and execute the command `gcc main.c -o phoenix-core -l pcap -lpthread`

## Compile with clang

The clang compiler is a better c compiler, but is not preinstalled on many distributions.

To compile the program with clang open a command line in the project folder and execute the command `clang main.c -o phoenix-core -l pcap -lpthread`

## Run the program

First follow the compilation instruductions above, then open a command line in the project folder and execute `sudo ./phoenix-core your-network-device`

To find out what your network device is, execute `ip link` in a command line.
