# sklton-key

`sklton-key`, pronounced 'skeleton key', allows you to decrypt TLS traffic of a
target go process. `sklton-key` attaches to go processes and intercepts the
KeyLogWriter method to enable SSLKEYLOGFILE-style logging of TLS secrets.

## Requirements

* binary must contain DWARF debugging information
* binary must be compiled with at least go1.8

## Installation

```
go install github.com/amlweems/sklton-key
```

## Usage

```
$ sklton-key -h
Usage of sklton-key:
  -log string
    	Log file to write key log to (defaults to stdout).
  -pid int
    	Pid to attach to.
```

Before starting your target, you'll need to start a packet capture (e.g. tcpdump):
```
$ tcpdump -s0 -w capture.pcap
```

You may now start your target process and launch `sklton-key` to begin writing
the key log:
```
$ ./target-binary &
$ sklton-key -pid `pidof target-binary` -log keys.log
```

Once the binary begins making requests, you can use Wireshark to decrypt the
packet capture. Wireshark 1.6.0 and above can use these log files to decrypt
packets. Set the following Wireshark setting to your `keys.log` file.

Edit→Preferences→Protocols→TLS→(Pre)-Master-Secret log filename

![Wireshark screenshot showing packet decryption.](docs/wireshark.png)
