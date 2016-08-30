# gttlvutil
Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically 
ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global 
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term 
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical 
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, 
see [https://guardtime.com](https://guardtime.com).

The gttlvutil is a collection of tools for converting KSI TLV data structures to and from binary data streams.
Following tools are included:
* gttlvdump - tool for decoding KSI binary data into human readable text stream. 
* gttlvundump - tool for encoding KSI TLV textually described data into binary data stream.
* gttlvwrap - tool for wraping input data into KSI TLV data structures.
* gttlvgrep - tool for seaching TLV type patterns in KSI binary stream.


## Installation ##

To build the gttlvutil, you need to have a cryptography provider installed on your system. The following cryptography 
providers are supported, choose one:
* OpenSSL (recommended)
* Windows native CryptoAPI

For building under Windows you need the Windows SDK.

If you do not want to build your own binaries, you can get the latest stable release from the Guardtime repository.
To set up the repository, save this repo file in your repositories directory (e.g. /etc/yum.repos.d/): 
[http://download.guardtime.com/ksi/configuration/guardtime.el6.repo](http://download.guardtime.com/ksi/configuration/guardtime.el6.repo)


## Usage ##

### gttlvdump ###

* Decode KSI signature
```
gttlvdump signature.ksig
```

* Decode publications file
```
gttlvdump -H 8 publicationsfile.bin
```

### gttlvundump ###

* Encode KSI signature
```
gttlvundump signature.txt
```

### gttlvwrap ###

* Wrap file content into TLV structure with type value '0123'
```
gttlvwrap -t 0123 -i test.file
```

### gttlvgrep ###

* Search for a publication time from calendar authentication record
```
gttlvgrep 800.805.10.02 signature.ksig
```

Detailed usage information is described in individual tool help ('-h') and in man pages: gttlvdump(1), gttlvgrep(1), gttlvwrap(1), tlv(5), tlv-desc(5).

For more information about TLV encoding see also man page: tlv(5)


## License ##

See LICENSE file.

## Dependencies ##

| Dependency        | Version                           | License type | Source                         | Notes |
| :---              | :---                              | :---         | :---                           |:---   |
| OpenSSL           | Latest stable for target platform | BSD          | http://www.openssl.org/        | This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).  This product includes software written by Tim Hudson (tjh@cryptsoft.com). |
| Windows CryptoAPI |                                   |              |                                | Can be used as alternative to OpenSSL. Build time option. |


## Compatibility ##

| OS / Platform                       | Compatibility                                |
| :---                                | :---                                         | 
| RHEL 6 and 7, x86_64 architecture   | Fully compatible and tested                  |
| CentOS 6 and 7, x86_64 architecture | Fully compatible and tested                  |
| Debian                              | Compatible but not tested on a regular basis |
| OS X                                | Compatible but not tested on a regular basis |
| Windows 7, 8, 10                    | Compatible but not tested on a regular basis |
