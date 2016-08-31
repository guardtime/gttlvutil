# gttlvutil
Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically 
ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global 
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term 
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical 
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, 
see [https://guardtime.com](https://guardtime.com).

The gttlvutil is a collection of utils for working with the KSI type-length-value (TLV) encoded binary data. This encoding is used
throughout the KSI infrastructure - for KSI signature, publications file and network communication.

The following utils are provided: 
* gttlvdump - converts TLV-encoded binary data into human readable text format 
* gttlvundump - converts data in human readable text format into TLV-encoded binary data
* gttlvwrap - wraps given data into TLV data structure
* gttlvgrep - searches TLV type patterns in TLV binary stream


## Installation ##

To build the gttlvutil, a cryptography provider has to be installed in the system. The following providers are supported:
* OpenSSL (recommended)
* Windows native CryptoAPI

For building under Windows you need the Windows SDK.

If you do not want to build your own binaries, you can get the latest stable release from the Guardtime repository.
To set up the repository, save the appropriate repo file in your repositories directory (e.g. `/etc/yum.repos.d/`):
* [http://download.guardtime.com/ksi/configuration/guardtime.el6.repo](http://download.guardtime.com/ksi/configuration/guardtime.el6.repo)
* [http://download.guardtime.com/ksi/configuration/guardtime.el7.repo](http://download.guardtime.com/ksi/configuration/guardtime.el7.repo)

## Usage ##

### gttlvdump ###

* Convert KSI signature to human readble text format
```
gttlvdump signature.ksig
```

* Convert publications file to human readable text format
```
gttlvdump -H 8 publicationsfile.bin
```

### gttlvundump ###

* Convert KSI signature in human readable text format to binary TLV
```
gttlvundump signature.txt
```

### gttlvwrap ###

* Wrap the content of the given file into TLV structure with type '0123'
```
gttlvwrap -t 0123 -i test.file
```

### gttlvgrep ###

* Find publication time from calendar authentication record in the given KSI signature
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
