# gttlvutil

Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically 
ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global 
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term 
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical 
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, 
see [https://guardtime.com](https://guardtime.com).

The gttlvutil is a collection of utils for working with the KSI type-length-value (TLV) encoded binary data. This 
encoding is used throughout the KSI infrastructure - for KSI signature, publications file and network communication.

The following utils are provided: 
* gttlvdump - converts TLV-encoded binary data into human readable text format 
* gttlvundump - converts data in human readable text format into TLV-encoded binary data
* gttlvwrap - wraps given data into TLV data structure
* gttlvgrep - extracts data, that is described via TLV type pattern, from TLV binary stream




## Installation ##

### Latest release from Guardtime repository ###

In order to install the gttlvutil CentOS/RHEL packages directly from the Guardtime public repository, download and 
save the repository configuration to the /etc/yum.repos.d/ folder:

```
cd /etc/yum.repos.d

# In case of RHEL/CentOS 6
sudo curl -O http://download.guardtime.com/ksi/configuration/guardtime.el6.repo

# In case of RHEL/CentOS 7
sudo curl -O http://download.guardtime.com/ksi/configuration/guardtime.el7.repo

sudo yum install gttlvutil
```

### From source code ###

If the latest version is needed, or the package is not available for the
platform, check out source code from Github and build it using gcc or VS.

To build the gttlvutil, a cryptography provider has to be installed in the system. The following providers are supported:
* OpenSSL (recommended)
* Windows native CryptoAPI

Use rebuild-rpm.sh script to build an RPM installation package on CentOS/RHEL. 

See `WinBuild.txt` to read how to build KSI tool on Windows. 

### Automated tests ###

See `test/README.md` to learn how to run gttlvutil tests on linux.




## Usage ##

### gttlvdump ###

* Convert KSI signature to human readable text format
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

* Extract publication time from calendar authentication record in the given KSI signature
```
gttlvgrep 800.805.10.02 signature.ksig
```

Detailed usage information is described in individual tool help ('-h') and in man pages: gttlvdump(1), gttlvgrep(1), 
gttlvwrap(1), tlv-desc(5).

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
