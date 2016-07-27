# gttlvdump

## Help

	gttlvdump [-h] [options] tlvfile
		-h       This help message
		-H num   Constant header lenght.
		-d num   Max depth of nested elements
		-x       Display file offset for every TLV
		-w       Wrap the output.
		-y       Show content length.
		-z       Convert payload with length les than 8 bytes to decimal.
		-a       Annotate known KSI elements.
		-s       Strict types - do not parse TLV's with unknown types.
		-p       Pretty print values.
		-P       Pretty print keys.

## Useful commands

	* Dump publications file
		gttlvdump -H 8 publicationsfile
    * Dump tlv in hex format
        echo "tlvhex" | xxd -r -p | gttlvdump

## Dependencies

There are non 3rd Party dependencies for gttlvutil.


## Compatibility

```
OS / PLatform                       Compatibility

RHEL 6 and 7, x86_64 architecture   Fully compatible and tested.
CentOS 6 and 7, x86_64 architecture Fully Compatible and tested.
Debian                              Compatible but not tested on regular basis.
OS X                                Compatible but not tested on regular basis.
Windows 7, 8, 10                    Compatible but not tested on regular basis.
```