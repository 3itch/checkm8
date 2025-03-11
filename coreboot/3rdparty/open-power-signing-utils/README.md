sb-signing-utils
================

A simple utility for signing firmware components for OpenPOWER Secure
and Trusted Boot.

How Firmware Signing works on OpenPOWER
---------------------------------------

The core root of trust is in the CPU module (package). From the factory,
they come with "imprint" keys. The private key part is well known (i.e.
**the private key is published on the internet**), and vendors, when
putting modules into machines, will replace the imprint key with their
own key.

A hash of this key is stored in a SEEPROM inside the module (as there is
not enough space to store the full key). The full key is stored in the
Secure/Trusted Boot Header (i.e the container header) of every bit of
firmware loaded from flash (PNOR).

All firmware loaded must be signed by this hardware key. In fact, there
are three hardware keys, permitting a separation of duties for the root
authority. Signatures by all three hardware keys must be present in the
container.

In addition to the hardware key, there is also a software key (also
referred to as firmware key in some documentation.) In fact there are
three software keys, permitting a separation of duties for the firmware
signing operation.

Having separate hardware and software keys allows firmware to be
developed by a separate group to hardware (or multiple firmware loads
for the same hardware to be developed by separate entities).

The signing operations necessitate a two-step signing process since the
part of the container header that must be signed needs to be created
first, then the signatures must be returned to the container build
process to complete the container. In the case of locally accessible keys
(i.e. the private key is available to the build process), the entire
container can be completed at once (in a two-step process). In the case
where signatures must be created externally, there may be some delay
between the two steps.

By default, op-build will produce a signed firmware image but with the
published imprint keys. As such you **MUST NOT** use these to implement
secure boot. **The default product from op-build is only suitable for
development use.**

The container build process
---------------------------

The hardware and software keys form a two level hierarchy. The root keys
are the hardware keys, and the signing keys are the software keys. In
short, the hardware keys sign the software keys, the and software keys
sign the firmware components. The publc portion of the hardware and
software keys are added to the container during the build process.

There are two sections, or blobs, of the container header to be signed:
the software header and the prefix header. The software header, among
other fields, contains a SHA512 hash of the payload (i.e. the firmware
image being signed). The software header will be signed by the software
keys. The prefix header contains a SHA512 hash of the software keys. The
prefix header will be signed by the hardware keys.

The create-container program is run in a two-pass process. On each pass,
the program will create as much of the container as possible using all
available information. Normally, all information (i.e. all updatable
fields) are provided on the first pass, except for the signatures. On the
first pass, the program must have enough information to construct the
software and prefix headers. Namely, it must have the payload and the
public software keys. (Normally the hardware keys are also added on the
first pass, although they don't have to be.) On the first pass, the
program dumps the prefix and software header to the files specified.

The prefix header is then signed by the hardware keys, and the software
header is signed by the software keys. The signing operation (and keys)
use an ECDSA p521 signing algorithm. The signatures should be returned
in DER format and can be performed by a simple "openssl dgst" command.

On the second pass, the program consumes the hardware and software key
signatures, adds these fields to the container header and completes the
container. The complete container consists of the container header (with
all required public keys and signatures) added to the beginning of the
payload.

Building the project
--------------------

The scripts "build_all.sh" and "clean_all.sh" are included in the project
project, and demonstrate how to build the project from source. The scripts
support the GNU toolchain enabled method of building, and a
"lite" method of building.

To build with full GNU toolchain support, run "build_all.sh" passing
"gnu" on the command-line:

$ build_all.sh gnu

This utilizes the included "configure.ac" and "Makefile.am", and is
equivalent to running:

$ libtoolize -f && aclocal && autoheader && automake -a && autoconf && \
  configure && make

Or:

$ autoreconf -i -Wno-unsupported && ./configure && make

To clean the project, including removing *all* GNU toolchain support
files, run:

$ clean_all.sh gnu

To build "lite" using a simple Makefile and config.h, run "build_all.sh"
passing "lite" on the command-line (or no option at all, as "lite" is the
default):

$ build_all.sh lite

This utilizes the included "configure.h.lite" and "Makefile.lite". The
script simply copies these files into place and runs "make".

To clean the project, run the following, which is really just doing a
"make clean":

$ clean_all.sh lite

Installing the project
--------------------
To install the project (executable files) locally, after running the
preferred build method above:

$ make install

To uninstall:

$ make uninstall

The files install to /usr/local/bin by default.  You must have write
permission to this directory.  To install to a different directory:

$ make install bindir=/preferred/install/path/
$ make uninstall bindir=/preferred/install/path/

Signing HOWTO
-------------

This HOWTO signs a single payload (i.e. the contents of a single
PNOR partition). You will need to repeat these steps for each signed bit
of firmware. This may be several FFS partitions in a PNOR image, or
several files (depending on platform).

Signing with local keys
-----------------------

The included shell script "sign-with-local-keys.sh" demonstrates the
container build operation. First, the program builds enough of the
container to create the prefix and software headers, and dumps them to
the specified files:

$ ./create-container -a hw_key_a.key -b hw_key_b.key -c hw_key_c.key \
                     -p sw_key_a.key \
                      --payload image.bin --imagefile container.out \
                      --dumpPrefixHdr prefix_hdr --dumpSwHdr software_hdr

where the *.key files contain the public keys in PEM format, the payload
is the firmware image to be protected by this container, the output file
is the completed container and the prefix_hdr and software_hdr files
contain the dump of the blobs to-be-signed.

(Actually, the .key files may contain either the public key or the
private key. Only the public key is required at this step, since this is
not a signing operation. The program only needs to extract the public key
to add it to the container, and it can do so with either the public key
or private key as input.)

The script reuses HW key A as SW key P, as a shortcut. Normally the
hardware and firmware keys would be different. Also, the script only uses
one software key. The use of 1-3 software keys is supported by secure
boot. However, for every software public key provided in the container
header, a corresponding signature must be present. In the case of the
hardware keys, all three keys must be used (although the user may choose
to use the same key thrice.)

Next, the prefix and software headers are signed by the hardware and
software keys, respectively. These may be done with simple openssl
operations:

$ openssl dgst -SHA512 -sign hw_key_a.key prefix_hdr > hw_key_a.sig
$ openssl dgst -SHA512 -sign hw_key_b.key prefix_hdr > hw_key_b.sig
$ openssl dgst -SHA512 -sign hw_key_c.key prefix_hdr > hw_key_c.sig

$ openssl dgst -SHA512 -sign sw_key_a.key software_hdr > sw_key_p.sig

In this case the .key files *must* be the private keys. The .sig files are
the resulting signatures in DER format. (The prefix_hdr and software_hdr
files have now been consumed and may be discarded.)

Finally, create-container is run one more time to add the signatures and
complete the container:

$ ./create-container -a hw_key_a.key -b hw_key_b.key -c hw_key_c.key \
                     -p sw_key_a.key \
                     -A hw_key_a.sig -B hw_key_b.sig -C hw_key_c.sig \
                     -P sw_key_p.sig \
                      --payload image.bin --imagefile container.out

All input files have the same meaning as on the first pass: the *.key
files may be the public or private key in PEM format. The .sig files are
the signatures in DER format.

You now have a completed container that will secure boot on OpenPOWER
(assuming the HW public keys match that stored in the CPU SEEPROM).

Signing securely with protected private keys
--------------------------------------------

The local signing method is secure only if the system on which the
container is built is secure. Bear in mind that the private keys will be
exposed on the local system while the container header is built.

If the build system is not secure it may be desirable to perform the
signing operation in a separate environment. In this case the prefix and
software headers may be transferred to this environment (or environments,
as separation of duties dictates), signed, and resulting signatures
returned to the build environment. It is not necessary to expose the
private keys to the build environment.

In all cases, those doing the signing should **verify** the legitimacy of
what they are about to sign, and perform the signing in a secure, trusted
environment in which it safe to expose the unencrypted private keys.

