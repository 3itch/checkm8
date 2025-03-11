# Important Information About Secure and Trusted Boot And Signing Keys

## Background

IBM OpenPOWER systems support Secure and Trusted Boot to protect system
firmware.  Secure Boot implements a processor based chain of trust.  The
chain starts with an implicitly trusted component with other components being
authenticated and integrity checked before being executed on the host processor
cores.  At the root of this trust chain is the Host Platform Core Root of Trust
for Measurement (CRTM).  Immutable Read Only Memory (ROM - fixed in the POWER
processor chip) verifies the initial firmware load.  That firmware verifies
cryptographic signatures on all subsequent "to be trusted" firmware that is
loaded for execution on the P8 cores.  Trusted Boot also makes use of this same
CRTM by measuring and recording FW images via a Trusted Platform Module (TPM)
before control is passed on to the next layer in the boot stack.  The CRTM
design is based on a Public Key Infrastructure (PKI) process to validate the
firmware images before they are executed.  This process makes use of a set of
hardware and firmware asymmetric keys.  Multiple organizations will want to
deliver POWER hardware, digitally signed firmware, signed boot code,
hypervisors, and operating systems.  Each platform manufacturer wants to
maintain control over its own code and sign it with its own keys.  A single key
hash is stored in host processor module SEEPROM representing the anchoring root
set of hardware keys.  The P8 Trusted Boot supports a key management flow that
makes use of two kinds of hardware root keys, a wide open, well-known, openly
published public/private key pair (imprint keys) and a set of production keys
where the private key is protected by a hardware security module (HSM) internal
to the manufacturing facility of the key owner.

## Purpose Of Imprint Public/Private Keys

It is critical to note that the imprint keys are not to be used for production.
These are strictly for manufacturing and development level support given the
open nature of the private part of the Hardware keys.  This allows developers
and testers to sign images and create builds for Secure and Trusted Boot
development lab testing.  Systems must be transitioned to production level
keys for customer environments.

## Manufacturer Key Management Role

If a system is shipped from the System Manufacturer with imprint keys installed
rather than production level hardware keys, the system must be viewed as running
with a set of well-known default keys and vulnerable to exploitation.  The
System Access Administrator must work with the System Manufacturer to insure
that a key transition process is utilized once a hardware based chain of trust
is to be enabled as part of Secure or Trusted Boot functionality.

## Intentional Public Release Of Imprint Public/Private Keys

All public and private keys in this directory are being intentionally released
to enable the developer community to sign code images.  For true security, a
different set of production signing keys should be used, and the private
production signing key should be carefully guarded.  Currently, we do not yet
support production key signing, only development signing.

### Imprint Private Keys

#### Hardware Private Keys

The following files contain the Imprint private keys, in PEM format:

    hw_key_a.key
    hw_key_b.key
    hw_key_c.key

#### Software Private Keys

The project contains one sample Software key:

    sw_key_p.key

To generate your own software keys use the openssl "ecparam" command.  The
following commands will generate new private software keys P, Q and R:

    $ openssl ecparam -genkey -outform pem -noout -name secp521r1 -out sw_key_p.key
    $ openssl ecparam -genkey -outform pem -noout -name secp521r1 -out sw_key_q.key
    $ openssl ecparam -genkey -outform pem -noout -name secp521r1 -out sw_key_r.key

OpenPOWER secure boot supports three keys for Hardware (HW) key signing and (up
to) three keys for Software (SW) key signing,  This permits a "separation of
duties" in the firmware signing process, if such a separation is desired.  All
three HW keys are required, but the SW keys allow for the use of one, two or
three keys.  A signature is required (i.e. must be present in the container) by
*all three* firwmare keys, and by every (1-3) SW key in use, to create a
container that will boot with secure mode on.  If a separation of duties is not
required, the signer may use the same key for all three required HW keys, and
for the (1-3) required SW keys.  The container will boot as long as all required
signatures are present.

#### Hardware and Software Public Keys

The project includes the public keys for all the above private keys, in both PEM
format (*.pub) and RAW format (*.raw).  In the case where public keys are
required, you may use either format.  The RAW format is the minimal binary
format, with all (ASN.1) metadata stripped.  This is how they keys are stored
within the container, to provide the minimal footprint.  Usually you will work
with the keys in PEM format, as this is the most flexible and widely compatible
format.  The RAW keys are included mainly for testing.  However, for all
programs included in this project, the *.pub and *.raw keys are interchangeable.

The PEM format public keys can be easily extracted from the private keys using
the openssl `pkey` command, for example:

    $ openssl pkey -pubout -inform pem -outform pem -in sw_key_p.key -out sw_key_p.pub

To automatically extract the PEM public keys from the private keys, run the
included `extract_pubkeys.sh`

#### Keys required by each operational mode

When running the program in `Local (a.k.a. Development) mode` you must use the
private keys, as the signatures will be created locally.  The public keys are
not required, as the program automatically extracts the public key from the
private as needed.

When running in `Independent mode` you will use the public keys to generate the
signing requests, use the private keys to create the signatures, and again use
the public keys to complete the container.  This allows the signing operation to
be done independently of the other steps.

When running in `Production mode` the public keys are requested from the signing
server, and the signing operations are performed *at* the server, so the private
keys are never exposed.  In this mode there is no need to input any keys to the
program; it knows exactly what to request.

In sum: for any operation where signing is done, the program must consume the
private keys.  For any operation where signing requests are generated, or the
final container construction is done, the program needs only the public keys.

#### Hardware Keys Hash

As mentioned, a hash of the three public HW keys authorizing the platform
firmware is stored in system SEEPROM.  This is a 64 byte, SHA512 hash value.
On a running OpenPOWER machine this value may be read from an entry in the
system device tree:

    # cat /proc/device-tree/ibm,secureboot/hw-key-hash | xxd -p
    40d487ff7380ed6ad54775d5795fea0de2f541fea9db06b8466a42a320e6
    5f75b48665460017d907515dc2a5f9fc50954d6ee0c9b67d219dfb708535
    1d01d6d1

This pseudo-file is accessible from both the target OS and the petitboot shell.

Secure boot protects the signed firmware by comparing this hash to the
(calculated) hash of the three HW public keys in the container header (and then
using these keys to verify the HW key signatures, also in the container header).
If the hashes don't match, the machine won't boot.

To check that the hash of the HW keys you are using to build your container
matches the hash installed in the machine you wish to boot, use the `hashkeys`
tool:

    $ hashkeys -a hw_key_a.key -b hw_key_b.key -c hw_key_c.key

Note that the tool can calculate the value using either public or private keys
as input.  The output is always the hash of the public keys.

To store the value to a file that you can use to verify the completed container:

    $ hashkeys -a hw_key_a.key -b hw_key_b.key -c hw_key_c.key --outfile hw_keys_hash.md

Or run the included `gen_keys_hash.sh` which does the same.

To check the hash of the HW keys in an existing container, run the
`print-container` tool and look for the value in the output:

    $ print-container -w0 --imagefile /tmp/secure-container | grep -A1 "HW keys hash"
    HW keys hash (calculated):
        40d487ff7380ed6ad54775d5795fea0de2f541fea9db06b8466a42a32...

To verify that the value of the HW keys hash in the container matches the given
value, run the `print-container` tool with the `--verify` option.

    $ print-container --no-print --imagefile /tmp/secure-container \
                      --validate --verify hw_keys_hash.md

    Container validity check PASSED. Container verification check PASSED.

Note the `--validate` option performs an independent validity check, but is
shown for completeness
