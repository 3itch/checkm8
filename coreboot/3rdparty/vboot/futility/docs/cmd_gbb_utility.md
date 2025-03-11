% FUTILITY(1) Version 1.0 | Futility GBB Documentation

NAME
====

**futility gbb** - allows for the printing and manipulation of GBB flag state.

SYNOPSIS
========

- **futility gbb** \[**\--help**]
- **futility gbb** \[**-g**|**--get**] \[GET mode options] \[image_file]
- **futility gbb** \[**-s**|**--set**] \[SET mode options] \[image_file] \[output_file]
- **futility gbb** \[**-c**|**--create**] \[CREATE mode options]
- **futility gbb** \[**-g**|**-s**] \[**\--flash**] \[GET|SET mode options] \[FLASH options]

DESCRIPTION
===========

The GBB sub-command allows for the printing and manipulation of the GBB flag state.

Options
-------

\--help

:   Prints brief usage information.

-g, \--get

:   Puts the GBB command into GET mode. (default)

-s, \--set

:   Puts the GBB command into SET mode.

-c, \--create=hwid_size,rootkey_size,bmpfv_size,recoverykey_size

:   Puts the GBB command into CREATE mode. Create a GBB blob by given size list.

GET Mode Options
----------------

Get (read) from image_file or flash, with following options:

\--flash

:   Read from and write to flash, ignore file arguments.

### Report Fields

The following options are available for reporting different types of information
from image_file or flash. The default is returning hwid. There could be multiple
fields to be reported at one time.

\--hwid

:   Report hardware id (default).

        hardware_id: EXAMPLE

\--flags

:   Report header flags.

        flags: 0x00000000

\--digest

:  Report digest of hwid (>= v1.2)

        digest: DIGEST_STRING

-e, \--explicit

:   Report header flags by name. This implies **\--flags**.

        flags: 0x00000000
        VB2_GBB_FLAG_FLAG_A
        VB2_GBB_FLAG_FLAG_B

### File Names to Export

-k, \--rootkey=FILE

:   File name to export Root Key.

-b, \--bmpfv=FILE

:   File name to export Bitmap FV.

-r, \--recoverykey=FILE

:   File name to export Recovery Key.

SET Mode Options
----------------

Set (write) to flash or file, with following options:

\--flash

:   Read from and write to flash, ignore file arguments.

-o, \--output=FILE

:   New file name for ouptput.

If no output file is specified, futility gbb will write back to image_file.

### Values to be Changed

There could be multiple values to be changed at one time.

\--hwid=HWID

:   The new hardware id to be changed.

\--flags=FLAGS

:   The new (numeric) flags value or +/- diff value.

### New File Names of Output

-k, \--rootkey=FILE

:   File name of new Root Key.

-b, \--bmpfv=FILE

:   File name of new Bitmap FV.

 -r  \--recoverykey=FILE

 :  File name of new Recovery Key.

FLASH Options
-------------

In GET and SET mode, the following options modify the behaviour of flashing.
Presence of any of these implies \--flash.

-p, \--programmer=PRG

:   Change AP (host) flashrom programmer

\--ccd_without_servod

:   Flash via Case Closed Debugging (CCD) without servod (similar to
    `--fast --force --wp=0 -p=raiden_debug_spi`). Note this
    may be unsafe on some boards, and using `--servo` is preferred whenever
    possible.

\--emulate=FILE

:   Emulate system firmware using file

\--servo

:   Flash using Servo (v2, v4, micro, ...)

\--servo_port=PRT

:   Override servod port, implies \--servo

EXAMPLES
========

Get information from $FILE

        futility gbb --get $FILE
        futility gbb --get --hwid $FILE
        futility gbb --get --flags $FILE
        futility gbb --get --digest $FILE
        futility gbb --get --hwid --flags --digest $FILE

Get the names of GBB flags

        futility gbb --get -e $FILE

Get information from host flash

        futility gbb --get --flash
        futility gbb --get --hwid --flash
        futility gbb --get --flags --flash
        futility gbb --get --digest --flash

Get information from flash using servo

        futility gbb --get --servo
        futility gbb --get --flash --servo

Export the rootkey from $FILE to $ROOTKEY_FILE

        futility gbb --rootkey=$ROOTKEY_FILE $FILE

Set values from $FILE and overwrite it

        futility gbb --set --flags=$FLAGS $FILE
        futility gbb --set --hwid=$HWID $FILE
        futility gbb --set --flags=$FLAGS $FILE --hwid=$HWID $FILE

Set values from $FILE to $OUT_FILE

        futility gbb --set --flags=$FLAGS $FILE $OUT_FILE
        futility gbb --set --flags=$FLAGS $FILE -o $OUT_FILE

Read from flash and write back new values using host flash

        futility gbb --set --flags=$FLAGS --flash

Read from servo and write back new values using servo

        futility gbb --set --flags=$FLAGS --servo

Create a GBB blob

        futility gbb --create $HWIDSIZE,$ROOTKEYSIZE,$BMPFVSIZE,$RECOVERYKEYSIZE
