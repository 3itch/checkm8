Using TBOOT
===========

Instructions for Use:
--------------------
-  For Grub, the new tboot module must be added as the 'kernel' in the grub.conf file.
   For Grub2, the new tboot module must be added as the 'multiboot' in the grub.conf file.
   The existing 'kernel' entry should follow as a 'module'.  The SINIT AC
   module must be added to the grub.conf boot config as the last module, e.g.:

       title Xen w/ Intel(R) Trusted Execution Technology
           root (hd0,1)
           kernel /tboot.gz logging=serial,vga,memory
           module /xen.gz iommu=required dom0_mem=524288 com1=115200,8n1
           module /vmlinuz-2.6.18-xen root=/dev/VolGroup00/LogVol00 ro
           module /initrd-2.6.18-xen.img
           module /Q35_SINIT_17.BIN

-  The appropriate SINIT AC Modules can be downloaded from this webiste:
   https://software.intel.com/en-us/articles/intel-trusted-execution-technology/
   The current version of tboot (both in the repository and .tar.gz) requires 
   version 17 or greater of the SINIT AC module. It will not work with some 
   previous SINIT ACMs nor will it work on the TEP.

-  For Xen: newer versions of Xen support the `iommu=required` command line
   option, which causes Xen to fail to run if there is any error in
   programming the VT-d engines.  This is the most secure configuration.
   Older versions of Xen used the param `vtd=1` or `iommu=1`, which enables
   VT-d but does not fail if it cannot be enabled.

-  For Linux:  the `intel_iommu=on` command line option will enable VT-d and
   the TXT code in Linux will force this if it is not specified.  Support is
   now part of the 2.6.32 kernel.

-  Progress of the launch process is indicated via debug printk's using three
   different logging methods:
    - `serial` - logging is traced over a COM/serial port to a remote console
    - `vga`    - logging is traced to the local screen
    - `memory` - logging is traced to a memory location
   
   These three methods are not mutually exclusive - any combination can be
   enabled. Logging is enabled with command line parameters to tboot. The first
   parameter enables or disables logging levels (note that the default is all);
   any combination of "err", "warn", "info", "detail" can be used:

       loglvl=err,warn,info,detail|all|none

   To achieve a faster S3 resume, suggest to use `loglvl=err` or `loglvl=none`.
   The next parameter is used to configure the various logging targets; any 
   combination can be used (note that when the parameter is not set, serial 
   is the default):

       logging=vga,serial,memory

   If vga logging is set, the vga_delay parameter can be used to specify the
   number of seconds to pause after every screenful of output.  It is
   specified as:

       vga_delay=<secs>

   If serial logging is set, the serial port settings can be configured with
   the following parameters:

       serial=<baud>[/<clock_hz>][,<DPS>[,<io-base>[,<irq>[,<serial-bdf> [,<bridge-bdf>]]]]]

   The default values for these are: `serial=115200,8n1,0x3f8`.

-  tboot will attempt to seal the module measurements using the TPM so that if
   it is put into S3 it can restore the correct PCR values on resume.  In order
   for this to work, the TPM must be owned and the SRK auth must be set to all
   0s.  This can be done using the `-z` flag to tpm_takeownership.  If the
   tboot policy being used is 'nonfatal' and the seal operation fails, tboot
   will continue the boot.  However, for 'continue' or 'halt' policy types,
   tboot will halt the boot.

-  tboot provides a better AP wakeup mechanism based on cpu MWAIT feature for
   OS/VMM. This mechanism is defaultly disabled, and could be enabled with
   tboot command line option:

       ap_wake_mwait=true|false

   Once this mechanism is enabled, system will boot faster and will NOT require
   VT to be enabled. But before enabling this option, please make sure the
   OS/VMM has already support it, otherwise system can never boot up. Confirm
   it via finding lines like below in the OS/VMM booting log:

       TBOOT: found shared page at ....
         ...
         flags: 0x0000000x
   
-  tboot support a new PCR usage called Details / Authorities PCR Mapping(DA).
   DA can be enabled by below tboot command line option (note: default is
   legacy):

       pcr_map=da|legacy

   With DA PCR Mapping enabled it separates detailed measurements, stored in
   PCR17, from authorities measurements stored in PCR18.

   "Details" measurements include hashes of all components participating in
   establishing of trusted execution environment and due to very nature of hash
   algorithm change of any component entail change of final PCR17 value.

   "Authorities" measurements include hashes of some unique identifying
   properties of signing authorities such as public signature verification
   keys. This enables authority issue an update of component without affecting
   of final PCR18 value, because updated component is signed in the same way as
   old one.

-  Previously tboot tried to avoid including any reserved e820 region (in 1M
   ~4GB) into PMR low region to avoid possible SMM hang. So all e820 RAM regions
   after the first reserved one(above 1MB) will be discarded. It was found that
   some platforms reserve low memory regions to mitigate some hardware issues.
   Including such kind of reserved e820 regions into PMR low region does not
   cause SMM hang.

   Below tboot command line option can be used to mitigate the cases that large
   amount of RAM(sometime > 3GB) marked as reserved(discarded from OS/VMM usable
   RAM size) by tboot because some reserved e820 regions occurred in very low
   memory(notes: default is 0, means no mitigation for unwanted memory losing):

       min_ram=0xXXXXXXXX

   During 1MB~4GB, only the first RAM region with size less than <min_ram> byte
   and all following RAM regions will be discarded. The min_ram option gives a
   way to do fine-grain tuning on specific platforms. A suggested practical
   value for min_ram is 32M(0x2000000).

-  Tboot provides support to launch Revocation ACM (RACM) to revoke old buggy
   SINIT version if following command line option is used (default value is
   false):

       call_racm=true|false|check

   RACM is also loaded into memory via bootload like grub or syslinux, and is
   launched with getsec[ENTERACCS] instruction. Below is a example GRUB entry
   for RACM launch:

       title RACM Launch
           root (hd0,1)
           kernel /tboot.gz logging=serial,vga,memory call_racm=true
           module /racm.bin

   Tboot will always warm reset platform after RACM was launched & executed.
   Whether RACM launch has succeeded or not could be checked via doing a tboot
   launch with "call_racm=check" right after the warm reset. This tboot launch
   will end with halt right after the RACM launch result was output, and the
   system need manually reset.

-  Tboot support EFI boot via grub2 multiboot2 protocol. 

   In Fedora 18/19, the OS should be installed and booted in EFI mode first,
   then:
    - Under tboot code root folder: `make; make install`
    - Copy appropriate SINIT for platform into /boot.
    - Run: `grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg`
    - Create directory /boot/efi/EFI/fedora/x86_64-efi, and copy
      multiboot2.mod and relocator.mod from /usr/lib/grub/x86_64-efi into it.
    - Reboot to choose tboot grub option for TXT launch.

   In Centos 7, the OS should be installed and booted in EFI mode first,
   then:
    - Under tboot code root folder: make; make install
    - Copy appropriate SINIT for platform into /boot.
    - Run: `grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg`
    - Create directory /boot/efi/EFI/centos/x86_64-efi, and copy
      multiboot2.mod and relocator.mod from /usr/lib/grub/x86_64-efi into it.
    - If there aren't multiboot2.mod and relocator.mod in directory /usr/lib/grub/x86_64-efi,
      run: `yum install grub2-efi-modules`
    - Reboot to choose tboot grub option for TXT launch.

   Linux launch works already. Xen for trad BIOS still work and Xen EFI is not
   going to work until we can get a version with Daniel Kiper's multiboot2
   changes in it -- and then we'll need to make some trivial changes to the
   20_xen_tboot file. Grub2 is required for all of this.

-  Tboot support TPM NV measuring via extended Verified Launch Tboot Policy.
   This works only for TPM1.2 by far. TPM NV measuring is default disabled,
   need below cmdline option to enable:

       measure_nv=true

   When NV measuring is enabled, it will get all NV measuring policy entry from
   the tboot policy structure. Every NV policy entry will specify:

       nv_index: TPM NV index to measure and verify
       pcr:      PCR to be extended with the NV measurement
       mod_num:  Tell how to measure the nv
         = TB_POL_MOD_NUM_NV: hash then extend, no size limitation on NV index
         = TB_POL_MOD_NUM_NV_RAW: extend w/o hash, size should equal hash size
       hash_type:
         = any: no verification needed
         = image: need verify per hashs list.
       hashs:    hash list. optional.

   There is one default NV policy entry, which will try to read NV 0x40000010
   and extend it into pcr 22 without hashing. The nv_index to be measured must
   be defined with OWNERWRITE permission, otherwise the verification will fail,
   and nothing will be extended into pcr.

-  Tboot provides support to TPM2 module, and following command line option is
   used to select TPM2 extend policy.

       extpol=agile|embedded|sha1|sha256|sm3|...

   When "agile" policy is selected, ACM will use specific TPM2 commands to compute
   hashes and extend all existing PCR banks at the expense of possible
   performance loss.

   For "embedded" policy, ACM will use algorithms supported by tboot to compute
   hashes and then will use TPM2_PCR_Extend commands to extend them into PCRs.
   If PCRs utilizing hash algorithms not supported by SW are discovered, they
   will be capped with "1" value. This policy when selected will ensure maximum
   possible performance at the expense of possible capping of some of the PCRs.

   Other policy, like "sha1", "sha256", etc., only represent one single algorithm.
   It means tboot will use this algorithm to compute hash and use TPM2_PCR_Extend
   to extend it into PCRs.

-  Recovering from measured launch failures.
   When there's an error during SENTER, the system usually reboots.
   Since the underlying cause is some sort of configuration error, the system can 
   end up in a loop rebooting endlessly after each attempted measured launch. In 
   some environments it make more sense to fall back to booting the kernel directly 
   so that the system comes up and is remotely accessible. After that the issue can 
   be diagnosed and the system power-cycled to clear the error. To enable this 
   behavior, a command line option can be used:

         ignore_prev_err=false|true  // defaults to true

   The option defaults to true, which preserves the original behavior i.e. try a 
   measured launch even if the previous measured launch had errors.
   Setting the value to false will check if the previous measured launch was 
   successful by inspecting the TXT.ERRORCODE value. If measured launch failed,
   tboot will launch the kernel directly without trying to perform a measured launch.

   Note: TXT.ERRORCODE is only cleared if the system is power cycled. A reboot is not
   sufficient to clear the error code.

-  Force TPM2 legacy log format.
   Some SINITs have a bug where they don't extend the MLE hash to the event log.
   This makes it impossible to verify the measurement chain for PCR 17. However,
   if we force them to use the legacy (not TCG standardized) TPM2 log format,
   the SINITs in question log all the inputs to PCR 17 to the event log. This
   setting provides a way to force use of the legacy log format for TPM 2 systems:

        force_tpm2_legacy_log=false|true  // defaults to false

-  Opt-in the vtd dmar table save/restore process
   With recent kernel (4.16.3 in fedora28), the acpi table seems changed by
   kernel. So function restore_vtd_dmar_table() will not work as expected to
   find the vtd dmar table and restore it in S3 resume, instead, the system will
   run into a hang or a reset. To solve the S3 issue but still keep vtd dmar
   table save/restore process for specific case, add below option:

       save_vtd=false|true  // defaults to false
 
PCR Usage
---------
- Legacy PCR mapping

  - PCR 17 : It will be extended with the following values (in this order):
       -  The values as documented in the MLE Developers Manual
       -  SHA-1 hash of:  tboot policy control value (4 bytes) |
                          SHA-1 hash of tboot policy (20 bytes)
          : where the hash of the tboot policy will be 0s if
            TB_POLCTL_EXTEND_PCR17 is clear
  - PCR 18 : It will be extended with the following values (in this order):
       -  SHA-1 hash of tboot (as calculated by lcp_mlehash)
       -  SHA-1 hash of first module in grub.conf (e.g. Xen or Linux kernel)
  - PCR * : tboot policy may specify modules' measurements to be extended into
        PCRs specified in the policy 
  - The default tboot policy will extend, in order, the SHA-1 hashes of all
   modules (other than 0) into PCR 19.

- Details / Authorities PCR Mapping(DA)

  - PCR 17 (Details) - It will be extended with the following values (in this order):
       -  The values as documented in the MLE Developers Manual
       -  SHA-1 hash of: tboot policy control value (4 bytes) |
                         SHA-1 hash of tboot policy (20 bytes)
          ; where the hash of the tboot policy will be 0s if
            TB_POLCTL_EXTEND_PCR17 is clear
       -  SHA-1 hash of first module in grub.conf (e.g. Xen or Linux kernel)
  - PCR 18 (Authorities) - It will be extended with the following values (in this order):
      -  The values as documented in the MLE Developers Manual
      -  SHA-1 hash of: tboot policy control value (4 bytes) |
                        SHA-1 hash of tboot policy (20 bytes)
         ; where the hash of the tboot policy will be 0s if
           TB_POLCTL_EXTEND_PCR17 is clear
  - PCR * - tboot policy may specify modules' measurements to be extended into
        PCRs specified in the policy
  - The default tboot policy will extend, in order, the SHA-1 hashes of all
   modules (other than 0) into PCR 17.


PE signature support
--------------------

TBOOT, starting from version 2.0.0, allows to sign its binary in the same way as
defined in UEFI Secure Boot specs. There is a special output file - tboot.mb2
that is a TBOOT binary with PE header. This file can be loaded by GRUB2 using
multiboot2 protocol in the same way as tboot.gz file. It is not possible to run
it directly from UEFI.

GRUB2, from version 2.05, does not allow to run unsigned binaries via multiboot
protocol if it was loaded by SHIM. That's why the only way to use TBOOT when
UEFI Secure Boot is enabled is to use signed tboot.mb2 file. To create the
signature standard signing tools can be used:

    sbsign --key my.key --cert my.crt tboot.mb2