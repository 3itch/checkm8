Trusted Boot (TBOOT) is an open source, pre-kernel/VMM module that uses
Intel(R) Trusted Execution Technology (Intel(R) TXT) to perform a measured
and verified launch of an OS kernel/VMM.

This version of tboot supports Intel (both retail and Software Development
Platforms (SDPs)) and OEM systems that are Intel TXT-capable. This version of
tboot only supports both the Xen virtual machine monitor (versions >= 3.4) and
Linux kernel versions >= 2.6.33.

The mercurial source code repository for this project is located at:
http://hg.code.sf.net/p/tboot/code. Updates to the mercurial repository are
automatically sent to the mailing list tboot-changelog@lists.sourceforge.net.

## Overview of Tboot Functionality:

-  **Measured Launch** If the processor is detected as being TXT-capable
   and enabled then the code will attempt to perform a measured launch.  If
   the measured launch process fails (processor is not capable, TXT is not
   enabled, missing SINIT, corrupted data, etc.)) then it will fall-through
   to a non-TXT boot.

-  **Teardown of measured environment** When the system is shutdown, the
   measured environment will be torn down properly. This support S3/S4/S5
   sleep states.

-  **Reset data protection** Intel TXT hardware prevents access to secrets
   if the system is reset without clearing them from memory (as part of a
   TXT teardown).  This code will support this by setting the flag indicating
   that memory should be so protected during the measured launch and clearing
   the flag just before teardown.

-  **Protection of TXT memory ranges** Intel TXT reserves certain regions of
   RAM for its use and also defines several MMIO regions. These regions
   (excluding the TXT public configuration space) are protected from use by
   any domains (including dom0).

-  **Intel TXT Launch Control Policy (LCP) tools** The lcptools project
   contains a set of tools (and basic documentation) that can be used to
   create and provision TXT Launch Control policies.  LCP uses TPM
   non-volatile storage (TPM NV) to hold a launch policy, which the SINIT AC
   module reads and uses to enforce which measured launched environments
   (MLEs) (e.g. tboot) can be launched (based on a SHA-1 hash).  These
   tools require a TPM Software Stack (TSS) that supports the Tspi_NV_* API.
   Versions of the TrouSerS project >0.3.0 support them.

-  **Verified Launch**  Tboot will extend verification from the MLE to the kernel/VMM
   and dom0, using policies similar to the LCP called as Verified Launch Policy 
   and also store the policies in TPM NV.
   These policies can be created and managed by the tb_polgen tool and
   provisioned into TPM NV using the lcptools. For more details, see Verified 
   Launched Policy guide in docs/ directory.


## Instructions for Building:

The trousers sub-project has been removed (it was using an out-of-date
version and was often problematic to build).  Instead, the trousers and
trousers-devel packages must already be installed in order to build the
lcptools sub-project.  Most distributions either provide these packages
by default or optionally; otherwise they can be found on various package
sites and manually installed.

## Using TBOOT
[Link to page] (docs/howto_use.md)

## Execution flow
[Link to page] (docs/tboot_flow.md)

## Interesting Items of Note:

-  A Xen or Linux version that does not support tboot can still be launched by
   tboot, however it will not protect any of the TXT memory nor tboot itself.
   And it will hang on reboot/shutdown.  Aside from this, it will behave
   normally.

-  Tboot will copy and alter the e820 table provided by GRUB to "reserve"
   its own memory plus the TXT memory regions.  These are marked as
   E820_UNUSABLE or E820_RESERVED so that the patched Xen code can prevent
   them from being assigned to dom0.  The e820 table is not altered if the
   measured launch fails for any reason.

-  Tboot is always built 32bit and runs in protected mode without PAE or
   paging enabled.  Tboot loads and executes at 0x1000000 (16MB).

-  The code requires that VT be enabled as well as TXT.  This is because
   the mechanism for bringing up the APs uses VMX to create a mini-VM in
   order to trap on INIT-SIPI-SIPI. If OS/VMM support tboot's new AP wakeup
   mechanism based on MWAIT, then VT is not required to be enabled.

-  The tools/txt-stat project is a Linux application that reads some of
   the TXT registers and will display the tboot boot log if tboot was run
   with 'logging=memory'.


## Contributing to the project:

Contributions to any files in this project require the contributor(s) to
certify the following:

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

If the above can be certified by the contributor(s), then he/they should
include a signed-off-by line along with the changes that indicate this:
    
    Signed-off-by: John Developer <jdev@yoyodyne.org>

