Execution flow for TBOOT
========================

General flow
============

Diagrams below describes general flow of 4 possible use scenarios:

<table>
<tr>
    <td>
        @startuml Boot flow
        :GRUB;
        :TBOOT (pre-SINIT);
        :SINIT;
        :TBOOT (post-SINIT);
        :Linux;
        @enduml
    </td>
    <td>
        @startuml Shutdown flow
        :Linux;
        :TBOOT (shutdown);
        :shutdown;
        @enduml
    </td>
    <td>
        @startuml S3 enter
        :Linux;
        :TBOOT (shudown);
        :enter sleep;
        @enduml
    </td>
    <td>
        @startuml S3 exit
        :exit sleep;
        :TBOOT (pre-SINIT);
        :SINIT;
        :TBOOT (post-SINIT);
        :Linux;
        @enduml
    </td>
</tr>
</table>

S3 sleep/wakeup and standard launch/shutdown are very similar from general
perspective, main differences are entry points for jumping to Linux kernel. For
detailed description what is going on in each scenario please look at next
sections.

Platform launch
===============

In general there are few steps that TBOOT has to do during platform launch:
  - check if platform is TXT capable
  - load SINIT
  - prepare and launch SINIT
  - measure modules described in policy
  - launch kernel

A more complex description of each step is shown below.

@startuml
!include launch.plantuml
@enduml

TBOOT entry point for pre-SINIT and post-SINIT launch is the same, so in early
step there is a detection if SINIT was launched or not and there are two
branches that handle each scenario. Red arrow indicates error flow which depends
on policy, there are few possibilities:
  - boot Linux in non-trusted environment
  - halt platform
  - reboot platform

To not make diagram too complex few blocks are described in details in following
sections

Load SINIT
----------

This step is first point where we checks if platform has any chance to perform
measured boot. SINIT is mandatory module for Intel TXT, it is distributed as
binary and can be either loaded by GRUB and passed to TBOOT via MBI or (only in
server platforms) included in BIOS binary. If there is no SINIT, that matches
current platform, provided we can stop measured boot execution at this step.

@startuml
!include load_sinit.plantuml
@enduml

TBOOT always takes newer SINIT, there can be multiple entries in MBI and one in
BIOS. If both MBI and BIOS has exactly the same SINIT version, one from BIOS is
taken.

Prepare for SINIT launch
------------------------

There a few requirements for platform state before GETSEC[SENTER] can be called:
  - CPU has to be in protected mode
  - cache must be enabled
  - native FPU error reporting must be enabled
  - cannot be in virtual-8086 mode

TBOOT also has to configure MTRRs and VT-d to be compliant wth MLE developers
guide, in other case SINIT will detect wrong configuration and invoke LT-reset.

Handle post-launch
------------------

When SINIT finished its job it returns back to TBOOT and post-SINIT code branch
is executed. There few operations that are done just after returning from SINIT:
  - verify TXT heap structures
  - verify saved MTRRs
  - verify PMRs
  - wakeup RLPs
  - restore MTRRs
  - set TXT.CMD.SECRETS flag
  - open locality 1

Platform shutdown
=================

If Linux is launched inside measured environment, the last step in shutdown/S3
procedure will be jumping to TBOOT shutdown entry point to properly tear down
environment and wipe secrets from memory. Shutdown flow in TBOOT is shown below:

@startuml
!include shutdown.plantuml
@enduml

As all CPUs are jumping to TBOOT's shutdown entry, it has to filter-out all APs
and continue work only on BSP. One of the important step is to call
GETSEC[SEXIT] to exit measured environment. Before executing that instruction,
TBOOT has to:
  - clear SECRETS flag
  - unlock memory configuration
  - close TXT private config space (implicitly closes TPM localities 1 + 2)
  - disable SMXE

After GETSEC[SEXIT] TBOOT can proceed to finish shutdown process.