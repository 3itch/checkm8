                     __               __             _______ 
               .----|  |--.-----.----|  |--.--------|   _   |
               |  __|     |  -__|  __|    <|        |.  |   |
               |____|__|__|_____|____|__|__|__|__|__|.  _   |
                                                    |:  1   |
                                                    |::.. . |
                                                    `-------'
                    Intel TXT hash integrity check
                     bypassing via TBoot patching



### CHECKM8 ### -----------------------------------------------------==========
                
                ┌────────────────────────────────────────────┐
                │   1.0 Introduction                         │
                └────────────────────────────────────────────┘


        Abstract--Intel TXT has a plethora of security features that 
    prevent against malicious attacks, but one stood out to me the most.
        This is of course the hash integrity checking logic.
        Intel seems to think that a bool function was appropriate
    for handling the integrity checking logic...

        Today we'll dig into the `verify_integrity()` function among
    others that Intel's TBoot uses for integrity checking and why they're 
    not very efficient and how they can easily be exploited.
                
                
                ┌────────────────────────────────────────────┐
                │   2.0 TBoot                                │
                └────────────────────────────────────────────┘


        TBoot ( Trusted Boot ) is a bootloader developed by Intel for
    use with the Intel TXT ( Trusted Execution Technology ) environment.
        It enables several security features Intel TXT uses  like:

        - Isolated, trusted execution environment
            ( the Intel TEE itself )
        - Authenticated code modules
            ( intel digitally signed modules like the
            SINIT ACM which provides core instructions )
        - Integrity checking
            ( software-defined ( TBoot ) hash integrity checking )

        Intel implements TBoot so it verifies the hashes integrity through
    TPM ( Trusted Platform Module ) reads.
        This allows Intel TXT to peer into integrity violations, and can easily
    track and prevent such.

        Intel TXT passes an MLE ( Measured Launch Environment ) to TBoot through 
    the `GETSEC[SENTER]` instruction, which initiates the MLE.

        It's important to note that:

        - Intel TXT does no post-boot integrity checks of TBoot when the MLE
    is passed to it.
        - Intel TXT does however, implement pre-boot checks before it passes the MLE.

        So we implement CheckM8 to modify TBoot when the MLE is passed 
    to it / post-boot. Which means we aren't subject to to integrity violations.

                
                ┌────────────────────────────────────────────┐
                │   2.1 TBoot implementation                 │
                └────────────────────────────────────────────┘


        TBoots implementation for hash integrity checking is as follows:

            ```tboot/tboot/common/integrity.c
                bool verify_integrity(void) {
                    ...
    
                    /*  verify mem integrity against measured value  */
                    vmac_t mac;
                    if ( !measure_memory_integrity(&mac, secrets.mac_key) )
                        goto error;
                    if ( memcmp(&mac, &g_post_k_s3_state.kernel_integ, sizeof(mac)) ) {
                        printk(TBOOT_INFO"memory integrity lost on S3 resume\n");
                        printk(TBOOT_DETA"MAC of current image is: ");
                        print_hex(NULL, &mac, sizeof(mac));
                        printk(TBOOT_DETA"MAC of pre-S3 image is: ");
                        print_hex(NULL, &g_post_k_s3_state.kernel_integ,
                                  sizeof(g_post_k_s3_state.kernel_integ));
                        goto error;
                    }
                    printk(TBOOT_INFO"memory integrity OK\n");
                    ...
                }
            ```

        Here TBoot previously computes and then compares the hash against the
    measured/sealed hash inside of the TPM PCRn register.
                                        (n == PCR1..21)

                
                ┌────────────────────────────────────────────┐
                │   3.0 Realisation                          │
                └────────────────────────────────────────────┘


        Maybe you're thinking: " Can't we just modify the instruction that
    launches the MLE??? ".
        The simple answer is no. we cannot. we can however directly modify the
    software-defined functions in TBoot via patching using firmware on the side.
                                                        ( like our oprom firmware )

        Complete rest l8r... ZzzZzZZzz


                ┌────────────────────────────────────────────┐
                │   4.0 How to use?                          │
                └────────────────────────────────────────────┘

        Ok so you want to know how to use it? well i'll walk you through
    it in just a moment.
        First we need to go over some pre-requisites:

        - coreboot 24.12 ( latest version ) which is in this repository
            already: `coreboot/`
        - tboot   1.11.9 ( latest version ) which is also in this repository
            already: `tboot/`
        - the SINIT ACM module specific to your host processor.
            - To see this you will need to run `lscpu` or `cat /proc/cpuinfo`
                to see what model your processor is.
            - You can find the appropriate SINIT ACM module here:
                https://cdrdv2.intel.com/v1/dl/getContent/630744?explicitVersion=true
            - Then unzip the downloaded file and you should see something like:

              ```
                ../acms ( what i called the folder )
                ├── 630744_ACM_Platform_List_004.pdf
                ├── ADL_SINIT_v1_18_18_20240523_REL_NT_O1.PW_signed.bin           //  Alder  Lake
                ├── CFL_SINIT_20221220_PRODUCTION_REL_NT_O1_1.10.1_signed.bin     //  Coffee Lake
                ├── CML_S_SINIT_1_13_33_REL_NT_O1.PW_signed.bin                   //  Comet  Lake
                ├── CMLSTGP_SINIT_v1_14_46_20220819_REL_NT_O1.PW_signed.bin       //  Comet  Lake
                ├── 'Legal Disclaimer.pdf'
                ├── LNC_SINIT_REL_NT_O1.PW_signed.bin                             //  Lincroft
                ├── MTL_SINIT_REL_NT_O1.PW_signed.bin                             //  Meteor Lake
                ├── SKL_KBL_AML_SINIT_20211019_PRODUCTION_REL_NT_O1_1.10.0.bin    //  Sky Lake  / Kaby Lake  / Amber Lake
                ├── RKLS_SINIT_v1_14_46_20220819_REL_NT_O1.PW_signed.bin          //  Rocket Lake
                └── TGL_SINIT_v1_14_46_20220819_REL_NT_O1.PW_signed.bin           //  Tiger  Lake
              ```

              Pick the one your host processor matches the name of

        - GCC i386-elf toolchain

        coreboot config:

            - `sudo apt install build-essential git qemu-system-x86 libncurses-dev iasl flex bison`
                                                    ( to build coreboot and run qemu )
            - tar -xzvf patch_test.tar.gz
                cd patch_test

            - `cd coreboot/`
            - `cp ../coreboot.config .config`
            - `make menuconfig` ( in coreboot/ )
                Configure:

                - Chipset > SINIT ACM ( should point to the ACM .bin file
                                        f.eg RKLS_SINIT_v1_14_46_20220819_REL_NT_O1.PW_signed.bin )
                - Payload > payload path ( set to `../shim.bin` )
                - CBFS > files in CBFS ( should list tboot.gz ( ../tboot.gz ) | type should be raw )

                Save & Exit

            - `make`

            then you'll see build/coreboot.rom get generated.

            go back to the checkm8 root directory `cd ..`

        qemu config:

            we can now begin making our qemu qcow2 disk

            - `qemu-img create -f qcow2 disk.img 1G`

            attempt to run qemu.

            NOTE:   if KVM is supported append `-enable-kvm` for better performance..

            - `qemu-system-x86_64 -bios coreboot/build/coreboot.rom -hda disk.img -machine q35 -cpu Skylake-Client -m 2048
               -serial file:serial.log -nographic`

        success???:

            wait like a minute or two, then close qemu.
            then you can check the serial.log dump file generated.

            - `cat serial.log`

            look for something like:

                ```
                    checkmate:  shim running post-SINIT
                    checkmate:  tboot loaded @ 0x1000000
                    checkmate:      patching verify_integrity @ 0x1080af10
                    checkmate:         patched!
                    checkmate:  jumping to tboot entry
                ```

            if it works zip this & send to me,  or you can just screenshot :).
            if it doesn't put out an issue or PR.
                or just DM me on discord:   .rydr_