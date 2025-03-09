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
