/* SPDX-License-Identifier: GPL-2.0-only */

#include <option.h>
#include <soc/ramstage.h>

void mainboard_silicon_init_params(FSP_S_CONFIG *supd)
{
	/*
	 * FSP defaults to pins that are used for LPC; given that
	 * coreboot only supports eSPI, set these pins accordingly.
	 */
	supd->PchSerialIoI2cSdaPinMux[0]	= 0x1947c404;	// GPP_H4
	supd->PchSerialIoI2cSclPinMux[0]	= 0x1947a405;	// GPP_H5
	supd->SataPortDevSlpPinMux[1]		= 0x5967400d;	// GPP_H13

	/*
	 * Enable Hot Plug on RP5 to slow down coreboot so that
	 * third-party drives are detected.
	 */
	if (get_uint_option("pci_hot_plug", 0) == 1)
		supd->PcieRpHotPlug[8] = 1;
}
