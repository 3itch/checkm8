--
-- Copyright (C) 2015 secunet Security Networks AG
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--

private package HW.GFX.GMA.PCH.Sideband is

   type Destination_Type is (SBI_ICLK, SBI_MPHY);

   type Register_Type is
     (SBI_SSCDIVINTPHASE,
      SBI_SSCDITHPHASE,
      SBI_SSCCTL,
      SBI_SSCDIVINTPHASE6,
      SBI_SSCCTL6,
      SBI_SSCAUXDIV,
      SBI_GEN0,
      SBI_DBUFF0,

      SBI_MPHY_2008,
      SBI_MPHY_206C,
      SBI_MPHY_2080,
      SBI_MPHY_208C,
      SBI_MPHY_2098,
      SBI_MPHY_20C4,
      SBI_MPHY_20EC,
      SBI_MPHY_2108,
      SBI_MPHY_216C,
      SBI_MPHY_2180,
      SBI_MPHY_218C,
      SBI_MPHY_2198,
      SBI_MPHY_21C4,
      SBI_MPHY_21EC,
      SBI_MPHY_8008);

   procedure Read
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Value    :    out Word32);

   procedure Write
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Value    : in     Word32);

   procedure Unset_Mask
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Mask     : in     Word32);

   procedure Set_Mask
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Mask     : in     Word32);

   procedure Unset_And_Set_Mask
     (Dest        : in     Destination_Type;
      Register    : in     Register_Type;
      Mask_Unset  : in     Word32;
      Mask_Set    : in     Word32);

end HW.GFX.GMA.PCH.Sideband;
