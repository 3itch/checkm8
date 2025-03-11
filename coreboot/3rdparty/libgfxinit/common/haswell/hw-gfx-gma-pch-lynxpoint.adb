--
-- Copyright (C) 2020 Angel Pons <th3fanbus@gmail.com>
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

with HW.GFX.GMA.Config;
with HW.GFX.GMA.Registers;
with HW.GFX.GMA.PCH.Sideband;

with HW.Debug;
with GNAT.Source_Info;

package body HW.GFX.GMA.PCH.Lynxpoint is

   FDI_MPHY_IOSFSB_RESET_CTL     : constant := 1 * 2 ** 12;
   FDI_MPHY_IOSFSB_RESET_STATUS  : constant := 1 * 2 ** 13;

   procedure Reset_FDI_mPHY is
   begin
      Registers.Set_Mask
        (Register => Registers.QUIRK_C2004,
         Mask     => FDI_MPHY_IOSFSB_RESET_CTL);

      Registers.Wait_Set_Mask
        (Register => Registers.QUIRK_C2004,
         Mask     => FDI_MPHY_IOSFSB_RESET_STATUS,
         TOut_MS  => 1); -- 100 us

      Registers.Unset_Mask
        (Register => Registers.QUIRK_C2004,
         Mask     => FDI_MPHY_IOSFSB_RESET_CTL);

      Registers.Wait_Unset_Mask
        (Register => Registers.QUIRK_C2004,
         Mask     => FDI_MPHY_IOSFSB_RESET_STATUS,
         TOut_MS  => 1); -- 100 us
   end Reset_FDI_mPHY;

   -- WaMPhyProgramming:hsw
   procedure Program_FDI_mPHY
   is
      use Sideband;
      subtype Bit_Index is Natural range 0 .. Word32'Size - 1;

      procedure mPHY_Update_Field
        (High_Bit : in Bit_Index;
         Low_Bit  : in Bit_Index;
         Value    : in Word32;
         Register : in Register_Type)
      with
         Pre => High_Bit >= Low_Bit
      is
      begin
         Unset_And_Set_Mask
           (Dest       => SBI_MPHY,
            Register   => Register,
            Mask_Unset => 2 ** (High_Bit + 1) - 2 ** Low_Bit,
            Mask_Set   => Value * 2 ** Low_Bit);
      end mPHY_Update_Field;

      procedure mPHY_Update_Lanes
        (High_Bit    : in Bit_Index;
         Low_Bit     : in Bit_Index;
         Value       : in Word32;
         Reg_Lane_0  : in Register_Type;
         Reg_Lane_1  : in Register_Type)
      with
         Pre => High_Bit >= Low_Bit
      is
      begin
         mPHY_Update_Field (High_Bit, Low_Bit, Value, Reg_Lane_0);
         mPHY_Update_Field (High_Bit, Low_Bit, Value, Reg_Lane_1);
      end mPHY_Update_Lanes;
   begin
      mPHY_Update_Field (31, 24, 16#12#, SBI_MPHY_8008);
      mPHY_Update_Lanes (11, 11,      1, SBI_MPHY_2008, SBI_MPHY_2108);
      mPHY_Update_Lanes (24, 24,      1, SBI_MPHY_206C, SBI_MPHY_216C);
      mPHY_Update_Lanes (21, 21,      1, SBI_MPHY_206C, SBI_MPHY_216C);
      mPHY_Update_Lanes (18, 18,      1, SBI_MPHY_206C, SBI_MPHY_216C);
      mPHY_Update_Lanes (15, 13, 16#05#, SBI_MPHY_2080, SBI_MPHY_2180);
      mPHY_Update_Lanes ( 7,  0, 16#1c#, SBI_MPHY_208C, SBI_MPHY_218C);
      mPHY_Update_Lanes (23, 16, 16#1c#, SBI_MPHY_2098, SBI_MPHY_2198);
      mPHY_Update_Lanes (27, 27,      1, SBI_MPHY_20C4, SBI_MPHY_21C4);
      mPHY_Update_Lanes (31, 28, 16#04#, SBI_MPHY_20EC, SBI_MPHY_21EC);
   end Program_FDI_mPHY;

   ----------------------------------------------------------------------------

   SBI_SSCCTL_DISABLE               : constant := 1 * 2 **  0;
   SBI_SSCCTL_PATHALT               : constant := 1 * 2 **  3;
   SBI_GEN0_CFG_BUFFENABLE_DISABLE  : constant := 1 * 2 **  0;

   procedure Enable_Clkout_DP_And_FDI_mPHY is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));

      Sideband.Unset_And_Set_Mask
        (Dest        => Sideband.SBI_ICLK,
         Register    => Sideband.SBI_SSCCTL,
         Mask_Unset  => SBI_SSCCTL_DISABLE,
         Mask_Set    => SBI_SSCCTL_PATHALT);

      Time.U_Delay (24);

      Sideband.Unset_Mask
        (Dest     => Sideband.SBI_ICLK,
         Register => Sideband.SBI_SSCCTL,
         Mask     => SBI_SSCCTL_PATHALT);

      Reset_FDI_mPHY;
      Program_FDI_mPHY;

      Sideband.Set_Mask
        (Dest     => Sideband.SBI_ICLK,
         Register => (if Config.Is_LP then Sideband.SBI_GEN0 else Sideband.SBI_DBUFF0),
         Mask     => SBI_GEN0_CFG_BUFFENABLE_DISABLE);
   end Enable_Clkout_DP_And_FDI_mPHY;

   procedure Disable_Clkout_DP
   is
      function Is_Mask_Set (Value, Mask : Word32) return Boolean is
        ((Value and Mask) = Mask);
      SSC_Ctl  : Word32;
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));

      Sideband.Unset_Mask
        (Dest     => Sideband.SBI_ICLK,
         Register => (if Config.Is_LP then Sideband.SBI_GEN0 else Sideband.SBI_DBUFF0),
         Mask     => SBI_GEN0_CFG_BUFFENABLE_DISABLE);

      Sideband.Read
        (Dest     => Sideband.SBI_ICLK,
         Register => Sideband.SBI_SSCCTL,
         Value    => SSC_Ctl);

      if not Is_Mask_Set (SSC_Ctl, SBI_SSCCTL_DISABLE) then
         if not Is_Mask_Set (SSC_Ctl, SBI_SSCCTL_PATHALT) then
            Sideband.Set_Mask
              (Dest     => Sideband.SBI_ICLK,
               Register => Sideband.SBI_SSCCTL,
               Mask     => SBI_SSCCTL_PATHALT);
            Time.U_Delay (32);
         end if;
         Sideband.Set_Mask
           (Dest     => Sideband.SBI_ICLK,
            Register => Sideband.SBI_SSCCTL,
            Mask     => SBI_SSCCTL_DISABLE);
      end if;
   end Disable_Clkout_DP;

   procedure Unbend_Clkout_DP is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));

      Sideband.Write
        (Dest     => Sideband.SBI_ICLK,
         Register => Sideband.SBI_SSCDITHPHASE,
         Value    => 0);

      Sideband.Unset_And_Set_Mask
        (Dest        => Sideband.SBI_ICLK,
         Register    => Sideband.SBI_SSCDIVINTPHASE,
         Mask_Unset  => 16#ffff#,
         Mask_Set    => 16#0025#);
   end Unbend_Clkout_DP;

end HW.GFX.GMA.PCH.Lynxpoint;
