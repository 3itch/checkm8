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

with HW.GFX.GMA.Registers;

package body HW.GFX.GMA.PCH.Sideband is

   SBI_CTL_DEST_ICLK : constant := 0 * 2 ** 16;
   SBI_CTL_DEST_MPHY : constant := 1 * 2 ** 16;
   SBI_CTL_OP_IORD   : constant := 2 * 2 **  8;
   SBI_CTL_OP_IOWR   : constant := 3 * 2 **  8;
   SBI_CTL_OP_CRRD   : constant := 6 * 2 **  8;
   SBI_CTL_OP_CRWR   : constant := 7 * 2 **  8;

   SBI_RESPONSE_FAIL : constant := 1 * 2 **  1;
   SBI_BUSY          : constant := 1 * 2 **  0;

   type Register_Array is array (Register_Type) of Word32;
   Register_Addr : constant Register_Array := Register_Array'
     (SBI_SSCDIVINTPHASE   => 16#0200_0000#,
      SBI_SSCDITHPHASE     => 16#0204_0000#,
      SBI_SSCCTL           => 16#020c_0000#,
      SBI_SSCDIVINTPHASE6  => 16#0600_0000#,
      SBI_SSCCTL6          => 16#060c_0000#,
      SBI_SSCAUXDIV        => 16#0610_0000#,
      SBI_GEN0             => 16#1f00_0000#,
      SBI_DBUFF0           => 16#2a00_0000#,

      SBI_MPHY_2008        => 16#2008_0000#,
      SBI_MPHY_206C        => 16#206c_0000#,
      SBI_MPHY_2080        => 16#2080_0000#,
      SBI_MPHY_208C        => 16#208c_0000#,
      SBI_MPHY_2098        => 16#2098_0000#,
      SBI_MPHY_20C4        => 16#20c4_0000#,
      SBI_MPHY_20EC        => 16#20ec_0000#,
      SBI_MPHY_2108        => 16#2108_0000#,
      SBI_MPHY_216C        => 16#216c_0000#,
      SBI_MPHY_2180        => 16#2180_0000#,
      SBI_MPHY_218C        => 16#218c_0000#,
      SBI_MPHY_2198        => 16#2198_0000#,
      SBI_MPHY_21C4        => 16#21c4_0000#,
      SBI_MPHY_21EC        => 16#21ec_0000#,
      SBI_MPHY_8008        => 16#8008_0000#);

   ----------------------------------------------------------------------------

   procedure Read
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Value    :    out Word32)
   is
   begin
      Registers.Wait_Unset_Mask
        (Register => Registers.SBI_CTL_STAT,
         Mask     => SBI_BUSY);

      Registers.Write
        (Register => Registers.SBI_ADDR,
         Value    => Register_Addr (Register));

      if Dest = SBI_ICLK then
         Registers.Write
           (Register => Registers.SBI_CTL_STAT,
            Value    => SBI_CTL_DEST_ICLK or SBI_CTL_OP_CRRD or SBI_BUSY);
      else
         Registers.Write
           (Register => Registers.SBI_CTL_STAT,
            Value    => SBI_CTL_DEST_MPHY or SBI_CTL_OP_IORD or SBI_BUSY);
      end if;

      Registers.Wait_Unset_Mask
        (Register => Registers.SBI_CTL_STAT,
         Mask     => SBI_BUSY);

      Registers.Read
        (Register => Registers.SBI_DATA,
         Value    => Value);
   end Read;

   procedure Write
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Value    : in     Word32)
   is
   begin
      Registers.Wait_Unset_Mask
        (Register => Registers.SBI_CTL_STAT,
         Mask     => SBI_BUSY);

      Registers.Write
        (Register => Registers.SBI_ADDR,
         Value    => Register_Addr (Register));
      Registers.Write
        (Register => Registers.SBI_DATA,
         Value    => Value);

      if Dest = SBI_ICLK then
         Registers.Write
           (Register => Registers.SBI_CTL_STAT,
            Value    => SBI_CTL_DEST_ICLK or SBI_CTL_OP_CRWR or SBI_BUSY);
      else
         Registers.Write
           (Register => Registers.SBI_CTL_STAT,
            Value    => SBI_CTL_DEST_MPHY or SBI_CTL_OP_IOWR or SBI_BUSY);
      end if;

      Registers.Wait_Unset_Mask
        (Register => Registers.SBI_CTL_STAT,
         Mask     => SBI_BUSY);
   end Write;

   ----------------------------------------------------------------------------

   procedure Unset_Mask
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Mask     : in     Word32)
   is
      Value : Word32;
   begin
      Read (Dest, Register, Value);
      Write (Dest, Register, Value and not Mask);
   end Unset_Mask;

   procedure Set_Mask
     (Dest     : in     Destination_Type;
      Register : in     Register_Type;
      Mask     : in     Word32)
   is
      Value : Word32;
   begin
      Read (Dest, Register, Value);
      Write (Dest, Register, Value or Mask);
   end Set_Mask;

   procedure Unset_And_Set_Mask
     (Dest        : in     Destination_Type;
      Register    : in     Register_Type;
      Mask_Unset  : in     Word32;
      Mask_Set    : in     Word32)
   is
      Value : Word32;
   begin
      Read (Dest, Register, Value);
      Write (Dest, Register, (Value and not Mask_Unset) or Mask_Set);
   end Unset_And_Set_Mask;

end HW.GFX.GMA.PCH.Sideband;
