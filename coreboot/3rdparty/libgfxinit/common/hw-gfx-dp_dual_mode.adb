--
-- Copyright (C) 2021 Angel Pons <th3fanbus@gmail.com>
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

with HW.Debug;
with HW.Time;
with GNAT.Source_Info;

with HW.GFX.DP_Defs;
with HW.GFX.I2C;

use type HW.Word8;

package body HW.GFX.DP_Dual_Mode is

   DUAL_MODE_I2C_ADDR   : constant := 16#40#;

   DUAL_MODE_ADAPTOR_ID : constant := 16#10#;
   LSPCON_MODE_CHANGE   : constant := 16#40#;
   LSPCON_CURRENT_MODE  : constant := 16#41#;

   LSPCON_MODE_LS       : constant := 0;
   LSPCON_MODE_PCON     : constant := 1;

   procedure Read_LSPCON_Mode
     (Port     : in     T;
      Mode     :    out Word8;
      Success  :    out Boolean)
   is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
      for I in 1 .. 6 loop
         Aux_Ch.I2C_Read_Byte
           (Port     => Port,
            Address  => DUAL_MODE_I2C_ADDR,
            Offset   => LSPCON_CURRENT_MODE,
            Value    => Mode,
            Success  => Success);
         exit when Success;
         Time.U_Delay (500);
      end loop;
   end Read_LSPCON_Mode;

   procedure Write_LSPCON_Mode
     (Port     : in     T;
      Mode     : in     Word8;
      Success  :    out Boolean)
   is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
      for I in 1 .. 6 loop
         Aux_Ch.I2C_Write_Byte
           (Port     => Port,
            Address  => DUAL_MODE_I2C_ADDR,
            Offset   => LSPCON_MODE_CHANGE,
            Value    => Mode,
            Success  => Success);
         exit when Success;
         Time.U_Delay (500);
      end loop;
   end Write_LSPCON_Mode;

   pragma Warnings
     (GNATprove, Off, "subprogram ""Dump_LSPCON_Mode"" has no effect",
      Reason => "It's only used for debugging");
   procedure Dump_LSPCON_Mode (Mode : in Word8)
   is
   begin
      pragma Debug (Debug.Put ("Current LSPCON mode: "));
      case Mode is
         when LSPCON_MODE_LS     => pragma Debug (Debug.Put_Line ("Level Shifter"));
         when LSPCON_MODE_PCON   => pragma Debug (Debug.Put_Line ("Protocol Converter"));
         when others             =>
            pragma Debug (Debug.Put ("Unknown ("));
            pragma Debug (Debug.Put_Word8 (Mode));
            pragma Debug (Debug.Put_Line (")"));
      end case;
   end Dump_LSPCON_Mode;

   procedure Auto_Configure_LSPCON (Port : in T)
   is
      Wanted_Mode : constant Word8 := LSPCON_MODE_PCON;
      Timeout : Time.T;
      Timed_Out : Boolean;
      Success : Boolean;
      Mode : Word8;
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));

      Read_LSPCON_Mode (Port, Mode, Success);

      if not Success then
         pragma Debug (Debug.Put_Line ("Could not determine LSPCON mode."));
         return;
      end if;

      Dump_LSPCON_Mode (Mode);

      if Mode = Wanted_Mode then
         pragma Debug (Debug.Put_Line ("LSPCON mode is good enough."));
         return;
      end if;

      -- Change to PCON mode if necessary
      Write_LSPCON_Mode (Port, Wanted_Mode, Success);

      if not Success then
         pragma Debug (Debug.Put_Line ("Could not write new LSPCON mode."));
         return;
      end if;

      Timeout := Time.MS_From_Now (2000);
      loop
         Read_LSPCON_Mode (Port, Mode, Success);

         if not Success then
            pragma Debug (Debug.Put_Line ("Could not confirm LSPCON mode change."));
            return;
         end if;

         if Mode = Wanted_Mode then
            pragma Debug (Debug.Put_Line ("Successfully set LSPCON to PCON mode."));
            return;
         end if;

         Timed_Out := Time.Timed_Out (Timeout);
         exit when Timed_Out;
      end loop;

      pragma Debug (Debug.Put_Line ("Timed out waiting for LSPCON mode change."));
      Dump_LSPCON_Mode (Mode);
   end Auto_Configure_LSPCON;

   subtype HDMI_ID_Index is Natural range 0 .. 15;
   subtype HDMI_ID_Data is Buffer (HDMI_ID_Index);

   procedure Read_Dual_Mode_HDMI_ID
     (Port     : in T;
      HDMI_ID  : out HDMI_ID_Data;
      Success  : out Boolean)
   is
      Length : I2C.Transfer_Length := HDMI_ID'Length;
      Buffer : I2C.Transfer_Data;
   begin
      Aux_Ch.I2C_Read
        (Port     => Port,
         Address  => DUAL_MODE_I2C_ADDR,
         Length   => Length,
         Data     => Buffer,
         Success  => Success);

      Success := Success and then Length = HDMI_ID'Length;
      if Success then
         HDMI_ID := Buffer (HDMI_ID'Range);
      else
         HDMI_ID := HDMI_ID_Data'(others => 0);
      end if;
   end Read_Dual_Mode_HDMI_ID;

   function Is_HDMI_Adaptor (Actual_ID : in HDMI_ID_Data) return Boolean
   is
      -- "DP-HDMI ADAPTOR\x04"
      Expected_ID : constant HDMI_ID_Data :=
        (16#44#, 16#50#, 16#2d#, 16#48#, 16#44#, 16#4d#, 16#49#, 16#20#,
         16#41#, 16#44#, 16#41#, 16#50#, 16#54#, 16#4f#, 16#52#, 16#04#);
   begin
      return Expected_ID = Actual_ID;
   end Is_HDMI_Adaptor;

   procedure Detect_LSPCON (Port : in T; Success : out Boolean)
   is
      HDMI_ID     : HDMI_ID_Data;
      Adaptor_ID  : Word8;
   begin
      Read_Dual_Mode_HDMI_ID (Port, HDMI_ID, Success);
      Success := Success and then Is_HDMI_Adaptor (HDMI_ID);
      if Success then
         Aux_Ch.I2C_Read_Byte
           (Port     => Port,
            Address  => DUAL_MODE_I2C_ADDR,
            Offset   => DUAL_MODE_ADAPTOR_ID,
            Value    => Adaptor_ID,
            Success  => Success);

         Success := Success and then Adaptor_ID = 16#a8#;
      end if;
   end Detect_LSPCON;

   procedure Switch_LSPCON (Port : in T)
   is
      Has_LSPCON : Boolean;
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
      Detect_LSPCON (Port, Has_LSPCON);
      if Has_LSPCON then
         Auto_Configure_LSPCON (Port);
      end if;
   end Switch_LSPCON;

end HW.GFX.DP_Dual_Mode;
