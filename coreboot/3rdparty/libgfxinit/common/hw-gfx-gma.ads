--
-- Copyright (C) 2015-2018 secunet Security Networks AG
-- Copyright (C) 2017 Nico Huber <nico.h@gmx.de>
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

with HW.Config;
with HW.Time;
with HW.PCI;
with HW.Port_IO;
with HW.GFX.Framebuffer_Filler;

use type HW.Word32;

package HW.GFX.GMA
with
   Abstract_State =>
     (State,
      Init_State,
      (Device_State with External)),
   Initializes => Init_State
is

   GTT_Page_Size : constant := 4096;
   type GTT_Address_Type is mod 2 ** 39;
   subtype GTT_Range is Natural range 0 .. 16#8_0000# - 1;
   GTT_Rotation_Offset : constant GTT_Range := GTT_Range'Last / 2 + 1;

   type Generation is (G45, Ironlake, Haswell, Broxton, Skylake, Tigerlake);

   type CPU_Type is
     (G45,
      GM45,
      Ironlake,
      Sandybridge,
      Ivybridge,
      Haswell,
      Broadwell,
      Broxton,
      Skylake,
      Kabylake,
      Tigerlake,
      Alderlake);

   type CPU_Variant is (Normal, ULT, ULX);

   type PCH_Type is
     (No_PCH,
      Ibex_Peak,
      Cougar_Point,     -- Panther Point compatible
      Lynx_Point,       -- Wildcat Point compatible
      Sunrise_Point,    -- Union Point compatible
      Cannon_Point,
      Tiger_Point,
      Alder_Point);

   type Port_Type is
     (Disabled,
      LVDS,
      eDP,
      DP1,
      DP2,
      DP3,
      HDMI1, -- or DVI
      HDMI2, -- or DVI
      HDMI3, -- or DVI
      Analog,
      USBC1_DP,
      USBC2_DP,
      USBC3_DP,
      USBC4_DP,
      USBC5_DP,
      USBC6_DP,
      USBC1_HDMI,
      USBC2_HDMI,
      USBC3_HDMI,
      USBC4_HDMI,
      USBC5_HDMI,
      USBC6_HDMI);
   subtype Active_Port_Type is Port_Type
      range Port_Type'Succ (Disabled) .. Port_Type'Last;
   subtype Internal_Port_Type is Port_Type range LVDS .. eDP;
   subtype Combo_Port_Type is Port_Type range DP1 .. HDMI3;
   subtype USBC_Port_Type is Port_Type range USBC1_DP .. USBC6_HDMI;

   type Cursor_Mode is (No_Cursor, ARGB_Cursor);
   type Cursor_Size is (Cursor_64x64, Cursor_128x128, Cursor_256x256);
   Cursor_Width : constant array (Cursor_Size) of Width_Type := (64, 128, 256);

   subtype Cursor_Pos is Int32 range Int32'First / 2 .. Int32'Last / 2;

   type Cursor_Type is record
      Mode        : Cursor_Mode;
      Size        : Cursor_Size;
      Center_X    : Cursor_Pos;
      Center_Y    : Cursor_Pos;
      GTT_Offset  : GTT_Range;
   end record;
   Default_Cursor : constant Cursor_Type :=
     (Mode        => No_Cursor,
      Size        => Cursor_Size'First,
      Center_X    => 0,
      Center_Y    => 0,
      GTT_Offset  => 0);

   type Pipe_Config is record
      Port        : Port_Type;
      Framebuffer : Framebuffer_Type;
      Cursor      : Cursor_Type;
      Mode        : Mode_Type;
   end record;
   type Pipe_Index is (Primary, Secondary, Tertiary);
   type Pipe_Configs is array (Pipe_Index) of Pipe_Config;

   -- Special framebuffer offset to indicate legacy VGA plane.
   -- Only valid on primary pipe.
   VGA_PLANE_FRAMEBUFFER_OFFSET : constant := 16#ffff_ffff#;

   pragma Warnings (GNATprove, Off, "unused variable ""Write_Delay""",
      Reason => "Write_Delay is used for debugging only");
   procedure Initialize
     (Write_Delay : in     Word64 := 0;
      Clean_State : in     Boolean := False;
      Success     :    out Boolean)
   with
      Global =>
        (In_Out => (Device_State, Port_IO.State),
         Output => (State, Init_State),
         Input  => (Time.State)),
      Post => Success = Is_Initialized;
   function Is_Initialized return Boolean
   with
      Global => (Input => Init_State);
   pragma Warnings (GNATprove, On, "unused variable ""Write_Delay""");

   procedure Power_Up_VGA
   with
      Global =>
        (Input => (State, Time.State),
         In_Out => (Device_State),
         Proof_In => (Init_State)),
      Pre => Is_Initialized;

   ----------------------------------------------------------------------------

   procedure Update_Outputs (Configs : Pipe_Configs)
   with
      Global =>
        (Input => (Time.State),
         In_Out => (State, Device_State, Port_IO.State),
         Proof_In => (Init_State)),
      Pre => Is_Initialized;

   procedure Update_Cursor (Pipe : Pipe_Index; Cursor : Cursor_Type)
   with
      Global =>
        (In_Out => (State, Device_State),
         Proof_In => (Init_State)),
      Pre => Is_Initialized;

   procedure Place_Cursor
     (Pipe : Pipe_Index;
      X : Cursor_Pos;
      Y : Cursor_Pos)
   with
      Global =>
        (In_Out => (State, Device_State),
         Proof_In => (Init_State)),
      Pre => Is_Initialized;

   procedure Move_Cursor
     (Pipe : Pipe_Index;
      X : Cursor_Pos;
      Y : Cursor_Pos)
   with
      Global =>
        (In_Out => (State, Device_State),
         Proof_In => (Init_State)),
      Pre => Is_Initialized;

   ----------------------------------------------------------------------------

   procedure Backlight_On (Port : Active_Port_Type)
   with
      Global => (In_Out => Device_State);

   procedure Backlight_Off (Port : Active_Port_Type)
   with
      Global => (In_Out => Device_State);

   procedure Set_Brightness (Port : Active_Port_Type; Level : Word32)
   with
      Global => (In_Out => Device_State);

   procedure Get_Max_Brightness (Port : Active_Port_Type; Level : out Word32)
   with
      Global => (In_Out => Device_State);

   ----------------------------------------------------------------------------

   procedure Write_GTT
     (GTT_Page       : GTT_Range;
      Device_Address : GTT_Address_Type;
      Valid          : Boolean)
   with
      Global =>
        (Input => State,
         In_Out => Device_State, Proof_In => Init_State),
      Pre => Is_Initialized;

   procedure Read_GTT
     (Device_Address :    out GTT_Address_Type;
      Valid          :    out Boolean;
      GTT_Page       : in     GTT_Range)
   with
      Global =>
        (Input => State,
         In_Out => Device_State, Proof_In => Init_State),
      Pre => Is_Initialized;

   procedure Setup_Default_FB
     (FB       : in     Framebuffer_Type;
      Clear    : in     Boolean := True;
      Success  :    out Boolean)
   with
      Global =>
        (In_Out =>
           (State, Device_State,
            Framebuffer_Filler.State, Framebuffer_Filler.Base_Address),
         Proof_In => (Init_State)),
      Pre => Is_Initialized and HW.Config.Dynamic_MMIO;

   procedure Map_Linear_FB (Linear_FB : out Word64; FB : in Framebuffer_Type)
   with
      Global =>
        (In_Out => (State, Device_State),
         Proof_In => (Init_State)),
      Pre => Is_Initialized and HW.Config.Dynamic_MMIO;

   ----------------------------------------------------------------------------

   pragma Warnings (GNATprove, Off, "subprogram ""Dump_Configs"" has no effect",
                    Reason => "It's only used for debugging");
   procedure Dump_Configs (Configs : Pipe_Configs);

private

   PCI_Usable : Boolean with Part_Of => State;
   use type HW.PCI.Index;
   procedure PCI_Read16 (Value : out Word16; Offset : HW.PCI.Index)
   with
      Pre => PCI_Usable and Offset mod 2 = 0;

   ----------------------------------------------------------------------------

   -- For the default framebuffer setup (see below) with 90 degree rotations,
   -- we expect the offset which is used for the final scanout to be above
   -- `GTT_Rotation_Offset`. So we can use `Offset - GTT_Rotation_Offset` for
   -- the physical memory location and aperture mapping.
   function Phys_Offset (FB : Framebuffer_Type) return Word32 is
     (if Rotation_90 (FB)
      then FB.Offset - Word32 (GTT_Rotation_Offset) * GTT_Page_Size
      else FB.Offset);

   ----------------------------------------------------------------------------
   -- State tracking for the currently configured pipes

   Cur_Configs : Pipe_Configs with Part_Of => State;

   function Requires_Scaling (Pipe_Cfg : Pipe_Config) return Boolean is
     (Requires_Scaling (Pipe_Cfg.Framebuffer, Pipe_Cfg.Mode));

   function Scaling_Type (Pipe_Cfg : Pipe_Config) return Scaling_Aspect is
     (Scaling_Type (Pipe_Cfg.Framebuffer, Pipe_Cfg.Mode));

   ----------------------------------------------------------------------------
   -- Internal representation of a single pipe's configuration

   type GPU_Port is
     (DIGI_A, DIGI_B, DIGI_C, DIGI_D, DIGI_E,
      DDI_TC1, DDI_TC2, DDI_TC3, DDI_TC4, DDI_TC5, DDI_TC6,
      LVDS, VGA);

   subtype Digital_Port is GPU_Port range DIGI_A .. DIGI_E;
   subtype GMCH_DP_Port is GPU_Port range DIGI_B .. DIGI_D;
   subtype GMCH_HDMI_Port is GPU_Port range DIGI_B .. DIGI_C;
   subtype Combo_Port is GPU_Port range DIGI_A .. DIGI_C;
   subtype USBC_Port is GPU_Port range DDI_TC1 .. DDI_TC6;
   subtype TGL_Digital_Port is GPU_Port range DIGI_A .. DDI_TC6;

   function Is_Digital_Port (Port : GPU_Port) return Boolean is
      (Port in Digital_Port or Port in TGL_Digital_Port);

   type PCH_Port is
     (PCH_DAC, PCH_LVDS,
      PCH_HDMI_A, PCH_HDMI_B, PCH_HDMI_C, PCH_HDMI_D,
      PCH_DP_B, PCH_DP_C, PCH_DP_D,
      PCH_TC1, PCH_TC2, PCH_TC3, PCH_TC4, PCH_TC5, PCH_TC6);

   subtype PCH_HDMI_Port is PCH_Port range PCH_HDMI_A .. PCH_HDMI_D;
   subtype PCH_DP_Port is PCH_Port range PCH_DP_B .. PCH_DP_D;
   subtype PCH_TC_Port is PCH_Port range PCH_TC1 .. PCH_TC6;

   type Panel_Control is (No_Panel, Panel_1, Panel_2);
   subtype Valid_Panels is Panel_Control range Panel_1 .. Panel_2;

   type Port_Config is
      record
         Port     : GPU_Port;
         PCH_Port : GMA.PCH_Port;
         Display  : Display_Type;
         Panel    : Panel_Control;
         Mode     : Mode_Type;
         Is_FDI   : Boolean;
         FDI      : DP_Link;
         DP       : DP_Link;
      end record;

   type FDI_Training_Type is (Simple_Training, Full_Training, Auto_Training);

   ----------------------------------------------------------------------------

   type DP_Port is (DP_A, DP_B, DP_C, DP_D, DP_E, DP_F, DP_G, DP_H, DP_I);

   ----------------------------------------------------------------------------

   subtype DDI_HDMI_Buf_Trans_Range is Integer range 0 .. 11;

   ----------------------------------------------------------------------------

   Tile_Width : constant array (Tiling_Type) of Width_Type :=
     (Linear => 16, X_Tiled => 128, Y_Tiled => 32);
   Tile_Rows : constant array (Tiling_Type) of Height_Type :=
     (Linear => 1, X_Tiled => 8, Y_Tiled => 32);

   function FB_Pitch (Px : Pos_Pixel_Type; FB : Framebuffer_Type) return Natural
      is (Natural (Div_Round_Up
           (Pixel_To_Bytes (Px, FB), Tile_Width (FB.Tiling) * 4)));

   function Valid_Stride (FB : Framebuffer_Type) return Boolean is
     (FB.Width + FB.Start_X <= FB.Stride and
      Pixel_To_Bytes (FB.Stride, FB) mod (Tile_Width (FB.Tiling) * 4) = 0 and
      FB.Height + FB.Start_Y <= FB.V_Stride and
      FB.V_Stride mod Tile_Rows (FB.Tiling) = 0);

end HW.GFX.GMA;
