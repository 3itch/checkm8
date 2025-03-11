--
-- Copyright (C) 2015-2016 secunet Security Networks AG
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

with HW.Time;
with HW.GFX.GMA.Registers;

private package HW.GFX.GMA.Panel
with
   Abstract_State => (Panel_State with Part_Of => GMA.State)
is

   procedure Static_Init
   with
      Global =>
        (Output => Panel_State,
         Input  => Time.State);

   procedure Setup_PP_Sequencer (Default_Delays : Boolean := False)
   with
      Global =>
        (In_Out => (Panel_State, Registers.Register_State)),
      Depends =>
        ((Panel_State, Registers.Register_State) =>
           (Panel_State, Registers.Register_State, Default_Delays));

   ----------------------------------------------------------------------------

   procedure VDD_Override (Panel : Panel_Control);

   procedure On (Panel : Panel_Control; Wait : Boolean := True);

   procedure Wait_On (Panel : Panel_Control);

   procedure Off (Panel : Panel_Control);

   ----------------------------------------------------------------------------

   procedure Backlight_On (Panel : Panel_Control);

   procedure Backlight_Off (Panel : Panel_Control);

   procedure Set_Backlight (Panel : Panel_Control; Level : Word32);

   procedure Get_Max_Backlight (Panel : Panel_Control; Level : out Word32);

end HW.GFX.GMA.Panel;
