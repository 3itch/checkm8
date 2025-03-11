--
-- Copyright (C) 2022 Google, LLC
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
with GNAT.Source_Info;

package body HW.GFX.GMA.PLLs
with
   Refined_State => (State => PLLs)
is

   type Count_Range is new Natural range 0 .. 2;

   type PLL_State is record
      Use_Count  : Count_Range;
   end record;

   type PLL_State_Array is array (Configurable_DPLLs) of PLL_State;

   pragma Warnings (Off, "unused variable ""PLLs""",
                    Reason => "Not yet implemented.");
   pragma Warnings (Off, "variable ""PLLs"" is assigned but never read",
                    Reason => "Not yet implemented.");
   PLLs : PLL_State_Array;
   pragma Warnings (On, "variable ""PLLs"" is assigned but never read");
   pragma Warnings (On, "unused variable ""PLLs""");

   procedure Initialize is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
      PLLs :=
        (Configurable_DPLLs =>
           (Use_Count => 0));
   end Initialize;

   procedure Alloc
     (Port_Cfg : in     Port_Config;
      PLL      :    out T;
      Success  :    out Boolean)
   is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
      PLL := Invalid_PLL;
      Success := True;
   end Alloc;

   procedure Free (PLL : T) is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
   end Free;

   procedure All_Off is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
   end All_Off;

   function Register_Value (PLL : T) return Word32
   is
   begin
      pragma Debug (Debug.Put_Line (GNAT.Source_Info.Enclosing_Entity));
      Return 0;
   end Register_Value;
end HW.GFX.GMA.PLLs;
