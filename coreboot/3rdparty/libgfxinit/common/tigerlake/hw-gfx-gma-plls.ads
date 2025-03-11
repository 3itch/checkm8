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

private package HW.GFX.GMA.PLLs
with
   Abstract_State => (State with Part_Of => GMA.State)
is

   -- XXX: Types should be private (but that triggers a bug in SPARK GPL 2016)
   type T is (Invalid_PLL, DPLL0, DPLL1, DPLL4, DPLL2);
   subtype Configurable_DPLLs is T range DPLL0 .. DPLL4;
   Invalid : constant T := Invalid_PLL;

   procedure Initialize
   with
      Global => (Output => State);

   pragma Warnings (Off, "unused variable ""Port_Cfg""",
                    Reason => "Not yet implemented.");
   procedure Alloc
     (Port_Cfg : in     Port_Config;
      PLL      :    out T;
      Success  :    out Boolean);
   pragma Warnings (On, "unused variable ""Port_Cfg""");


   pragma Warnings (Off, "subprogram ""Free"" has no effect",
                    Reason => "Not yet implemented.");
   procedure Free (PLL : T);
   pragma Warnings (On, "subprogram ""Free"" has no effect");

   pragma Warnings (Off, "subprogram ""All_Off"" has no effect",
                    Reason => "Not yet implemented.");
   procedure All_Off;
   pragma Warnings (On, "subprogram ""All_Off"" has no effect");

   pragma Warnings (Off, "unused variable ""PLL""",
                    Reason => "Not yet implemented.");
   function Register_Value (PLL : T) return Word32;
   pragma Warnings (On, "unused variable ""PLL""");

end HW.GFX.GMA.PLLs;
