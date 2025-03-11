# delete `Dyn_CPU` lines along with a preceding comma in the previous line:
:s
/,$/{
        N
        s/,\n.*Dyn_CPU[^,)]*//
        ts
        P
        D
}
# delete all other lines about `Dyn_CPU`:
/Dyn_CPU/d
