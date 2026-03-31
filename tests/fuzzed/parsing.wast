;; Expected results should be based on what the WASM specification test runner returns.

;; Tracking of `ref.func` in constant expressions caused access to uninitialized
;; `ArenaAllocator` when an expression that was later expected to be an integer was parsed.
(assert_invalid
  (module binary
    "\00asm" ;; magic
    "\01\00\00\00" ;; version

    "\01" ;; type section
    "\04" ;; section size
    "\01" ;; # of types
    "\60\00\00" ;; (type $t0 (func))

    "\03" ;; func section
    "\02" ;; section size
    "\01" ;; # of functions
    "\00" ;; (func $f0 (type $t0))

    "\05" ;; memory section
    "\03" ;; section size
    "\01" ;; # of memories
    "\00\01" ;; (memory $m1)

    "\0a" ;; code
    "\04" ;; section size
    "\01" ;; # of functions

    ;; (func $f0)
    "\02" ;; body size
    "\00" ;; local count
    "\0b" ;; end

    "\0b" ;; data
    "\06" ;; section size
    "\01" ;; # of data segments

    "\00" ;; (data $d0)
    "\d2\00" ;; (ref.func $f0)
    "\0b" ;; end
    "\00" ;; data segment size
  )
  "type mismatch"
)
