;; Tests the parser when SIMD is disabled at compile time.
;;
;; Expected results should be based on what the WASM specification test runner returns.

(assert_malformed
  (module
  (func
    i32.const 0
    i32x4.splat
    drop)
  )
 "unexpected opcode"
)

(assert_malformed
  (module
  (func
    (local v128))
  )
 "valid local type"
)

(assert_malformed
  (module
    (global v128 (v128.const i64x2 0 0))
  )
  "invalid global type"
)

(assert_malformed
  (module
    (import "a" "b" (global v128))
  )
  "invalid global type"
)

(assert_malformed
  (module
    (func (param v128))
  )
  "valid param type"
)

(assert_malformed
  (module
    (func (result v128))
  )
  "valid result type"
)
