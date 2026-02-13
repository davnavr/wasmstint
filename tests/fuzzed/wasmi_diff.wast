;; https://github.com/wasmi-labs/wasmi/issues/1741
(module
  (func (param i32 i32 i64) (result i32)
    local.get 0
    f32.reinterpret_i32
    i32.trunc_sat_f32_s
    i32.const -1
    i32.rem_s
  )
  (export "" (func 0)))

(assert_return
  (invoke "" (i32.const 0x3030_3030) (i32.const 0x3030_3030) (i64.const 0x3030_3030_3030_3030))
  (i32.const 0))
(assert_return
  (invoke "" (i32.const 0xFB30_3030) (i32.const 0) (i64.const 0))
  (i32.const 0))


;; allocation of memory for globals
(module
  (type (;0;) (func))
  (import "spectest" "global_f32" (global (;0;) f32))
  (import "spectest" "print" (func (;0;) (type 0)))
  (import "spectest" "global_f32" (global (;1;) f32))
  (import "spectest" "global_f32" (global (;2;) f32))
  (func (;1;) (type 0))
  (global (;3;) v128 (v128.const i32x4 0x30303030 0x30303030 0x30303030 0x30303030))
  (global (;4;) i32 (i32.const 0))
  (global (;5;) v128 (v128.const i32x4 0x00000000 0x00000000 0x00000000 0x00000000)))


;; assembly backend
(module
  (func (export "i32.div_s") (param $numerator i32) (param $denominator i32) (result i32)
    local.get $numerator
    local.get $denominator
    i32.div_s
  )
  
  (func (export "i64.div_s") (param $numerator i64) (param $denominator i64) (result i64)
    local.get $numerator
    local.get $denominator
    i64.div_s
  )
)

;; incorrect overflow check
(assert_return
  (invoke "i32.div_s" (i32.const 0) (i32.const 0x7FFF_FFFF))
  (i32.const 0))
(assert_return
  (invoke "i64.div_s" (i64.const 0) (i64.const 0x7FFF_FFFF_FFFF_FFFF))
  (i64.const 0))
