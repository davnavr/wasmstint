;; https://github.com/wasmi-labs/wasmi/issues/1741
(module
  (func (;0;) (param i32 i32 i64) (result i32)
    local.get 0
    ;; i32
    f32.reinterpret_i32
    ;; f32
    i32.trunc_sat_f32_s
    ;; i32
    i32.const -1
    ;; i32 i32
    i32.rem_s ;; trap occurs here??
    ;; i32
  )
  (export "" (func 0)))

(assert_return
  (invoke "" (i32.const 0x3030_3030) (i32.const 0x3030_3030) (i64.const 0x3030_3030_3030_3030))
  (i32.const 0))
(assert_return
  (invoke "" (i32.const 0xFB30_3030) (i32.const 0) (i64.const 0))
  (i32.const 0)) ;; wasmi thinks this should trap with "integer overflow"
