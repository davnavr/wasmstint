(module
  ;; X86-64 assembly implementation
  (func (export "5-bytes-at-freddys") (result i32)
    (i32.const 0x7fc00000))
)

(assert_return (invoke "5-bytes-at-freddys") (i32.const 0x7FC0_0000))
