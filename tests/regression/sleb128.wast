(module
  (func (export "5-bytes-at-freddys") (result i32)
    i32.const 0x7FC0_0000
  )

  (func (export "i64.msb") (result i64)
    i64.const 0xC000_0000_0000_0000
  )
)

(assert_return (invoke "5-bytes-at-freddys") (i32.const 0x7FC0_0000))
(assert_return (invoke "i64.msb") (i64.const 0xC000_0000_0000_0000))
