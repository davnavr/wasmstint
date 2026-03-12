;; Tests for the X86-64 assembly implementation of the interpreter

;; table.grow

(module
  (table 0 externref)

  (func (export "get") (param $idx i32) (result externref)
    local.get $idx
    table.get 0
  )

  (func (export "grow") (param $delta i32) (param $init externref) (result i32)
    local.get $init
    local.get $delta
    table.grow 0
  )
)

(assert_return (invoke "grow" (i32.const 10) (ref.extern 0xAAAA)) (i32.const 0))
(assert_return (invoke "get" (i32.const 9)) (ref.extern 0xAAAA))
;; Trigger a reallocation
(assert_return (invoke "grow" (i32.const 65527) (ref.extern 0xBBB)) (i32.const 10)) ;; 10
(assert_return (invoke "get" (i32.const 0)) (ref.extern 0xAAAA))
(assert_return (invoke "get" (i32.const 8)) (ref.extern 0xAAAA))
(assert_return (invoke "get" (i32.const 10)) (ref.extern 0xBBB))
(assert_return (invoke "get" (i32.const 1234)) (ref.extern 0xBBB))
(assert_return (invoke "get" (i32.const 5678)) (ref.extern 0xBBB))
