;; Tests for the X86-64 assembly implementation of the interpreter

;; const

(module
  (func (export "5-bytes-at-freddys") (result i32)
    (i32.const 0x7fc00000))
)

(assert_return (invoke "5-bytes-at-freddys") (i32.const 0x7FC0_0000))

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
(assert_return (invoke "grow" (i32.const 65527) (ref.extern 0xBBB)) (i32.const -1)) ;; 10
;; (assert_return (invoke "get" (i32.const 0)) (ref.extern 0xAAAA))
;; (assert_return (invoke "get" (i32.const 8)) (ref.extern 0xAAAA))
;; (assert_return (invoke "get" (i32.const 1234)) (ref.extern 0xBBB))
;; (assert_return (invoke "get" (i32.const 5678)) (ref.extern 0xBBB))
