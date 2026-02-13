;; table.fill segmentation fault
(module
  (table 8 8 externref)
  (func
    i32.const 0
    ref.null extern
    i32.const 8 ;; 8 elements is 64 bytes
    table.fill 0 ;; triggered path to align to nearest 64-byte boundary
  )
  (export "" (func 0)))

(invoke "")
