(module
  (type (func (result i32 i32)))

  (func (type 0) (result i32 i32)
    i32.const 0
    if (result i32 i32)  ;; label = @1
      unreachable
      br_table 0 (;@1;) 1
    else
      unreachable
    end ;; if @1
    unreachable)

  ;; same as above, with an extra instruction
  (func (type 0) (result i32 i32)
    i32.const 0 ;; new
    i32.const 0
    if (result i32 i32)  ;; label = @1
      unreachable
      br_table 0 (;@1;) 1
    else
      unreachable
    end ;; if @1
    unreachable)
)
