(module
  (type (;0;) (func (result i32 i32)))
  (func (;0;) (type 0) (result i32 i32)
    i32.const 0
    if (result i32 i32)  ;; label = @1
      unreachable
      br_table 0 (;@1;) 1
    else
      unreachable
    end ;; if @1
    unreachable))
