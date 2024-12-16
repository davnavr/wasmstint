//! Parses a sequence of `Token`s into a list of `SExpr`essions.

/// An S-expression.
pub const SExpr = union(enum) {
    atom,
    // expr
};

//const Tree = struct { arena };
