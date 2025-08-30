macro_rules! gen_ops {
    (@gen_op $type:ident, $underlying:ident, $opTrait:ident, $opFn: ident, $op:tt) =>
    {
        impl<T: Into<$underlying>> std::ops::$opTrait<T> for $type {
            type Output = $type;

            fn $opFn(self, rhs: T) -> Self::Output {
                $type(self.0 $op rhs.into())
            }
        }
    };
    (@gen_op_assign $type:ident, $underlying:ident, $opTrait:ident, $opFn: ident, $op: tt) =>
    {
        impl<T: Into<$underlying>> std::ops::$opTrait<T> for $type {
            fn $opFn(&mut self, rhs: T) {
                self.0 $op rhs.into()
            }
        }
    };
    ($type:ident, $underlying:ident) => {
        gen_ops!(@gen_op $type, $underlying, Add, add, +);
        gen_ops!(@gen_op_assign $type, $underlying, AddAssign, add_assign, +=);
        gen_ops!(@gen_op $type, $underlying, Sub, sub, -);
        gen_ops!(@gen_op_assign $type, $underlying, SubAssign, sub_assign, -=);
        gen_ops!(@gen_op $type, $underlying, Mul, mul, *);
        gen_ops!(@gen_op_assign $type, $underlying, MulAssign, mul_assign, *=);
        gen_ops!(@gen_op $type, $underlying, Div, div, /);
        gen_ops!(@gen_op_assign $type, $underlying, DivAssign, div_assign, /=);

    };
}

macro_rules! wrap_numeric {
    ($newtype: ident, $underlying: ident, $($c:tt)+) => {
        #[doc = stringify!($($c)+)]
        #[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $newtype(pub $underlying);

        impl From<$newtype> for $underlying {
            fn from(value: $newtype) -> Self {
                value.0
            }
        }

        impl From<$underlying> for $newtype {
            fn from(value: $underlying) -> Self {
                $newtype(value)
            }
        }

        gen_ops!($newtype, $underlying);

        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(&self.0, f)
            }
        }
    }
}

wrap_numeric!(Pages, u64, "A quantity of pages of memory");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pages() {
        let p = Pages(64);
        let mut p2 = (p * 2u32) + 4u32;
        assert!(p2 == 132u64.into());

        let formatted = format!("{}", p2);
        assert_eq!(formatted, "132");
        p2 /= 2u32;
        let formatted = format!("{}", p2);
        assert_eq!(formatted, "66");
    }
}
