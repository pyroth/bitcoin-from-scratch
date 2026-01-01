//! Core functions for math over Elliptic Curves over Finite Fields,
//! especially the ability to define Points on Curves and perform
//! addition and scalar multiplication.

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Zero};
use std::ops::{Add, Mul};

/// Extended Euclidean Algorithm
/// Returns (gcd, x, y) s.t. a * x + b * y == gcd
#[must_use]
pub fn extended_euclidean_algorithm(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let mut old_r = a.clone();
    let mut r = b.clone();
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();
    let mut old_t = BigInt::zero();
    let mut t = BigInt::one();

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let temp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = &old_s - &quotient * &s;
        old_s = temp_s;

        let temp_t = t.clone();
        t = &old_t - &quotient * &t;
        old_t = temp_t;
    }

    (old_r, old_s, old_t)
}

/// Returns modular multiplicative inverse m s.t. (n * m) % p == 1
#[must_use]
#[inline]
pub fn mod_inv(n: &BigInt, p: &BigInt) -> BigInt {
    let (_, x, _) = extended_euclidean_algorithm(n, p);
    x.mod_floor(p)
}

/// Elliptic Curve over the field of integers modulo a prime.
/// Points on the curve satisfy y^2 = x^3 + a*x + b (mod p).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Curve {
    pub p: BigInt,
    pub a: BigInt,
    pub b: BigInt,
}

impl Curve {
    pub fn new(p: BigInt, a: BigInt, b: BigInt) -> Self {
        Curve { p, a, b }
    }
}

/// An integer point (x,y) on a Curve, or the point at infinity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    pub curve: Option<Curve>,
    pub x: Option<BigInt>,
    pub y: Option<BigInt>,
}

impl Point {
    #[must_use]
    pub fn new(curve: Curve, x: BigInt, y: BigInt) -> Self {
        Point {
            curve: Some(curve),
            x: Some(x),
            y: Some(y),
        }
    }

    /// Point at infinity
    #[must_use]
    pub const fn infinity() -> Self {
        Point {
            curve: None,
            x: None,
            y: None,
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_infinity(&self) -> bool {
        self.x.is_none() && self.y.is_none()
    }
}

/// Core point addition logic - shared by all Add implementations
fn point_add_impl(lhs: &Point, rhs: &Point) -> Point {
    if lhs.is_infinity() {
        return rhs.clone();
    }
    if rhs.is_infinity() {
        return lhs.clone();
    }

    let curve = lhs.curve.as_ref().unwrap();
    let self_x = lhs.x.as_ref().unwrap();
    let self_y = lhs.y.as_ref().unwrap();
    let other_x = rhs.x.as_ref().unwrap();
    let other_y = rhs.y.as_ref().unwrap();

    if self_x == other_x && self_y != other_y {
        return Point::infinity();
    }

    let m = if self_x == other_x {
        let numerator = (BigInt::from(3) * self_x.pow(2) + &curve.a).mod_floor(&curve.p);
        let denominator = (BigInt::from(2) * self_y).mod_floor(&curve.p);
        (numerator * mod_inv(&denominator, &curve.p)).mod_floor(&curve.p)
    } else {
        let numerator = (self_y - other_y).mod_floor(&curve.p);
        let denominator = (self_x - other_x).mod_floor(&curve.p);
        (numerator * mod_inv(&denominator, &curve.p)).mod_floor(&curve.p)
    };

    let rx = (&m.pow(2) - self_x - other_x).mod_floor(&curve.p);
    let ry = (-(&m * (&rx - self_x) + self_y)).mod_floor(&curve.p);

    Point::new(curve.clone(), rx, ry)
}

impl Add for Point {
    type Output = Point;

    #[inline]
    fn add(self, other: Point) -> Point {
        point_add_impl(&self, &other)
    }
}

impl Add<&Point> for &Point {
    type Output = Point;

    #[inline]
    fn add(self, other: &Point) -> Point {
        point_add_impl(self, other)
    }
}

/// Scalar multiplication: k * Point
impl Mul<&Point> for BigInt {
    type Output = Point;

    fn mul(self, point: &Point) -> Point {
        scalar_mul(&self, point)
    }
}

impl Mul<&Point> for &BigInt {
    type Output = Point;

    fn mul(self, point: &Point) -> Point {
        scalar_mul(self, point)
    }
}

impl Mul<Point> for BigInt {
    type Output = Point;

    fn mul(self, point: Point) -> Point {
        scalar_mul(&self, &point)
    }
}

impl Mul<Point> for &BigInt {
    type Output = Point;

    fn mul(self, point: Point) -> Point {
        scalar_mul(self, &point)
    }
}

/// Double-and-add scalar multiplication
#[must_use]
pub fn scalar_mul(k: &BigInt, point: &Point) -> Point {
    debug_assert!(*k >= BigInt::zero(), "scalar must be non-negative");
    let mut result = Point::infinity();
    let mut addend = point.clone();
    let mut k = k.clone();

    while !k.is_zero() {
        if (&k & BigInt::one()) == BigInt::one() {
            result = &result + &addend;
        }
        addend = &addend + &addend;
        k >>= 1;
    }
    result
}

/// A generator over a curve: an initial point and the (pre-computed) order
#[derive(Debug, Clone)]
pub struct Generator {
    pub g: Point,  // A generator point on the curve
    pub n: BigInt, // The order of the generating point, so 0*G = n*G = INF
}

impl Generator {
    #[must_use]
    pub const fn new(g: Point, n: BigInt) -> Self {
        Generator { g, n }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_inv() {
        let p = BigInt::from(17);
        let n = BigInt::from(3);
        let inv = mod_inv(&n, &p);
        assert_eq!((&n * &inv).mod_floor(&p), BigInt::one());
    }

    #[test]
    fn test_point_infinity() {
        let inf = Point::infinity();
        assert!(inf.is_infinity());
    }
}
