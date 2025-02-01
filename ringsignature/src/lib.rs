#![allow(dead_code)]
#![allow(non_snake_case)]
#![feature(test)]
extern crate test;

mod commitment;
mod schnorr;
mod ringsig;

pub use merlin::Transcript;
