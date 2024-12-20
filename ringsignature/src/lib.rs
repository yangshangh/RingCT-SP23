#![feature(test)]
extern crate test;

pub mod schnorr;
mod errors;

pub use crate::errors::*;
pub use merlin::Transcript;
