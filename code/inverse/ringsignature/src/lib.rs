#![allow(dead_code)]
#![allow(non_snake_case)]
#![feature(test)]
extern crate test;

pub mod commitment;
pub mod ringsig;
mod schnorr;

pub use merlin::Transcript;
