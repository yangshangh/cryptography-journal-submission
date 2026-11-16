#![allow(dead_code)]
#![allow(non_snake_case)]
#![feature(test)]
extern crate test;

pub mod commitment;
mod schnorr;
pub mod ringsig;

pub use merlin::Transcript;
