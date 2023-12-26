* The implementation of sections 6,7 from https://eprint.iacr.org/2022/179.pdf
* For the underlying math operations https://github.com/ZenGo-X/curv wrapper crate is used for arithmetics in G1,G2 both as scalars and group elements and for pairings: https://github.com/algorand/pairing-plus is used.
* 'cargo test' will run the tests
* 'libgmp' is needed for the tests to run
* There is implicit hash to G1 for the input messages 
* Computation of beta coefficients is missing in both aggregate signature and encryption schemes
