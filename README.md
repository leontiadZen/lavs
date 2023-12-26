* The implementation of https://eprint.iacr.org/2022/179.pdf
* For the underlying math operations https://github.com/ZenGo-X/curv wrapper crate is used for arithmetics in G1,G2 both as scalars and group elements and for pairings: https://github.com/algorand/pairing-plus is used.
* cargo test will run the tests
* libgmp is needed for the tests to run
* Computation of beta  coefficients beta is missing.
