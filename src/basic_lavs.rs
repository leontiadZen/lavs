#![allow(non_snake_case)]

use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::bls12_381::Pair;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use ff_zeroize::Field;
use pairing_plus::bls12_381::{Fq12, G1Affine};
use pairing_plus::serdes::SerDes;
use curv::arithmetic::Converter;

#[derive(Clone, Copy, Debug)]
pub struct KeyPairG2 {
    Y: GE2,
    x: FE2,
    B: i32
}

pub struct VK{

}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LAVSSignature {
    pub sigma: GE1,
}

impl KeyPairG2 {
    pub fn new(messages:i32) -> Self {
        let x: FE2 = ECScalar::new_random();
        let Y = GE2::generator() * &x;
        KeyPairG2 { x, Y,B:messages }
    }
}

impl LAVSSignature {
    // compute sigma  = g^1/a+H(m)
    pub fn sign(message: &[u8], keys: &KeyPairG2) -> Self {
        // let H_m = GE1::hash_to_curve(message);

        //x in G1
        let fe1_x: FE1 = ECScalar::from(&ECScalar::to_big_int(&keys.x));
        //message as BigInt
        let mes = BigInt::from_bytes(message);
        //message  in G1
        let mes_f1: FE1 = ECScalar::from(&mes);
        //1/(a+m)
        let exp: FE1 = (mes_f1 + fe1_x).invert();
        LAVSSignature {
            //g^{1/(a+m)}
            sigma: GE1::generator() * exp,
        }
    }

    // check e(H(m), Y) == e(sigma, g2)
    pub fn verify(&self, message: &[u8], pubkey: &GE2) -> bool {
        
        //message as BigInt
        let mes = BigInt::from_bytes(message);
        //message  in G2
        let mes_f1: FE2 = ECScalar::from(&mes);

        //g^msg
        let exp  = GE2::generator() * mes_f1;

        let el1 = Pair::compute_pairing(&self.sigma,  &(pubkey + &exp));
        let el2 = Pair::compute_pairing(&GE1::generator(), &(GE2::generator()));

        el1==el2
    }

    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut pk = vec![];
        G1Affine::serialize(&self.sigma.get_element(), &mut pk, compressed)
            .expect("serialize to vec should always succeed");
        pk
    }
    pub fn Aggregate(messages: Vec<Vec<bytes>>,signatures: Vec<Vec<bytes>>)
}

mod test {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    pub fn test_simple_lavs() {
        let keypair = KeyPairG2::new(3);
        let Y = keypair.Y.clone();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = LAVSSignature::sign(&message_bytes[..], &keypair);
        assert!(signature.verify(&message_bytes[..], &Y));
    }

}
