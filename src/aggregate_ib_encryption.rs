#![allow(non_snake_case)]

use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::bls12_381::Pair;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::arithmetic::Converter;

use ff_zeroize::Field;

use pairing_plus::bls12_381::{Fq12, G1Affine};
use pairing_plus::serdes::SerDes;

#[derive(Clone, Copy, Debug)]
pub struct MSK {
    Y: GE1,
    x: FE1,
    T: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext {
    pub c1: Vec<GE1>,
    pub c2: Pair,
}

impl MSK {
    pub fn new(id:&[u8],T:i32) -> Self {
        let x: FE1 = ECScalar::new_random();
        //x in G1
        let fe1_x: FE1 = ECScalar::from(&ECScalar::to_big_int(&x));
        //id as BigInt
        let id = BigInt::from_bytes(id);
        //message  in G1
        let mid_f1: FE1 = ECScalar::from(&id);
        //1/(a+id)
        let exp: FE1 = (mid_f1 + fe1_x).invert();
        //g^{1/(a+m)}
        let Y = GE1::generator() * exp;
        
        MSK { x, Y , T}
    }
}

impl Ciphertext {
    //from https://www.di.ens.fr/david.pointcheval/Documents/Papers/2007_pairing.pdf fig 2, p12.
    //Running time: O(n**2). Can be improved in Langange interpolation trick as explained in the paper. 
    pub fn DPP(ids: Vec<Vec<u8>>,mut sks: Vec<MSK>)->GE1{
        let n = ids.len();
        for i in  0..n - 1{
		for j in i+1..n{
			if  i != j 
			{
                //x[l]-x[j]
				let diff_1 =  BigInt::from_bytes(&ids[j]) - BigInt::from_bytes(&ids[i]);
                let diff_1_scalar: FE1 = ECScalar::from(&diff_1);
                
                //1/(x[l]-x[j])
                let tmp_invert = diff_1_scalar.invert();

                //P[j]-P[l]
                let mut neg_sig2 = sks[j].Y.bytes_compressed_to_big_int();
                neg_sig2 = -neg_sig2;
                let neg_g1: FE1 = ECScalar::from(&neg_sig2);
                let exp  = GE1::generator() * neg_g1;
				let diff_2 =  sks[i].Y + exp;

                // 1/(x[l]-x[j]) * P[j]-P[l]
				sks[j].Y = diff_2 * tmp_invert; 
			}
		}
	}
    sks[n-1].Y
    }

    pub fn aggregate(ids: Vec<Vec<u8>>,mut sks: Vec<MSK>)->GE1{
        Ciphertext::DPP(ids,sks)

    }
    pub fn encrypt(msg:&[u8],msk: MSK, id:&[u8])->Self{
        let r :FE1 = ECScalar::new_random();
        let mut c1 =  Vec::new();


        for i in 0..msk.T {
            let fe1_x: FE1 = ECScalar::from(&ECScalar::to_big_int(&msk.x));
            //id as BigInt
            let id = BigInt::from_bytes(id);
            //id  in G1
            let mid_f1: FE1 = ECScalar::from(&id);
            //r*(a+id)*a^i
            let iexp: FE1 = ECScalar::from(&BigInt::from(i));
            let exp: FE1 = (mid_f1 + fe1_x)*r*fe1_x*iexp;
            //g^{r*(a+id)*a^i}
            let Y = GE1::generator() * exp;
            c1.push(Y);

        }
        let c2 = Pair::compute_pairing(&(GE1::generator()*&r), &(GE2::generator()));
        Ciphertext{c1,c2}



        
    }
    // pub fn aggregate_decrypt()->{
        //TODO
    // }
}

