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
pub struct KeyPairG2 {
    Y: GE2,
    x: FE2,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LAVSSignature {
    pub sigma: GE1,
}

impl KeyPairG2 {
    pub fn new(messages:i32) -> Self {
        let x: FE2 = ECScalar::new_random();
        let Y = GE2::generator() * &x;
        KeyPairG2 { x, Y }
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

    // check e(σ, g2^a * g2^H(m)) == e(g1, g2)
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

    //from https://www.di.ens.fr/david.pointcheval/Documents/Papers/2007_pairing.pdf fig 2, p12.
    //Running time: O(n**2). Can be improved in Langange interpolation trick as explained in the paper. 
    pub fn DPP(messages: Vec<Vec<u8>>,mut signatures: Vec<LAVSSignature>)->GE1{
        let n = messages.len();
        for i in  0..n - 1{
		for j in i+1..n{
			if  i != j 
			{
                //x[l]-x[j]
				let diff_1 =  BigInt::from_bytes(&messages[j]) - BigInt::from_bytes(&messages[i]);
                let diff_1_scalar: FE1 = ECScalar::from(&diff_1);
                
                //1/(x[l]-x[j])
                let tmp_invert = diff_1_scalar.invert();

                //P[j]-P[l]
                let mut neg_sig2 = signatures[j].sigma.bytes_compressed_to_big_int();
                neg_sig2 = -neg_sig2;
                let neg_g1: FE1 = ECScalar::from(&neg_sig2);
                let exp  = GE1::generator() * neg_g1;
				let diff_2 =  signatures[i].sigma + exp;

                // 1/(x[l]-x[j]) * P[j]-P[l]
				signatures[j].sigma = diff_2 * tmp_invert; 
			}
		}
	}
    signatures[n-1].sigma
    }
    pub fn aggregate(messages: Vec<Vec<u8>>,signatures: Vec<LAVSSignature>,pubkey: &GE2) ->GE1 {
        let n = messages.len();
        let l = signatures.len();
        assert_eq!(n,l);

        for (msg,sig) in messages.iter().zip(signatures.iter()) {
            assert!(sig.verify(&msg[..], pubkey));

        }

        LAVSSignature::DPP(messages,signatures)

     }

    //  pub fn compute_betas_coeff(messages: Vec<Vec<u8>>)->Vec<FE2>{
    //     //TODO. Not clear to me yet what the y's value should be to interpolate. Is Lagrange needed here?
    //  }

    //  pub fn agg_verify(vk: &GE1,messages: Vec<Vec<u8>>)-> bool {
    //     //TODO once compute_betas_coeff is ready 
    //     true

    //  }

    //  pub fn local_open(vk: &GE1,messages: Vec<Vec<u8>>,j:i32)->(&GE2, &GE2){
    //     //TODO once compute_betas_coeff is ready 

    //  }

     pub fn LocalAggVerify(message: &[u8], aggregate_sig: GE1,aux1: &GE2,aux2: &GE2,vk: &GE1)->bool{
        //message as BigInt
        let mes = BigInt::from_bytes(message);
        //message  in G2
        let mes_f1: FE2 = ECScalar::from(&mes);

        //aux1^msg*aux2
        let el1_2  = aux1 * &mes_f1 + aux2;

        //e(aggregate_sig,aux1^msg*aux2)
        let el1 = Pair::compute_pairing(&aggregate_sig,  &el1_2);
        //e(g1,g2)
        let el2 = Pair::compute_pairing(&GE1::generator(), &(GE2::generator()));
        //e(g1^a,aux1)
        let el3 = Pair::compute_pairing(&vk, &(aux1));
        //e(g1,aux2)
        let el4 = Pair::compute_pairing(&GE1::generator(), &(aux2));

        el1==el2 && el3==el4



     }

     pub fn SeqAggSign(message: &[u8],messages: Vec<Vec<u8>>,aggregate_sig: GE1,keys: &KeyPairG2)->GE1{
        //the first step is to agg_verify which is not implemented yet.
         
        //x in G1
        let fe1_x: FE1 = ECScalar::from(&ECScalar::to_big_int(&keys.x));
        //message as BigInt
        let mes = BigInt::from_bytes(message);
        //message  in G1
        let mes_f1: FE1 = ECScalar::from(&mes);
        //1/(a+m)
        let exp: FE1 = (mes_f1 + fe1_x).invert();
        //aggregate_sig^{1/(a+m)}
        aggregate_sig * exp
         


     }
     pub fn SeqAggVerify(message: &[u8], messages: Vec<Vec<u8>>,keys: &KeyPairG2,aggregate_sig: GE1,){
        //TODO:  blocked  by agg_verify->compute_betas_coeff



     }
 }

mod test {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    pub fn test_single_lavs_signature() {
        let test_vec:Vec<i32> = vec![1,3,2,5];
        let result = test_vec.iter()
            .zip(test_vec.iter().skip(1))
            .inspect(|(a ,b)| println!("a: {},b: {}", a,b))
            .map(|(a,b)| b-a)
            .collect::<Vec<_>>();
        println!("{:?}", result);


        let a:Vec<Vec<i32>>;
        let keypair = KeyPairG2::new(3);
        let Y = keypair.Y.clone();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = LAVSSignature::sign(&message_bytes[..], &keypair);
        assert!(signature.verify(&message_bytes[..], &Y));
    }

    // pub fn test_aggregate_lavs_signature() {
    //     let messages_bytes:Vec<Vec<i32>> = vec![["transfer 3 monads"],[353],[2],[5]];
    //     let a:Vec<Vec<i32>>;
    //     let keypair = KeyPairG2::new(3);
    //     let Y = keypair.Y.clone();
        
    //     let signature = LAVSSignature::sign(&message_bytes[..], &keypair);
    //     assert!(signature.verify(&message_bytes[..], &Y));
    // }

}
