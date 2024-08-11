use std::fmt::Debug;
use std::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriConfig;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{prove, verify, StarkConfig};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub struct ExponentRangeCheckAir {
    pub num_steps: usize,
    pub final_value: u32,
    pub gen: u32,
    pub modulus: u32,
}

impl<F: Field> BaseAir<F> for ExponentRangeCheckAir {
    fn width(&self) -> usize {
        63 
    }
}

impl<AB: AirBuilder> Air<AB> for ExponentRangeCheckAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0); // 0 -> remainder / result so far; 1 -> next bit in
                                       // exponent; 2 -> quotient
                                       // 3 .. 32 -> split indexes 
                                       // 33 .. 62 -> result bit decomposition

        // Enforce starting values
        builder.when_first_row().assert_eq(local[0], AB::Expr::from_canonical_u32(self.gen));
        builder.when_first_row().assert_eq(local[1], AB::Expr::one());
        builder.when_first_row().assert_eq(local[2], AB::Expr::zero());

        // Enforce state transition constraints
        // builder.when_transition().assert_eq(next[0], (AB::Expr::one() - local[1]) * local[0] + local[1] * (local[0] * AB::Expr::from_canonical_u32(self.gen)  - local[2] * AB::Expr::from_canonical_u32(self.modulus)));
        // builder.when_transition().assert_eq(local[1] * (local[1] - AB::Expr::one()), AB::Expr::zero());
        let modulus_bit: [u32; 30] = [1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1];
        let mut modulus_acc: [u32; 31] = [0; 31];
        for i in 0..modulus_bit.len() {
            for j in 0..=i {
                modulus_acc[i+1] += modulus_bit[j]*2u32.pow((29 - j).try_into().unwrap()); 
            }
        }
        
        let mut exp = AB::Expr::zero();
        for i in 3..=32 {
              builder.when_transition().assert_eq(local[i] * (local[i] - AB::Expr::one()), AB::Expr::zero());
             exp = exp + local[i];
        }
        builder.when_transition().assert_eq(AB::Expr::one(), exp);
        
        for i in 33..=62 {
             builder.when_transition().assert_eq(local[i] * (local[i] - AB::Expr::one()), AB::Expr::zero());
        }

        let mut brsum = AB::Expr::zero();
        for i in 33..=62 {
            brsum = brsum + local[i]*AB::Expr::from_canonical_u32( 2u32.pow( (29 - (i-33)).try_into().unwrap()  )  );
        }
        builder.when_transition().assert_eq(local[0], brsum);

        for i in 0..30 {
            let mut fh = AB::Expr::zero();
            for j in 0..i {
                fh += local[j + 3 + 30] * AB::Expr::from_canonical_u32( 2u32.pow((29 - j).try_into().unwrap()));
            }
            builder.when_transition().assert_eq(
                local[i + 3] *  // SI_i
                local[i + 3 +30] // BR_{i}
                , AB::Expr::zero());

            builder.when_transition().assert_eq(
                local[i + 3] *  // SI_i
                (AB::Expr::one() - AB::Expr::from_canonical_u32(modulus_bit[i]))
                , AB::Expr::zero());

            builder.when_transition().assert_eq(
                local[i+3] *
                (fh - AB::Expr::from_canonical_u32(modulus_acc[i])),
                AB::Expr::zero()
            );
        }

        // 111011011010000011101010111001 
        // Constraint the final value
        let final_value = AB::Expr::from_canonical_u32(self.final_value);
        builder.when_last_row().assert_eq(local[0], final_value);
        builder.when_last_row().assert_eq(local[1], AB::Expr::zero());
    }
}

pub fn generate_trace<F: Field>(num_steps: usize) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(num_steps * 63);
    let gen = 4;
    let exponent = 50;
    let modulus = 996686521;

    let modulus_bit: [u32; 30] = [1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1];
    let mut reminder = 4;
    let mut quotient = 0;
    let mut exponent_bit;
    let mut split_indexes = vec![F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()];
    let mut reminder_bits = vec![F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::one(), F::zero(), F::zero()];
    for i in 1..=num_steps {
        values.push(F::from_canonical_u32(reminder));
        if i < exponent {
            exponent_bit = 1;
        } else {
            exponent_bit = 0;
        }
        values.push(F::from_canonical_u32(exponent_bit));
        values.push(F::from_canonical_u32(quotient));
        values.extend(&split_indexes);
        values.extend(&reminder_bits);

        if i < exponent {
            reminder = reminder * gen;
        }
        quotient = reminder / modulus;
        reminder = reminder % modulus;
        reminder_bits.clear();
        split_indexes.clear();
        for i in (0..30).rev() {
            let bit = F::from_canonical_u32((reminder >> i) & 1);
            reminder_bits.push(bit);
            split_indexes.push(F::zero());
        }
        for i in 0..30 {
            if reminder_bits[i] != F::from_canonical_u32(modulus_bit[i]) {
                split_indexes[i] = F::one();
                break;
            }
        }
        
    }

    // values.push(F::one()); // selector
    // values.push(F::zero()); // quotient
    // for _ in 1..=29 { // split index
    //     values.push(F::zero());
    // }
    // values.push(F::one());

    // let mut bits = Vec::new();

    // // Iterate over each bit position from most significant to least significant
    // for i in (0..30).rev() {
    //     let bit = F::from_canonical_u32((reminder >> i) & 1);
    //     bits.push(bit);
    // }
    // println!("binaries {:?}", bits);
    // values.extend(&bits); // reminder bit composition


//     reminder = reminder * gen;
// 
//     for i in 2..=9 {
//         reminder = reminder % modulus;
//         values.push(F::from_canonical_u32(reminder));
//         println!("round {} value {}", i, reminder);
//         if i == 9 {
//             values.push(F::zero());
//         }
//         else {
//             values.push(F::one());
//         }
//         reminder = reminder * gen;
//         values.push(F::from_canonical_u32(reminder/modulus));
//         
//         for _ in 1..=29 {
//             values.push(F::zero());
//         }
//         values.push(F::one());
// 
//         bits = Vec::new();
// 
//     // Iterate over each bit position from most significant to least significant
//         for i in (0..30).rev() {
//             let bit = F::from_canonical_u32((reminder/gen >> i) & 1);
//             bits.push(bit);
//         }
//         values.extend(&bits);
//     }
// 
//     for i in 10..=16 {
//         values.push(F::from_canonical_u32(reminder/gen));
//         println!("round {} value {}", i, reminder/gen);
//         values.push(F::zero());
//         values.push(F::zero());
//         for _ in 1..=29 {
//             values.push(F::zero());
//         }
//         values.push(F::one());
//         bits = Vec::new();
// 
//     // Iterate over each bit position from most significant to least significant
//         for i in (0..30).rev() {
//             let bit = F::from_canonical_u32((reminder/gen >> i) & 1);
//             bits.push(bit);
//         }
//         values.extend(&bits);
//     }
    RowMajorMatrix::new(values, 63)
}

fn main() -> Result<(), impl Debug> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    type Val = Mersenne31;
    type Challenge = BinomialExtensionField<Val, 3>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher32<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Keccak256Hash {});

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);

    type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::new(field_hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs {
        mmcs: val_mmcs,
        fri_config,
        _phantom: PhantomData,
    };

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs);

    let num_steps = 64; // Choose the number of steps
    let final_value = 565654865; // Choose the final value
    let gen = 4;           // Generator
    let modulus = 996686521;    // Modulus
    let air = ExponentRangeCheckAir { num_steps, final_value, gen, modulus };
    let trace = generate_trace::<Val>(num_steps);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    verify(&config, &air, &mut challenger, &proof, &vec![])
}
