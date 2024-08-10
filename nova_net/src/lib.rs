extern crate num_bigint as bigint;

use bigint::BigUint;
#[no_mangle]
pub extern "C" fn _start() -> BigUint {
    let base: BigUint = BigUint::parse_bytes(b"4", 10).unwrap();
    let modulus: BigUint = BigUint::parse_bytes(
        b"00a09ecd8ada2a30634181e1bf5452b92268d2373ad4b234c750b79cb09cb2c82f2fd51310d7a771f44ccf58b46d94c156107c0695d289adb58280d8479da80b4f", 
        16,
    )
    .unwrap();
    let range: BigUint = modulus.clone() / BigUint::parse_bytes(b"5000000", 10).unwrap();
   
    let exp: BigUint = BigUint::parse_bytes(b"b7c8d9", 16).unwrap();

    if exp > range {
        panic!("Exp is not in range");
    }

    let result = base.modpow(&exp, &modulus);
    result
    //senv::commit(&(base, modulus, range, result));
}
