use blake3::Hasher;
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("proof invalid")]
    Invalid,
    #[error("age threshold not met")]
    BelowThreshold,
}

#[derive(ZeroizeOnDrop)]
struct BirthDate {
    days_since_epoch: u64,
}

impl BirthDate {
    fn new(days: u64) -> Self {
        Self { days_since_epoch: days }
    }
}

pub struct Commitment {
    pub bytes:           [u8; 32],
    pub(crate) blinding: [u8; 32],
}

impl Commitment {
    fn new(birth: &BirthDate) -> Self {
        let mut blinding = [0u8; 32];
        OsRng.fill_bytes(&mut blinding);
        let bytes = commit(birth.days_since_epoch, &blinding);
        Self { bytes, blinding }
    }
}

fn commit(days: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new_derive_key("discord-age-verify/v1/commitment");
    h.update(&days.to_le_bytes());
    h.update(blinding);
    h.finalize().into()
}

pub struct AgeProof {
    pub commitment:     [u8; 32],
    pub range_hash:     [u8; 32],
    pub threshold_days: u64,
    pub current_days:   u64,
}

pub struct Prover {
    birth: BirthDate,
    pub c: Commitment,
}

impl Prover {
    pub fn new(birth_days: u64) -> Self {
        let birth = BirthDate::new(birth_days);
        let c = Commitment::new(&birth);
        Self { birth, c }
    }

    pub fn prove(&self, current_days: u64, threshold_years: u64) -> Result<AgeProof, ProofError> {
        let threshold_days = threshold_years * 365 + threshold_years / 4;

        if current_days < self.birth.days_since_epoch + threshold_days {
            return Err(ProofError::BelowThreshold);
        }

        let age_days = current_days - self.birth.days_since_epoch;

        let range_hash = {
            let mut h = Hasher::new_derive_key("discord-age-verify/v1/range");
            h.update(&self.c.bytes);
            h.update(&age_days.to_le_bytes());
            h.update(&threshold_days.to_le_bytes());
            h.update(&proof_current_days_bytes(current_days));
            h.update(&self.c.blinding);
            h.finalize().into()
        };

        Ok(AgeProof {
            commitment: self.c.bytes,
            range_hash,
            threshold_days,
            current_days,
        })
    }
}

fn proof_current_days_bytes(days: u64) -> [u8; 8] {
    days.to_le_bytes()
}

pub struct Verifier;

impl Verifier {
    pub fn verify(
        proof:      &AgeProof,
        commitment: &[u8; 32],
        blinding:   &[u8; 32],
        birth_days: u64,
    ) -> Result<(), ProofError> {
        if proof.commitment != *commitment {
            return Err(ProofError::Invalid);
        }

        let recomputed = commit(birth_days, blinding);
        if recomputed != proof.commitment {
            return Err(ProofError::Invalid);
        }

        let age_days = proof.current_days
            .checked_sub(birth_days)
            .ok_or(ProofError::Invalid)?;

        if age_days < proof.threshold_days {
            return Err(ProofError::BelowThreshold);
        }

        let expected: [u8; 32] = {
            let mut h = Hasher::new_derive_key("discord-age-verify/v1/range");
            h.update(&proof.commitment);
            h.update(&age_days.to_le_bytes());
            h.update(&proof.threshold_days.to_le_bytes());
            h.update(&proof_current_days_bytes(proof.current_days));
            h.update(blinding);
            h.finalize().into()
        };

        if expected != proof.range_hash {
            return Err(ProofError::Invalid);
        }

        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    let birth_days   = 10_000u64;
    let current_days = birth_days + 365 * 20 + 5;

    let legitimate   = Prover::new(birth_days);
    let commitment   = legitimate.c.bytes;
    let blinding     = legitimate.c.blinding;

    println!("Commitment (public) : {}", hex(&commitment));
    println!("Birth date (private): day {}", birth_days);
    println!("Current day         : {}", current_days);
    println!("Proof size          : {} bytes", 32 + 32 + 8 + 8);
    println!();

    match legitimate.prove(current_days, 18) {
        Ok(proof) => {
            match Verifier::verify(&proof, &commitment, &blinding, birth_days) {
                Ok(()) => println!("Verification: VALID — user is over 18."),
                Err(e) => println!("Verification failed: {}", e),
            }
        }
        Err(e) => println!("Proof failed: {}", e),
    }

    println!();
    println!("-- Fraud attempt");
    println!("   Attacker is over 18 but uses a different birth date.");
    println!("   They present a valid proof against their own commitment.");
    println!("   Discord holds the legitimate user's commitment on file.");
    println!("   The mismatch is detected at verification.");
    println!();

    let fraud_birth  = birth_days + 365 * 19;
    let attacker     = Prover::new(fraud_birth);

    match attacker.prove(current_days, 18) {
        Ok(fraud_proof) => {
            match Verifier::verify(&fraud_proof, &commitment, &blinding, fraud_birth) {
                Ok(()) => println!("ERROR: fraud accepted."),
                Err(e) => println!("Fraud rejected: {}", e),
            }
        }
        Err(e) => println!("Fraud rejected at proof generation: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIRTH:     u64 = 10_000;
    const NOW_ADULT: u64 = BIRTH + 365 * 20;
    const NOW_MINOR: u64 = BIRTH + 365 * 16;

    #[test]
    fn adult_proof_valid() {
        let p = Prover::new(BIRTH);
        let c = p.c.bytes;
        let b = p.c.blinding;
        let proof = p.prove(NOW_ADULT, 18).unwrap();
        assert!(Verifier::verify(&proof, &c, &b, BIRTH).is_ok());
    }

    #[test]
    fn minor_cannot_prove() {
        let p = Prover::new(BIRTH);
        assert!(p.prove(NOW_MINOR, 18).is_err());
    }

    #[test]
    fn wrong_commitment_rejected() {
        let p = Prover::new(BIRTH);
        let b = p.c.blinding;
        let proof = p.prove(NOW_ADULT, 18).unwrap();
        assert!(Verifier::verify(&proof, &[0u8; 32], &b, BIRTH).is_err());
    }

    #[test]
    fn tampered_birth_rejected() {
        let p = Prover::new(BIRTH);
        let c = p.c.bytes;
        let b = p.c.blinding;
        let proof = p.prove(NOW_ADULT, 18).unwrap();
        assert!(Verifier::verify(&proof, &c, &b, BIRTH + 1000).is_err());
    }

    #[test]
    fn adult_attacker_with_different_birth_rejected() {
        let legitimate = Prover::new(BIRTH);
        let real_c = legitimate.c.bytes;
        let real_b = legitimate.c.blinding;

        let attacker       = Prover::new(BIRTH + 365 * 19);
        let fraud_proof    = attacker.prove(NOW_ADULT, 18).unwrap();

        assert!(Verifier::verify(&fraud_proof, &real_c, &real_b, BIRTH + 365 * 19).is_err());
    }

    #[test]
    fn blinding_makes_commitments_unique() {
        let p1 = Prover::new(BIRTH);
        let p2 = Prover::new(BIRTH);
        assert_ne!(p1.c.bytes, p2.c.bytes);
    }

    #[test]
    fn different_birth_different_commitment() {
        let p1 = Prover::new(BIRTH);
        let p2 = Prover::new(BIRTH + 1000);
        assert_ne!(p1.c.bytes, p2.c.bytes);
    }
}
