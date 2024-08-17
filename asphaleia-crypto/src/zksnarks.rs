use bellman::{
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
        Proof, VerifyingKey,
    },
    VerificationError,
};
use bls12_381::Bls12;
use thiserror::Error;

pub use bellman::{Circuit, ConstraintSystem, SynthesisError};
pub use bls12_381::Scalar;

#[derive(Error, Debug)]
pub enum ZkSnarkError {
    #[error("Failed to generate parameters: {0}")]
    ParameterGenerationError(bellman::SynthesisError),
    #[error("Failed to create proof: {0}")]
    ProofCreationError(bellman::SynthesisError),
    #[error("Failed to serialize proof: {0}")]
    ProofSerializationError(std::io::Error),
    #[error("Failed to serialize verifying key: {0}")]
    VkSerializationError(std::io::Error),
    #[error("Failed to deserialize proof: {0}")]
    ProofDeserializationError(std::io::Error),
    #[error("Failed to deserialize verifying key: {0}")]
    VkDeserializationError(std::io::Error),
    #[error("Failed to verify proof: {0}")]
    ProofVerificationError(bellman::SynthesisError),
}

pub fn generate_proof<C>(circuit: C) -> Result<(Vec<u8>, Vec<u8>), ZkSnarkError>
where
    C: Circuit<Scalar> + Clone,
{
    let params =
        generate_random_parameters::<Bls12, _, _>(circuit.clone(), &mut rand::thread_rng())
            .map_err(ZkSnarkError::ParameterGenerationError)?;
    let proof = create_random_proof(circuit, &params, &mut rand::thread_rng())
        .map_err(ZkSnarkError::ProofCreationError)?;
    let vk = params.vk;

    let mut proof_vec = Vec::new();
    proof
        .write(&mut proof_vec)
        .map_err(ZkSnarkError::ProofSerializationError)?;
    let mut vk_vec = Vec::new();
    vk.write(&mut vk_vec)
        .map_err(ZkSnarkError::VkSerializationError)?;
    Ok((proof_vec, vk_vec))
}

pub fn verify_zk_proof(
    proof: &[u8],
    vk: &[u8],
    public_inputs: &[Scalar],
) -> Result<(), ZkSnarkError> {
    let proof = Proof::<Bls12>::read(proof).map_err(ZkSnarkError::ProofDeserializationError)?;
    let pvk = prepare_verifying_key(
        &VerifyingKey::<Bls12>::read(vk).map_err(ZkSnarkError::VkDeserializationError)?,
    );

    verify_proof(&pvk, &proof, public_inputs).map_err(|_: VerificationError| {
        ZkSnarkError::ProofVerificationError(bellman::SynthesisError::Unsatisfiable)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellman::{Circuit, ConstraintSystem, SynthesisError};
    #[derive(Clone)]
    struct TestCircuit {
        a: Option<Scalar>,
        b: Option<Scalar>,
    }

    impl Circuit<Scalar> for TestCircuit {
        fn synthesize<CS: ConstraintSystem<Scalar>>(
            self,
            cs: &mut CS,
        ) -> Result<(), SynthesisError> {
            let a = cs.alloc(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.alloc_input(
                || "c",
                || {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a * b)
                },
            )?;

            cs.enforce(|| "a * b = c", |lc| lc + a, |lc| lc + b, |lc| lc + c);

            Ok(())
        }
    }

    #[test]
    fn test_zk_snark_proof() {
        let a = Scalar::from(2);
        let b = Scalar::from(3);
        let c = a * b;

        let circuit = TestCircuit {
            a: Some(a),
            b: Some(b),
        };

        let (proof, vk) = generate_proof(circuit).unwrap();
        let result = verify_zk_proof(&proof, &vk, &[c]);
        assert!(result.is_ok(), "Proof verification failed: {:?}", result);
    }

    #[test]
    fn test_invalid_proof() {
        let a = Scalar::from(2);
        let b = Scalar::from(3);
        let _c = a * b;

        let circuit = TestCircuit {
            a: Some(a),
            b: Some(b),
        };

        let (proof, vk) = generate_proof(circuit).unwrap();
        let invalid_c = Scalar::from(7); // This is not the correct result of a * b
        let result = verify_zk_proof(&proof, &vk, &[invalid_c]);
        assert!(result.is_err());
    }
}
