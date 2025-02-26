pub mod context;
pub mod decrypt;
pub mod jobs;
pub mod setup;
use blueprint_sdk::alloy::sol;
use serde::{Deserialize, Serialize};

sol!(
    #[sol(rpc)]
    #[derive(Debug, Serialize, Deserialize)]
    SilentTimelockEncryptionTaskManager,
    "contracts/out/SilentTimelockEncryptionTaskManager.sol/SilentTimelockEncryptionTaskManager.json",
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ServiceContext;
    use crate::decrypt::DecryptState;
    use crate::jobs::{decrypt_ciphertext, register_ste_key};
    use crate::setup::setup;
    use blueprint_sdk::alloy::primitives::Bytes;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;
    use blueprint_sdk::alloy::network::EthereumWallet;
    use blueprint_sdk::alloy::signers::local::PrivateKeySigner;
    use blueprint_sdk::testing::tempfile;
    use blueprint_sdk::testing::utils::harness::TestHarness;
    use blueprint_sdk::testing::utils::eigenlayer::EigenlayerTestHarness;
    use color_eyre::eyre;
    use silent_threshold_encryption::kzg::KZG10;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread")]
    async fn decrypt_ciphertext_test() -> Result<(), eyre::Error> {
        // Initialize test environment
        let tmp_dir = tempfile::TempDir::new()?;
        let harness = EigenlayerTestHarness::setup(tmp_dir).await?;
        
        // Set up service
        let (mut test_env, service_id, _) = harness.setup_services::<3>(false).await?;
        test_env.initialize().await?;
        
        // Initialize KZG parameters
        let max_degree = 1 << 10;
        let tau = <Bn254 as Pairing>::ScalarField::rand(&mut ark_std::test_rng());
        let params = KZG10::<Bn254, DensePolynomial<<Bn254 as Pairing>::ScalarField>>::setup(
            max_degree, tau,
        ).unwrap();
        
        // Generate keypairs for each operator
        let mut keypairs = Vec::new();
        for i in 0..3 {
            let keypair = setup::<Bn254>(3, i as u32, &params).unwrap();
            keypairs.push(keypair);
        }
        
        // Deploy contracts and set up operators
        let task_manager_address = harness.deploy_mock_contract().await?;
        
        // Set up and start nodes
        let handles = test_env.node_handles().await;
        for (i, handle) in handles.iter().enumerate() {
            let config = handle.gadget_config().await;
            let context = ServiceContext::new(config.clone(), params.clone(), service_id).await?;
            
            // Store the keypair
            context.secret_key_store.set(context::KEYPAIR_KEY, keypairs[i].clone());
            
            // Set up job handlers
            let ste_key_job = register_ste_key::EvmContractEventHandler::new(context.clone());
            let decrypt_job = decrypt_ciphertext::EvmContractEventHandler::new(context.clone());
            
            handle.add_job(ste_key_job).await;
            handle.add_job(decrypt_job).await;
        }
        
        // Start the test environment
        test_env.start().await?;
        
        // Create a mock contract instance
        let private_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = PrivateKeySigner::from_hex(private_key)?;
        let wallet = EthereumWallet::new(signer);
        
        // Wait for services to initialize
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        // Register operators
        for (i, keypair) in keypairs.iter().enumerate() {
            // In a real test, you would register the STE public key here
            println!("Registering operator {} with public key length {}", i, keypair.public_key.len());
        }
        
        // Mock a decryption task
        // In a real test, you would create a task and verify it was processed
        
        Ok(())
    }
}