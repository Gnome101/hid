use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use blueprint_sdk::logging::info;
use blueprint_sdk::runners::core::runner::BlueprintRunner;
use blueprint_sdk::runners::eigenlayer::bls::EigenlayerBLSConfig;
use silent_threshold_encryption::kzg::{PowersOfTau, KZG10};
use silent_timelock_encryption_blueprint::context::ServiceContext;
use silent_timelock_encryption_blueprint::jobs::{decrypt_ciphertext, encrypt_message, register_ste_key};

#[blueprint_sdk::main(env)]
async fn main() -> Result<(), color_eyre::eyre::Error> {
    info!("Starting Silent Timelock Encryption Blueprint");
    
    // Initialize KZG parameters for STE
    let max_degree = 1 << 10;
    let tau = <Bn254 as Pairing>::ScalarField::rand(&mut ark_std::test_rng());
    let params =
        KZG10::<Bn254, DensePolynomial<<Bn254 as Pairing>::ScalarField>>::setup(max_degree, tau)
            .unwrap();

    // Create service context
    let context = ServiceContext::new(
        env.clone(),
        params.clone(),
        env.protocol_settings.eigenlayer().unwrap().service_id.unwrap(),
    )
    .await?;

    // Create job handlers
    let ste_key_job = register_ste_key::EvmContractEventHandler::new(context.clone());
    let decrypt_job = decrypt_ciphertext::EvmContractEventHandler::new(context.clone());
    let encrypt_job = encrypt_message::EvmContractEventHandler::new(context.clone());

    // Start the Blueprint runner
    info!("Starting BlueprintRunner with jobs");
    let eigenlayer_config = EigenlayerBLSConfig::default();
    BlueprintRunner::new(eigenlayer_config, env)
        .job(ste_key_job)
        .job(decrypt_job)
        .job(encrypt_job)
        .run()
        .await?;

    info!("Silent Timelock Encryption Blueprint shutting down");
    Ok(())
}