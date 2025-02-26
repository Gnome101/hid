use crate::context::{ServiceContext, KEYPAIR_KEY};
use crate::decrypt::{threshold_decrypt_protocol, DecryptError, DecryptState, Msg};
use crate::setup::{from_bytes, setup, to_bytes, SilentThresholdEncryptionKeypair};
use crate::SilentTimelockEncryptionTaskManager;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use blueprint_sdk::alloy::primitives::{keccak256, Bytes, U256};
use blueprint_sdk::alloy::sol_types::SolType;
use blueprint_sdk::event_listeners::evm::EvmContractEventListener;
use blueprint_sdk::event_listeners::tangle::services::{services_post_processor, services_pre_processor};
use blueprint_sdk::job;
use blueprint_sdk::logging;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::networking::InstanceMsgPublicKey;
use color_eyre::eyre;
use color_eyre::Result;
use round_based::PartyIndex;
use silent_threshold_encryption::encryption::{Ciphertext, encrypt};
use silent_threshold_encryption::setup::{AggregateKey, PublicKey, SecretKey};
use std::collections::HashMap;

/// Ensures that the operator has an STE keypair and has registered it with the contract
#[job(
    id = 0,
    params(),
    event_listener(
        listener = EvmContractEventListener<ServiceContext, SilentTimelockEncryptionTaskManager::STEPublicKeyRegistered>,
        instance = SilentTimelockEncryptionTaskManager,
    ),
)]
pub async fn register_ste_key(
    context: ServiceContext,
) -> Result<(), DecryptError> {
    logging::info!("Checking if STE keypair exists");
    
    // Check if keypair exists in local db, otherwise generate and save it
    if context.secret_key_store.get(KEYPAIR_KEY).is_none() {
        logging::info!("Generating new STE keypair");
        
        let (i, operators) = context.get_party_index_and_operators().await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?;
        
        let n = operators.len() as u32;
        let new_keypair = setup::<Bn254>(n, i as u32, &context.params)
            .map_err(|e| DecryptError::ContextError(e))?;
        
        // Submit the STE public key to the blueprint contract
        logging::info!("Registering STE public key with contract");
        let task_manager = context.create_task_manager().await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?;
        
        task_manager
            .registerSTEPublicKey(
                context.service_id,
                Bytes::copy_from_slice(new_keypair.public_key.as_ref()),
            )
            .send()
            .await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?
            .await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?;

        logging::info!("Storing STE keypair locally");
        context.secret_key_store.set(KEYPAIR_KEY, new_keypair);
    } else {
        logging::info!("STE keypair already exists");
    }
    
    Ok(())
}

/// Pre-processor for decryption tasks
pub async fn decrypt_pre_processor(
    (event, _): (SilentTimelockEncryptionTaskManager::NewTaskCreated, blueprint_sdk::alloy::rpc::types::Log),
) -> Result<Option<(u16, Vec<u8>)>, blueprint_sdk::event_listeners::core::Error<blueprint_sdk::event_listeners::evm::error::Error>> {
    let task = event.task;
    
    // Check if this is a decrypt task by looking at message format
    if task.message.len() < 4 {
        return Ok(None);
    }
    
    // Try to decode as (bytes, uint16)
    match blueprint_sdk::alloy::abi::decode(&[
        blueprint_sdk::alloy::abi::ParamType::Bytes,
        blueprint_sdk::alloy::abi::ParamType::Uint(16),
    ], &task.message) {
        Ok(tokens) => {
            if tokens.len() != 2 {
                return Ok(None);
            }
            
            let ciphertext = match &tokens[0] {
                blueprint_sdk::alloy::abi::Token::Bytes(data) => data.clone(),
                _ => return Ok(None),
            };
            
            let threshold = match &tokens[1] {
                blueprint_sdk::alloy::abi::Token::Uint(value) => value.as_u64() as u16,
                _ => return Ok(None),
            };
            
            Ok(Some((threshold, ciphertext)))
        },
        Err(_) => Ok(None),
    }
}

/// Handles decryption tasks by generating a partial decryption
#[job(
    id = 1,
    params(threshold, ciphertext),
    result(_),
    event_listener(
        listener = EvmContractEventListener<ServiceContext, SilentTimelockEncryptionTaskManager::NewTaskCreated>,
        instance = SilentTimelockEncryptionTaskManager,
        pre_processor = decrypt_pre_processor,
    ),
)]
pub async fn decrypt_ciphertext(
    threshold: u16,
    ciphertext: Vec<u8>,
    context: ServiceContext,
) -> Result<Vec<u8>, DecryptError> {
    logging::info!("Starting decrypt_ciphertext job with threshold {}", threshold);
    
    // Get task information
    let task_index = match context.call_id {
        Some(id) => id,
        None => context.current_call_id().await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?,
    };
    
    logging::info!("Processing task {}", task_index);
    
    // Get the STE keypair
    let keypair = match context.secret_key_store.get(KEYPAIR_KEY) {
        Some(k) => k,
        None => return Err(DecryptError::ContextError("STE keypair not found".to_string())),
    };
    
    // Deserialize the ciphertext and secret key
    let ciphertext: Ciphertext<Bn254> = from_bytes(&ciphertext);
    let secret_key: SecretKey<Bn254> = from_bytes(&keypair.secret_key);
    
    // Get party information
    let (i, operators) = context.get_party_index_and_operators().await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;
    
    let parties: HashMap<u16, InstanceMsgPublicKey> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as PartyIndex, InstanceMsgPublicKey(ecdsa)))
        .collect();
    
    let n = parties.len() as u16;
    let i = i as u16;
    
    logging::info!("Starting decryption protocol as party {}/{}", i, n);
    
    // Create network adapter for protocol communication
    let network = RoundBasedNetworkAdapter::<Msg>::new(
        context.network_handle.clone(),
        i,
        parties.clone(),
        context.network_protocol(),
    );
    
    // Create MPC party
    let party = round_based::party::MpcParty::connected(network);
    
    // Create task manager contract
    let task_manager = context.create_task_manager().await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;
    
    // Get all registered STE public keys
    logging::info!("Fetching registered STE public keys");
    let registered_keys = task_manager.getAllSTEPublicKeys(context.service_id).call().await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;
    
    let pk_vec = registered_keys.iter()
        .filter(|k| !k.is_empty())
        .map(|k| from_bytes::<PublicKey<Bn254>>(k.as_ref()))
        .collect::<Vec<_>>();
    
    // Create aggregate key
    logging::info!("Creating aggregate key from {} public keys", pk_vec.len());
    let agg_key = AggregateKey::<Bn254>::new(pk_vec, &context.params);
    
    // Run the decryption protocol
    logging::info!("Running threshold decryption protocol");
    let decryption = threshold_decrypt_protocol(
        party,
        i,
        threshold,
        n,
        &secret_key,
        &ciphertext,
        &agg_key,
        &context.params,
    ).await?;
    
    // Store the decryption state locally
    context.decrypt_state_store.set(&task_index.to_string(), decryption.clone());
    
    // Submit partial decryption to the contract
    if let Some(partial_decryption) = decryption.partial_decryptions.get(&(i as usize)) {
        logging::info!("Submitting partial decryption to contract");
        task_manager
            .submitPartialDecryption(
                task_index as u32,
                Bytes::copy_from_slice(partial_decryption),
            )
            .send()
            .await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?
            .await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?;
    }
    
    // If we have a decryption result and we're the aggregator, submit it
    if let Some(result) = &decryption.decryption_result {
        if context.is_aggregator().await
            .map_err(|e| DecryptError::ContextError(e.to_string()))? 
        {
            logging::info!("Submitting completed decryption as aggregator");
            task_manager
                .completeDecryption(
                    task_index as u32,
                    Bytes::copy_from_slice(result),
                )
                .send()
                .await
                .map_err(|e| DecryptError::ContextError(e.to_string()))?
                .await
                .map_err(|e| DecryptError::ContextError(e.to_string()))?;
        }
    }
    
    // Return the serialized decryption state
    Ok(serde_json::to_vec(&decryption)
        .map_err(|e| DecryptError::SerializationError(e.to_string()))?)
}

/// Pre-processor for encryption tasks
pub async fn encrypt_pre_processor(
    (event, _): (SilentTimelockEncryptionTaskManager::EncryptionRequested, blueprint_sdk::alloy::rpc::types::Log),
) -> Result<Option<(Vec<u8>, u16)>, blueprint_sdk::event_listeners::core::Error<blueprint_sdk::event_listeners::evm::error::Error>> {
    Ok(Some((event.message.to_vec(), event.threshold)))
}

/// Handles encryption tasks
#[job(
    id = 2,
    params(message, threshold),
    result(_),
    event_listener(
        listener = EvmContractEventListener<ServiceContext, SilentTimelockEncryptionTaskManager::EncryptionRequested>,
        instance = SilentTimelockEncryptionTaskManager,
        pre_processor = encrypt_pre_processor,
    ),
)]
pub async fn encrypt_message(
    message: Vec<u8>,
    threshold: u16,
    context: ServiceContext,
) -> Result<Vec<u8>, DecryptError> {
    logging::info!("Starting encrypt_message job with threshold {}", threshold);
    
    // Get task information
    let task_index = match context.call_id {
        Some(id) => id,
        None => context.current_call_id().await
            .map_err(|e| DecryptError::ContextError(e.to_string()))?,
    };
    
    // Only the aggregator should perform encryption
    if !context.is_aggregator().await
        .map_err(|e| DecryptError::ContextError(e.to_string()))? 
    {
        logging::info!("Not the aggregator, skipping encryption");
        return Ok(Vec::new());
    }
    
    // Create task manager contract
    let task_manager = context.create_task_manager().await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;
    
    // Get all registered STE public keys
    logging::info!("Fetching registered STE public keys");
    let registered_keys = task_manager.getAllSTEPublicKeys(context.service_id).call().await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?;
    
    let pk_vec = registered_keys.iter()
        .filter(|k| !k.is_empty())
        .map(|k| from_bytes::<PublicKey<Bn254>>(k.as_ref()))
        .collect::<Vec<_>>();
    
    // Create aggregate key
    logging::info!("Creating aggregate key from {} public keys", pk_vec.len());
    let agg_key = AggregateKey::<Bn254>::new(pk_vec, &context.params);
    
    // Encrypt the message
    logging::info!("Encrypting message");
    let ciphertext = encrypt(&agg_key, threshold as usize, &context.params);
    let ciphertext_bytes = to_bytes(ciphertext);
    
    // Respond to the task with the encrypted message
    logging::info!("Responding to task with encrypted message");
    let task = task_manager.NewTaskCreated_filter()
        .taskIndex_eq(task_index as u32)
        .query_with_meta()
        .await
        .map_err(|e| DecryptError::ContextError(e.to_string()))?
        .first()
        .cloned()
        .ok_or_else(|| DecryptError::ContextError("Task not found".to_string()))?;
    
    let task_response = SilentTimelockEncryptionTaskManager::TaskResponse {
        referenceTaskIndex: task_index as u32,
        message: Bytes::copy_from_slice(&ciphertext_bytes),
    };
    
    // This would normally need BLS signatures from operators, but for simplicity
    // we're just mocking the response
    
    // Return the ciphertext
    Ok(ciphertext_bytes)
}