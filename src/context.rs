use crate::decrypt::DecryptState;
use crate::setup::SilentThresholdEncryptionKeypair;
use ark_bn254::Bn254;
use blueprint_sdk as sdk;
use blueprint_sdk::networking::service_handle::NetworkServiceHandle;
use blueprint_sdk::networking::InstanceMsgPublicKey;
use blueprint_sdk::stores::local_database::LocalDatabase;
use color_eyre::eyre;
use color_eyre::eyre::eyre;
use color_eyre::{Report, Result};
use sdk::clients::GadgetServicesClient;
use sdk::config::GadgetConfiguration;
use sdk::contexts::keystore::KeystoreContext;
use sdk::contexts::tangle::TangleClientContext;
use sdk::crypto::sp_core::SpSr25519;
use sdk::crypto::tangle_pair_signer::sp_core;
use sdk::keystore::backends::Backend;
use sdk::logging;
use sdk::macros::contexts::{KeystoreContext, ServicesContext, TangleClientContext};
use sdk::tangle_subxt;
use sdk::tangle_subxt::tangle_testnet_runtime::api;
use silent_threshold_encryption::kzg::PowersOfTau;
use sp_core::ecdsa;
use sp_core::ecdsa::Public;
use std::collections::btree_map::BTreeMap;
use std::collections::hash_set::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tangle_subxt::subxt_core::utils::AccountId32;

#[derive(Clone, ServicesContext, TangleClientContext, KeystoreContext)]
pub struct ServiceContext {
    #[config]
    pub config: GadgetConfiguration,
    #[call_id]
    pub call_id: Option<u64>,
    pub service_id: u64,
    pub secret_key_store: Arc<LocalDatabase<SilentThresholdEncryptionKeypair>>,
    pub decrypt_state_store: Arc<LocalDatabase<DecryptState>>,
    pub identity: ecdsa::Pair,
    pub params: PowersOfTau<Bn254>,
    pub network_handle: NetworkServiceHandle,
}

pub(crate) const NETWORK_PROTOCOL: &str = "silent-timelock-encryption.bn254/1.0.0";
pub const KEYPAIR_KEY: &str = "silent_timelock_encryption_keypair";

impl ServiceContext {
    pub async fn new(
        config: GadgetConfiguration,
        params: PowersOfTau<Bn254>,
        service_id: u64,
    ) -> eyre::Result<Self> {
        let operator_keys: HashSet<InstanceMsgPublicKey> = config
            .eigenlayer_client()
            .await?
            .get_operators()
            .await?
            .values()
            .map(|key| InstanceMsgPublicKey(*key))
            .collect();

        let network_config = config.libp2p_network_config(NETWORK_PROTOCOL)?;
        let identity = network_config.instance_key_pair.0.clone();

        let network_handle = config.libp2p_start_network(network_config, operator_keys)?;

        let secret_keystore_dir = PathBuf::from(config.keystore_uri.clone()).join("secret.json");
        let decrypt_store = PathBuf::from(config.keystore_uri.clone()).join("decrypt.json");
        let secret_key_store = Arc::new(LocalDatabase::open(secret_keystore_dir));
        let decrypt_state_store = Arc::new(LocalDatabase::open(decrypt_store));

        Ok(Self {
            params,
            call_id: None,
            secret_key_store,
            decrypt_state_store,
            identity,
            config,
            network_handle,
            service_id,
        })
    }

    /// Returns a reference to the configuration
    #[inline]
    pub fn config(&self) -> &GadgetConfiguration {
        &self.config
    }

    /// Returns a clone of the store handle for secret key
    #[inline]
    pub fn secret_key_store(&self) -> Arc<LocalDatabase<SilentThresholdEncryptionKeypair>> {
        self.secret_key_store.clone()
    }

    /// Returns a clone of the store handle for decrypt state
    #[inline]
    pub fn decrypt_state_store(&self) -> Arc<LocalDatabase<DecryptState>> {
        self.decrypt_state_store.clone()
    }

    /// Returns the network protocol version
    #[inline]
    pub fn network_protocol(&self) -> &str {
        NETWORK_PROTOCOL
    }

    /// Retrieves the current blueprint ID from the configuration
    ///
    /// # Errors
    /// Returns an error if the blueprint ID is not found in the configuration
    pub fn blueprint_id(&self) -> Result<u64> {
        self.config()
            .protocol_settings
            .eigenlayer()
            .map(|c| c.blueprint_id)
            .map_err(|err| eyre!("Blueprint ID not found in configuration: {err}"))
    }

    /// Retrieves the current party index and operator mapping
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to retrieve operator keys
    /// - Current party is not found in the operator list
    pub async fn get_party_index_and_operators(
        &self,
    ) -> Result<(usize, BTreeMap<AccountId32, Public>)> {
        let parties = self.eigenlayer_get_operators_ecdsa_keys().await?;
        let my_id = self.keystore().first_local::<SpSr25519>()?.0;

        logging::trace!(
            "Looking for {my_id:?} in parties: {:?}",
            parties.keys().collect::<Vec<_>>()
        );

        let index_of_my_id = parties
            .iter()
            .position(|(id, _)| id.0 == *my_id)
            .ok_or_else(|| eyre!("Party not found in operator list"))?;

        Ok((index_of_my_id, parties))
    }

    /// Retrieves the ECDSA keys for all current service operators
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to connect to the EigenLayer client
    /// - Failed to retrieve operator information
    /// - Missing ECDSA key for any operator
    pub async fn eigenlayer_get_operators_ecdsa_keys(
        &self,
    ) -> Result<BTreeMap<AccountId32, Public>> {
        let client = self.eigenlayer_client().await?;
        let current_blueprint = self.blueprint_id()?;
        let storage = client.storage().at_latest().await?;

        let mut map = BTreeMap::new();
        for (operator, _) in client.get_operators().await? {
            let addr = api::storage()
                .services()
                .operators(current_blueprint, &operator);

            let maybe_pref = storage
                .fetch(&addr)
                .await
                .map_err(|err| eyre!("Failed to fetch operator storage for {operator}: {err}"))?;

            if let Some(pref) = maybe_pref {
                let public_key = Public::from_full(pref.key.as_slice())
                    .map_err(|_| Report::msg("Invalid key"))?;
                map.insert(operator, public_key);
            } else {
                return Err(eyre!("Missing ECDSA key for operator {operator}"));
            }
        }

        Ok(map)
    }

    /// Checks if this operator is the aggregator
    pub async fn is_aggregator(&self) -> Result<bool> {
        let task_manager = self.create_task_manager().await?;
        let aggregator = task_manager.aggregator().call().await?;
        let my_address = self.config.wallet_address()?;
        Ok(aggregator == my_address)
    }

    /// Creates a task manager contract instance
    pub async fn create_task_manager(&self) -> Result<SilentTimelockEncryptionTaskManager> {
        let task_manager_address = self.config.protocol_settings.eigenlayer()?.task_manager_address;
        let provider = sdk::utils::evm::get_provider_http(&self.config.http_rpc_endpoint);
        Ok(SilentTimelockEncryptionTaskManager::new(task_manager_address, provider))
    }
}