use ark_ec::pairing::Pairing;
use ark_std::Zero;
use round_based::SinkExt;
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    MessageDestination,
};
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use serde::{Deserialize, Serialize};
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::Ciphertext,
    kzg::PowersOfTau,
    setup::{AggregateKey, SecretKey},
};
use std::collections::BTreeMap;

use crate::setup::{from_bytes, to_bytes};

/// Error type for decrypt-specific operations
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("MPC protocol error: {0}")]
    MpcError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("Delivery error: {0}")]
    DeliveryError(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryptionMessage {
    pub sender: u32,
    pub partial_decryption: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DecryptState {
    pub partial_decryptions: BTreeMap<usize, Vec<u8>>,
    pub decryption_result: Option<Vec<u8>>,
}

#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
pub enum Msg {
    Round1Broadcast(Msg1),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Msg1 {
    source: u16,
    data: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub async fn threshold_decrypt_protocol<M, E: Pairing>(
    party: M,
    i: PartyIndex,
    t: u16,
    n: u16,
    secret_key: &SecretKey<E>,
    ciphertext: &Ciphertext<E>,
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
) -> Result<DecryptState, DecryptError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut state = DecryptState::default();

    // Setup round router
    let mut rounds = RoundsRouter::builder();
    let round1 = rounds.add_round(RoundInput::<Msg1>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    // Generate partial decryption
    let p_decryption = secret_key.partial_decryption(ciphertext);

    // Broadcast partial decryption
    let broadcast_msg = Msg::Round1Broadcast(Msg1 {
        source: i,
        data: to_bytes(p_decryption),
    });

    send_message::<M, E>(broadcast_msg, &mut outgoings).await?;

    // Insert own partial decryption
    state
        .partial_decryptions
        .insert(i as usize, to_bytes::<E::G2>(p_decryption));

    // Collect other partial decryptions
    let round1_broadcasts = rounds
        .complete(round1)
        .await
        .map_err(|err| DecryptError::MpcError(err.to_string()))?;

    state.partial_decryptions.extend(
        round1_broadcasts
            .into_iter_indexed()
            .map(|r| (r.2.source as usize, r.2.data)),
    );

    // Compute final decryption if we have enough partial decryptions
    if state.partial_decryptions.len() >= (t + 1) as usize {
        // Create selector vector
        let mut selector: Vec<bool> = vec![false; n as usize];
        let mut partial_decryptions: Vec<E::G2> = vec![E::G2::zero(); n as usize];
        for j in state.partial_decryptions.keys() {
            selector[*j] = true;
            partial_decryptions[*j] =
                from_bytes::<E::G2>(state.partial_decryptions.get(j).unwrap());
        }

        for j in t + 1..n {
            selector[j as usize] = false;
        }

        let dec_key = agg_dec(&partial_decryptions, ciphertext, &selector, agg_key, params);
        state.decryption_result = Some(to_bytes(dec_key));
    }

    Ok(state)
}

async fn send_message<M, E: Pairing>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), DecryptError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let recipient = match &msg {
        Msg::Round1Broadcast(_) => MessageDestination::AllParties,
    };

    let msg = round_based::Outgoing { recipient, msg };
    tx.send(msg)
        .await
        .map_err(|e| DecryptError::DeliveryError(e.to_string()))?;

    Ok(())
}