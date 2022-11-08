// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
//
// The following code is based on hbbft : https://github.com/poanetwork/hbbft
//
// hbbft is copyright 2018, POA Networks, Ltd.
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. All files in the project
// carrying such notice may not be copied, modified, or distributed except
// according to those terms.
//
//! A _synchronous_ algorithm for dealerless distributed key generation.
//!
//! This protocol is meant to run in a _completely synchronous_ setting where each node handles all
//! messages in the same order. It can e.g. exchange messages as transactions on top of
//! `HoneyBadger`, or it can run "on-chain", i.e. committing its messages to a blockchain.
//!
//! Its messages are encrypted where necessary, so they can be publicly broadcast.
//!
//! When the protocol completes, every node receives a secret key share suitable for threshold
//! signatures and encryption. The secret master key is not known by anyone. The protocol succeeds
//! if up to _t_ nodes are faulty, where _t_ is the `threshold` parameter. The number of nodes must
//! be at least _2 t + 1_.
//!
//! ## Usage
//!
//! Before beginning the threshold key generation process, each validator needs to generate a
//! regular (non-threshold) key pair and multicast its public key. `SyncKeyGen::new` returns the
//! instance itself and a `Part` message, containing a contribution to the new threshold keys.
//! It needs to be sent to all nodes. `SyncKeyGen::handle_part` in turn produces an `Ack`
//! message, which is also multicast.
//!
//! All nodes must handle the exact same set of `Part` and `Ack` messages. In this sense the
//! algorithm is synchronous: If Alice's `Ack` was handled by Bob but not by Carol, Bob and
//! Carol could receive different public key sets, and secret key shares that don't match. One way
//! to ensure this is to commit the messages to a public ledger before handling them, e.g. by
//! feeding them to a preexisting instance of Honey Badger. The messages will then appear in the
//! same order for everyone.
//!
//! To complete the process, call `SyncKeyGen::generate`. It produces your secret key share and the
//! public key set.
//!
//! While not asynchronous, the algorithm is fault tolerant: It is not necessary to handle a
//! `Part` and all `Ack` messages from every validator. A `Part` is _complete_ if it
//! received at least _2 t + 1_ valid `Ack`s. Only complete `Part`s are used for key
//! generation in the end, and as long as at least one complete `Part` is from a correct node,
//! the new key set is secure. You can use `SyncKeyGen::is_ready` to check whether at least
//! _t + 1_ `Part`s are complete. So all nodes can call `generate` as soon as `is_ready` returns
//! `true`.
//!
//! Alternatively, you can use any stronger criterion, too, as long as all validators call
//! `generate` at the same point, i.e. after handling the same set of messages.
//! `SyncKeyGen::count_complete` returns the number of complete `Part` messages. And
//! `SyncKeyGen::is_node_ready` can be used to check whether a particluar node's `Part` is
//! complete.
//!
//! The `Part` and `Ack` messages alone contain all the information needed for anyone to compute
//! the public key set, and for anyone owning one of the participating secret keys to compute
//! their own secret key share. In particular:
//! * Observer nodes can also use `SyncKeyGen`. For observers, no `Part` and `Ack`
//! messages will be created and they do not need to send anything. On completion, they will only
//! receive the public key set, but no secret key share.
//! * If a participant crashed and lost its `SyncKeyGen` instance, but still has its original
//! key pair, and if the key generation messages were committed to some public ledger, it can
//! create a new `SyncKeyGen`, handle all the messages in order, and compute its secret key share.

use bls::{
    error::Error as CryptoError,
    group::{ff::Field, prime::PrimeCurveAffine},
    poly::{BivarCommitment, BivarPoly, Poly},
    serde_impl::FieldWrap,
    Ciphertext, Fr, G1Affine, PublicKey, PublicKeySet, SecretKey, SecretKeyShare,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    hash::Hash,
    ops::{AddAssign, Mul},
};
use thiserror::Error;

/// A peer node's unique identifier.
pub trait NodeIdT: Eq + Ord + Clone + Debug + Hash + Send + Sync {}
impl<N> NodeIdT for N where N: Eq + Ord + Clone + Debug + Hash + Send + Sync {}

/// A map assigning to each node ID a public key
pub type PubKeyMap<N, PK = PublicKey> = BTreeMap<N, PK>;

/// Returns a `PubKeyMap` corresponding to the given secret keys.
///
/// This is mostly useful for setting up test networks.
pub fn to_pub_keys<'a, I, B, N: NodeIdT + 'a>(sec_keys: I) -> PubKeyMap<N>
where
    B: Borrow<N>,
    I: IntoIterator<Item = (B, &'a SecretKey)>,
{
    let to_pub = |(id, sk): I::Item| (id.borrow().clone(), sk.public_key());
    sec_keys.into_iter().map(to_pub).collect()
}

/// A local error while handling an `Ack` or `Part` message, that was not caused by that message
/// being invalid.
#[derive(Clone, PartialEq, Debug, Error)]
pub enum Error {
    /// Error creating `SyncKeyGen`.
    #[error("Error creating SyncKeyGen: {0}")]
    Creation(CryptoError),
    /// Error generating keys.
    #[error("Error generating keys: {0}")]
    Generation(CryptoError),
    /// Unknown sender.
    #[error("Unknown sender")]
    UnknownSender,
    /// Failed to serialize message.
    #[error("Serialization error: {0}")]
    Serialize(String),
    /// Failed to encrypt message parts for a peer.
    #[error("Encryption error: {0}")]
    Encrypt(String),
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Error {
        Error::Serialize(format!("{:?}", err))
    }
}

/// A submission by a validator for the key generation. It must to be sent to all participating
/// nodes and handled by all of them, including the one that produced it.
///
/// The message contains a commitment to a bivariate polynomial, and for each node, an encrypted
/// row of values. If this message receives enough `Ack`s, it will be used as summand to produce
/// the the key set in the end.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Part(BivarCommitment, Vec<Ciphertext>);

impl Debug for Part {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Part")
            .field(&format!("<degree {}>", self.0.degree()))
            .field(&format!("<{} rows>", self.1.len()))
            .finish()
    }
}

/// A confirmation that we have received and verified a validator's part. It must be sent to
/// all participating nodes and handled by all of them, including ourselves.
///
/// The message is only produced after we verified our row against the commitment in the `Part`.
/// For each node, it contains one encrypted value of that row.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Ack(u64, Vec<Ciphertext>);

impl Debug for Ack {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ack")
            .field(&self.0)
            .field(&format!("<{} values>", self.1.len()))
            .finish()
    }
}

/// The information needed to track a single proposer's secret sharing process.
#[derive(Debug, PartialEq, Eq)]
struct ProposalState {
    /// The proposer's commitment.
    commit: BivarCommitment,
    /// The verified values we received from `Ack` messages.
    values: BTreeMap<u64, Fr>,
    /// The nodes which have acked this part, valid or not.
    acks: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new part state with a commitment.
    fn new(commit: BivarCommitment) -> ProposalState {
        ProposalState {
            commit,
            values: BTreeMap::new(),
            acks: BTreeSet::new(),
        }
    }

    /// Returns `true` if all nodes have acked.
    fn is_complete(&self, all_nodes_len: usize) -> bool {
        self.acks.len() == all_nodes_len
    }
}

/// The outcome of handling and verifying a `Part` message.
pub enum PartOutcome {
    /// The message was valid: the part of it that was encrypted to us matched the public
    /// commitment, so we can multicast an `Ack` message for it. If we are an observer or we have
    /// already handled the same `Part` before, this contains `None` instead.
    Valid(Option<Ack>),
    /// The message was invalid: We now know that the proposer is faulty, and dont' send an `Ack`.
    Invalid(PartFault),
}

/// The outcome of handling and verifying an `Ack` message.
pub enum AckOutcome {
    /// The message was valid.
    Valid,
    /// The message was invalid: The sender is faulty.
    Invalid(AckFault),
}

/// A synchronous algorithm for dealerless distributed key generation.
///
/// It requires that all nodes handle all messages in the exact same order.
#[derive(Debug)]
pub struct SyncKeyGen<N> {
    /// Our node ID.
    our_id: N,
    /// Our node index.
    our_idx: Option<u64>,
    /// Our secret key.
    sec_key: SecretKey,
    /// The public keys of all nodes, by node ID.
    pub_keys: PubKeyMap<N, PublicKey>,
    /// Proposed bivariate polynomials.
    parts: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial. The threshold of the generated keyset.
    threshold: usize,
}

impl<N: NodeIdT> SyncKeyGen<N> {
    /// Creates a new `SyncKeyGen` instance, together with the `Part` message that should be
    /// multicast to all nodes.
    ///
    /// If we are not a validator but only an observer, no `Part` message is produced and no
    /// messages need to be sent.
    pub fn new<R: bls::rand::RngCore>(
        our_id: N,
        sec_key: SecretKey,
        pub_keys: PubKeyMap<N, PublicKey>,
        threshold: usize,
        rng: &mut R,
    ) -> Result<(Self, Option<Part>), Error> {
        let our_idx = pub_keys
            .keys()
            .position(|id| *id == our_id)
            .map(|idx| idx as u64);
        let key_gen = SyncKeyGen {
            our_id,
            our_idx,
            sec_key,
            pub_keys,
            parts: BTreeMap::new(),
            threshold,
        };
        if our_idx.is_none() {
            return Ok((key_gen, None)); // No part: we are an observer.
        }

        let our_part = BivarPoly::random(threshold, rng);
        let commit = our_part.commitment();
        let encrypt = |(i, pk): (usize, &PublicKey)| {
            let row = bincode::serialize(&our_part.row(i + 1))?;
            Ok(pk.encrypt_with_rng(rng, &row))
        };
        let rows = key_gen
            .pub_keys
            .values()
            .enumerate()
            .map(encrypt)
            .collect::<Result<Vec<Ciphertext>, Error>>()?;
        Ok((key_gen, Some(Part(commit, rows))))
    }

    /// Returns the id of this node.
    pub fn our_id(&self) -> &N {
        &self.our_id
    }

    /// Returns the map of participating nodes and their public keys.
    pub fn public_keys(&self) -> &PubKeyMap<N> {
        &self.pub_keys
    }

    /// Handles a `Part` message. If it is valid, returns an `Ack` message to be broadcast.
    ///
    /// If we are only an observer, `None` is returned instead and no messages need to be sent.
    ///
    /// All participating nodes must handle the exact same sequence of messages.
    /// Note that `handle_part` also needs to explicitly be called with this instance's own `Part`.
    pub fn handle_part<R: bls::rand::RngCore>(
        &mut self,
        sender_id: &N,
        part: Part,
        rng: &mut R,
    ) -> Result<PartOutcome, Error> {
        let sender_idx = self.node_index(sender_id).ok_or(Error::UnknownSender)?;
        let row = match self.handle_part_or_fault(sender_idx, part) {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(PartOutcome::Valid(None)),
            Err(fault) => return Ok(PartOutcome::Invalid(fault)),
        };
        // The row is valid. Encrypt one value for each node and broadcast an `Ack`.
        let mut values = Vec::new();
        for (idx, pk) in self.pub_keys.values().enumerate() {
            let val = row.evaluate(idx + 1);
            let ser_val = bincode::serialize(&FieldWrap(val))?;
            values.push(pk.encrypt_with_rng(rng, ser_val));
        }
        Ok(PartOutcome::Valid(Some(Ack(sender_idx, values))))
    }

    /// Handles an `Ack` message.
    ///
    /// All participating nodes must handle the exact same sequence of messages.
    /// Note that `handle_ack` also needs to explicitly be called with this instance's own `Ack`s.
    pub fn handle_ack(&mut self, sender_id: &N, ack: Ack) -> Result<AckOutcome, Error> {
        let sender_idx = self.node_index(sender_id).ok_or(Error::UnknownSender)?;
        Ok(match self.handle_ack_or_fault(sender_idx, ack) {
            Ok(()) => AckOutcome::Valid,
            Err(fault) => AckOutcome::Invalid(fault),
        })
    }

    /// Returns the index of the node, or `None` if it is unknown.
    fn node_index(&self, node_id: &N) -> Option<u64> {
        self.pub_keys
            .keys()
            .position(|id| id == node_id)
            .map(|idx| idx as u64)
    }

    /// Returns the number of complete parts. If this is at least `threshold + 1`, the keys can
    /// be generated, but it is possible to wait for more to increase security.
    pub fn count_complete(&self) -> usize {
        self.parts
            .values()
            .filter(|part| part.is_complete(self.pub_keys.len()))
            .count()
    }

    /// Returns `true` if the part of the given node is complete.
    pub fn is_node_ready(&self, proposer_id: &N) -> bool {
        self.node_index(proposer_id)
            .and_then(|proposer_idx| self.parts.get(&proposer_idx))
            .map_or(false, |part| part.is_complete(self.pub_keys.len()))
    }

    /// Returns `true` if enough parts are complete to safely generate the new key.
    pub fn is_ready(&self) -> bool {
        self.count_complete() == self.pub_keys.len()
    }

    /// Returns the new secret key share and the public key set.
    ///
    /// These are only secure if `is_ready` returned `true`. Otherwise it is not guaranteed that
    /// none of the nodes knows the secret master key.
    ///
    /// If we are only an observer node, no secret key share is returned.
    ///
    /// All participating nodes must have handled the exact same sequence of `Part` and `Ack`
    /// messages before calling this method. Otherwise their key shares will not match.
    pub fn generate(&self) -> Result<(PublicKeySet, Option<SecretKeyShare>), Error> {
        let mut pk_commit = Poly::zero().commitment();
        let mut opt_sk_val = self.our_idx.map(|_| Fr::zero());
        let is_complete = |part: &&ProposalState| part.is_complete(self.pub_keys.len());
        for part in self.parts.values().filter(is_complete) {
            pk_commit += part.commit.row(0);
            if let Some(sk_val) = opt_sk_val.as_mut() {
                let row = Poly::interpolate(part.values.iter().take(self.threshold + 1))
                    .map_err(Error::Generation)?;
                sk_val.add_assign(&row.evaluate(0));
            }
        }
        let opt_sk = if let Some(mut fr) = opt_sk_val {
            let sk = SecretKeyShare::from_mut(&mut fr);
            Some(sk)
        } else {
            None
        };
        Ok((pk_commit.into(), opt_sk))
    }

    /// Returns the number of nodes participating in the key generation.
    pub fn num_nodes(&self) -> usize {
        self.pub_keys.len()
    }

    /// Handles a `Part` message, or returns a `PartFault` if it is invalid.
    fn handle_part_or_fault(
        &mut self,
        sender_idx: u64,
        Part(commit, rows): Part,
    ) -> Result<Option<Poly>, PartFault> {
        if rows.len() != self.pub_keys.len() {
            return Err(PartFault::RowCount);
        }
        if let Some(state) = self.parts.get(&sender_idx) {
            if state.commit != commit {
                return Err(PartFault::MultipleParts);
            }
            return Ok(None); // We already handled this `Part` before.
        }
        // Retrieve our own row's commitment, and store the full commitment.
        let opt_idx_commit_row = self.our_idx.map(|idx| (idx, commit.row(idx + 1)));
        self.parts.insert(sender_idx, ProposalState::new(commit));
        let (our_idx, commit_row) = match opt_idx_commit_row {
            Some((idx, row)) => (idx, row),
            None => return Ok(None), // We are only an observer. Nothing to send or decrypt.
        };
        // We are a validator: Decrypt and deserialize our row and compare it to the commitment.
        let ser_row = self
            .sec_key
            .decrypt(&rows[our_idx as usize])
            .ok_or(PartFault::DecryptRow)?;
        let row: Poly = bincode::deserialize(&ser_row).map_err(|_| PartFault::DeserializeRow)?;
        if row.commitment() != commit_row {
            return Err(PartFault::RowCommitment);
        }
        Ok(Some(row))
    }

    /// Handles an `Ack` message, or returns an `AckFault` if it is invalid.
    fn handle_ack_or_fault(
        &mut self,
        sender_idx: u64,
        Ack(proposer_idx, values): Ack,
    ) -> Result<(), AckFault> {
        if values.len() != self.pub_keys.len() {
            return Err(AckFault::ValueCount);
        }
        let part = self
            .parts
            .get_mut(&proposer_idx)
            .ok_or(AckFault::MissingPart)?;
        if !part.acks.insert(sender_idx) {
            return Ok(()); // We already handled this `Ack` before.
        }
        let our_idx = match self.our_idx {
            Some(our_idx) => our_idx,
            None => return Ok(()), // We are only an observer. Nothing to decrypt for us.
        };
        // We are a validator: Decrypt and deserialize our value and compare it to the commitment.
        let ser_val = self
            .sec_key
            .decrypt(&values[our_idx as usize])
            .ok_or(AckFault::DecryptValue)?;
        let val = bincode::deserialize::<FieldWrap<Fr>>(&ser_val)
            .map_err(|_| AckFault::DeserializeValue)?
            .into_inner();
        if part.commit.evaluate(our_idx + 1, sender_idx + 1)
            != G1Affine::generator().mul(val).into()
        {
            return Err(AckFault::ValueCommitment);
        }
        part.values.insert(sender_idx + 1, val);
        Ok(())
    }
}

/// An error in an `Ack` message sent by a faulty node.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Error)]
pub enum AckFault {
    /// The number of values differs from the number of nodes.
    #[error("The number of values differs from the number of nodes")]
    ValueCount,
    /// No corresponding Part received.
    #[error("No corresponding Part received")]
    MissingPart,
    /// Value decryption failed.
    #[error("Value decryption failed")]
    DecryptValue,
    /// Value deserialization failed.
    #[error("Value deserialization failed")]
    DeserializeValue,
    /// Value doesn't match the commitment.
    #[error("Value doesn't match the commitment")]
    ValueCommitment,
}

/// An error in a `Part` message sent by a faulty node.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Error)]
pub enum PartFault {
    /// The number of rows differs from the number of nodes.
    #[error("The number of rows differs from the number of nodes")]
    RowCount,
    /// Received multiple different Part messages from the same sender.
    #[error("Received multiple different Part messages from the same sender")]
    MultipleParts,
    /// Could not decrypt our row in the Part message.
    #[error("Could not decrypt our row in the Part message")]
    DecryptRow,
    /// Could not deserialize our row in the Part message.
    #[error("Could not deserialize our row in the Part message")]
    DeserializeRow,
    /// Row does not match the commitment.
    #[error("Row does not match the commitment")]
    RowCommitment,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Ack, AckOutcome, Part, PartOutcome, SyncKeyGen};
    use bls::{PublicKey, PublicKeySet, SecretKey, SecretKeyShare, SignatureShare};
    use eyre::{eyre, Result};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn test_sdkg() {
        // Use the OS random number generator for any randomness:
        // let mut rng = bls::rand::rngs::OsRng::fill_bytes([0u8; 16]);
        let mut rng = bls::rand::rngs::OsRng;

        // Two out of four shares will suffice to sign or encrypt something.
        let (threshold, node_num) = (1, 4);

        // Generate individual key pairs for encryption. These are not suitable for threshold schemes.
        let sec_keys: Vec<SecretKey> = (0..node_num).map(|_| bls::rand::random()).collect();
        let pub_keys: BTreeMap<usize, PublicKey> = sec_keys
            .iter()
            .map(SecretKey::public_key)
            .enumerate()
            .collect();

        // Create the `SyncKeyGen` instances. The constructor also outputs the part that needs to
        // be sent to all other participants, so we save the parts together with their sender ID.
        let mut nodes = BTreeMap::new();
        let mut parts = Vec::new();
        for (id, sk) in sec_keys.into_iter().enumerate() {
            let (sync_key_gen, opt_part) =
                SyncKeyGen::new(id, sk, pub_keys.clone(), threshold, &mut rng).unwrap_or_else(
                    |_| panic!("Failed to create `SyncKeyGen` instance for node #{}", id),
                );
            nodes.insert(id, sync_key_gen);
            parts.push((id, opt_part.unwrap())); // Would be `None` for observer nodes.
        }

        // All nodes now handle the parts and send the resulting `Ack` messages.
        let mut acks = Vec::new();
        for (sender_id, part) in parts {
            for (&id, node) in &mut nodes {
                match node
                    .handle_part(&sender_id, part.clone(), &mut rng)
                    .expect("Failed to handle Part")
                {
                    PartOutcome::Valid(Some(ack)) => acks.push((id, ack)),
                    PartOutcome::Invalid(fault) => panic!("Invalid Part: {:?}", fault),
                    PartOutcome::Valid(None) => {
                        panic!("We are not an observer, so we should send Ack.")
                    }
                }
            }
        }

        // Finally, we handle all the `Ack`s.
        for (sender_id, ack) in acks {
            for node in nodes.values_mut() {
                match node
                    .handle_ack(&sender_id, ack.clone())
                    .expect("Failed to handle Ack")
                {
                    AckOutcome::Valid => (),
                    AckOutcome::Invalid(fault) => panic!("Invalid Ack: {:?}", fault),
                }
            }
        }

        // We have all the information and can generate the key sets.
        // Generate the public key set; which is identical for all nodes.
        let pub_key_set = nodes[&0]
            .generate()
            .expect("Failed to create `PublicKeySet` from node #0")
            .0;
        let mut secret_key_shares = BTreeMap::new();
        for (&id, node) in &mut nodes {
            assert!(node.is_ready());
            let (pks, opt_sks) = node.generate().unwrap_or_else(|_| {
                panic!(
                    "Failed to create `PublicKeySet` and `SecretKeyShare` for node #{}",
                    id
                )
            });
            assert_eq!(pks, pub_key_set); // All nodes now know the public keys and public key shares.
            let sks = opt_sks.expect("Not an observer node: We receive a secret key share.");
            secret_key_shares.insert(id, sks);
        }

        // Two out of four nodes can now sign a message. Each share can be verified individually.
        let msg = "Nodes 0 and 1 does not agree with this.";
        let mut sig_shares: BTreeMap<usize, SignatureShare> = BTreeMap::new();
        for (&id, sks) in &secret_key_shares {
            if id != 0 && id != 1 {
                let sig_share = sks.sign(msg);
                let pks = pub_key_set.public_key_share(id);
                assert!(pks.verify(&sig_share, msg));
                sig_shares.insert(id, sig_share);
            }
        }

        // Two signatures are over the threshold. They are enough to produce a signature that matches
        // the public master key.
        let sig = pub_key_set
            .combine_signatures(&sig_shares)
            .expect("The shares can be combined.");
        assert!(pub_key_set.public_key().verify(&sig, msg));
    }

    #[test]
    fn test_threshold() -> Result<()> {
        for nodes_num in 2..10 {
            // for threshold in 1..((nodes_num-1)/2+1) {
            for threshold in 1..nodes_num {
                println!("Testing for threshold {}/{}...", threshold, nodes_num);

                let (secret_key_shares, pub_key_set) = simulate_dkg_round(nodes_num, threshold)?;
                let msg = "signed message";

                // check threshold + 1 sigs matches master key
                let mut sig_shares: BTreeMap<usize, SignatureShare> = BTreeMap::new();
                for (id, sks) in &secret_key_shares[0..threshold + 1] {
                    let sig_share = sks.sign(msg);
                    let pks = pub_key_set.public_key_share(id);
                    assert!(pks.verify(&sig_share, msg));
                    sig_shares.insert(*id, sig_share);
                }
                let sig = pub_key_set
                    .combine_signatures(&sig_shares)
                    .map_err(|err| eyre!("The shares can be combined: {err:?}"))?;
                assert!(pub_key_set.public_key().verify(&sig, msg));

                // check threshold sigs are not enough to match master key
                let mut sig_shares: BTreeMap<usize, SignatureShare> = BTreeMap::new();
                for (id, sks) in &secret_key_shares[0..threshold] {
                    let sig_share = sks.sign(msg);
                    let pks = pub_key_set.public_key_share(id);
                    assert!(pks.verify(&sig_share, msg));
                    sig_shares.insert(*id, sig_share);
                }
                let _sig = pub_key_set.combine_signatures(&sig_shares).is_err();
            }
        }
        Ok(())
    }

    // Test helpers
    #[allow(clippy::type_complexity)]
    fn init_nodes<R: bls::rand::RngCore>(
        num_nodes: usize,
        threshold: usize,
        rng: &mut R,
    ) -> Result<(BTreeMap<usize, SyncKeyGen<usize>>, Vec<(usize, Part)>)> {
        let sec_keys: Vec<SecretKey> = (0..num_nodes).map(|_| bls::rand::random()).collect();
        let pub_keys: BTreeMap<usize, PublicKey> = sec_keys
            .iter()
            .map(SecretKey::public_key)
            .enumerate()
            .collect();

        let mut nodes = BTreeMap::new();
        let mut parts = Vec::new();
        for (id, sk) in sec_keys.into_iter().enumerate() {
            let (sync_key_gen, opt_part) =
                SyncKeyGen::new(id, sk, pub_keys.clone(), threshold, rng)?;
            nodes.insert(id, sync_key_gen);
            parts.push((id, opt_part.unwrap())); // Would be `None` for observer nodes.
        }

        Ok((nodes, parts))
    }

    fn handle_parts<R: bls::rand::RngCore>(
        nodes: &mut BTreeMap<usize, SyncKeyGen<usize>>,
        parts: &Vec<(usize, Part)>,
        rng: &mut R,
    ) -> Result<Vec<(usize, Ack)>> {
        let mut acks = Vec::new();
        for (sender_id, part) in parts {
            for (&id, node) in nodes.iter_mut() {
                match node.handle_part(sender_id, part.clone(), rng)? {
                    PartOutcome::Valid(Some(ack)) => acks.push((id, ack)),
                    _ => return Err(eyre!("We are an observer/invalid part")),
                }
            }
        }
        Ok(acks)
    }

    fn handle_acks(
        nodes: &mut BTreeMap<usize, SyncKeyGen<usize>>,
        acks: &Vec<(usize, Ack)>,
    ) -> Result<()> {
        for (sender_id, ack) in acks {
            for node in nodes.values_mut() {
                match node
                    .handle_ack(sender_id, ack.clone())
                    .map_err(|err| eyre!("Failed to handle Ack {err:?}"))?
                {
                    AckOutcome::Valid => (),
                    AckOutcome::Invalid(fault) => return Err(eyre!("Invalid Ack {fault:?}")),
                }
            }
        }
        Ok(())
    }

    fn gen_key_share(
        nodes: &mut BTreeMap<usize, SyncKeyGen<usize>>,
    ) -> Result<(Vec<(usize, SecretKeyShare)>, PublicKeySet)> {
        let mut pk_set = BTreeSet::new();

        let mut secret_key_shares = Vec::new();
        for (&id, node) in nodes {
            if !node.is_ready() {
                return Err(eyre!("Node: {id} is not ready"));
            }
            let (pks, opt_sks) = node.generate()?;
            let sks = opt_sks.ok_or_else(|| eyre!("Node: {id} is an observer"))?;
            pk_set.insert(pks);
            secret_key_shares.push((id, sks));
        }

        // verify that they produced a single pks
        if pk_set.len() != 1 {
            return Err(eyre!("The pub_key_set is not the same for all the nodes"));
        }
        let pk_set = Vec::from_iter(pk_set.into_iter());

        Ok((secret_key_shares, pk_set[0].clone()))
    }

    fn simulate_dkg_round(
        num_nodes: usize,
        threshold: usize,
    ) -> Result<(Vec<(usize, SecretKeyShare)>, PublicKeySet)> {
        let mut rng = bls::rand::rngs::OsRng;

        let (mut nodes, parts) = init_nodes(num_nodes, threshold, &mut rng)?;
        let acks = handle_parts(&mut nodes, &parts, &mut rng)?;
        handle_acks(&mut nodes, &acks)?;
        gen_key_share(&mut nodes)
    }

    pub(crate) fn verify_threshold(
        threshold: usize,
        sk_shares: &[(usize, SecretKeyShare)],
        pk_set: &PublicKeySet,
    ) -> Result<()> {
        let msg = "verify threshold";
        let mut sig_shares: BTreeMap<usize, SignatureShare> = BTreeMap::new();

        for (id, sks) in sk_shares.iter().take(threshold + 1) {
            let sig_share = sks.sign(msg);
            let pks = pk_set.public_key_share(id);
            if !pks.verify(&sig_share, msg) {
                return Err(eyre!("The pub_key_share cannot verify the sig"));
            }
            sig_shares.insert(*id, sig_share);
        }

        let sig = pk_set.combine_signatures(&sig_shares)?;

        if !pk_set.public_key().verify(&sig, msg) {
            return Err(eyre!("The pub_key_set cannot verify the sig"));
        }

        Ok(())
    }
}
