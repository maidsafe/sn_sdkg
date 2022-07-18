// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls::{PublicKey, PublicKeySet, SecretKey, SecretKeyShare};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::knowledge::{Knowledge, KnowledgeFault};
use crate::sdkg::{AckOutcome, Part, PartOutcome, SyncKeyGen};
use crate::vote::{DkgSignedVote, DkgVote, IdAck, IdPart, NodeId};

/// State of the Dkg session, contains the sync keygen and currently known Parts and Acks
/// Can handle votes coming from other participants
pub struct DkgState<R: bls::rand::RngCore> {
    id: NodeId,
    secret_key: SecretKey,
    pub_keys: BTreeMap<NodeId, PublicKey>,
    keygen: SyncKeyGen<NodeId>,
    our_part: Part,
    all_votes: BTreeSet<DkgSignedVote>,
    rng: R,
}

pub enum VoteResponse {
    WaitingForMoreVotes,
    BroadcastVote(Box<DkgSignedVote>),
    RequestAntiEntropy,
    AntiEntropy(BTreeSet<DkgSignedVote>),
    DkgComplete(PublicKeySet, SecretKeyShare),
}

enum DkgCurrentState {
    IncompatibleVotes,
    NeedAntiEntropy,
    Termination(BTreeMap<IdPart, BTreeSet<IdAck>>),
    WaitingForTotalAgreement,
    GotAllAcks(BTreeMap<IdPart, BTreeSet<IdAck>>),
    WaitingForMoreAcks,
    GotAllParts(BTreeSet<IdPart>),
    WaitingForMoreParts,
}

impl<R: bls::rand::RngCore + Clone> DkgState<R> {
    pub fn new(
        our_id: NodeId,
        secret_key: SecretKey,
        pub_keys: BTreeMap<NodeId, PublicKey>,
        threshold: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let (sync_key_gen, opt_part) = SyncKeyGen::new(
            our_id,
            secret_key.clone(),
            Arc::new(pub_keys.clone()),
            threshold,
            rng,
        )?;
        Ok(DkgState {
            id: our_id,
            secret_key,
            pub_keys,
            keygen: sync_key_gen,
            all_votes: BTreeSet::new(),
            our_part: opt_part.ok_or(Error::NotInPubKeySet)?,
            rng: rng.clone(),
        })
    }

    /// The 1st vote with our Part
    pub fn first_vote(&mut self) -> Result<DkgSignedVote> {
        let vote = DkgVote::SinglePart(self.our_part.clone());
        self.cast_vote(vote)
    }

    fn get_validated_vote(&self, vote: &DkgSignedVote) -> Result<DkgVote> {
        let sender_id = vote.voter;
        let sender_pub_key = self.pub_keys.get(&sender_id).ok_or(Error::UnknownSender)?;
        let vote = vote.get_validated_vote(sender_pub_key)?;
        Ok(vote)
    }

    fn all_checked_votes(&self) -> Result<Vec<(DkgVote, NodeId)>> {
        self.all_votes
            .iter()
            .map(|v| Ok((self.get_validated_vote(v)?, v.voter)))
            .collect()
    }

    fn current_dkg_state(&self, votes: Vec<(DkgVote, NodeId)>) -> DkgCurrentState {
        let knowledge = match Knowledge::from_votes(votes) {
            Err(KnowledgeFault::IncompatibleAcks) | Err(KnowledgeFault::IncompatibleParts) => {
                return DkgCurrentState::IncompatibleVotes;
            }
            Err(KnowledgeFault::MissingParts) | Err(KnowledgeFault::MissingAcks) => {
                return DkgCurrentState::NeedAntiEntropy;
            }
            Ok(k) => k,
        };

        let participants_len = self.pub_keys.len();
        if knowledge.agreed_with_all_acks.len() == participants_len {
            DkgCurrentState::Termination(knowledge.part_acks)
        } else if !knowledge.agreed_with_all_acks.is_empty() {
            DkgCurrentState::WaitingForTotalAgreement
        } else if knowledge.got_all_acks(participants_len) {
            DkgCurrentState::GotAllAcks(knowledge.part_acks)
        } else if !knowledge.part_acks.is_empty() {
            DkgCurrentState::WaitingForMoreAcks
        } else if knowledge.parts.len() == participants_len {
            DkgCurrentState::GotAllParts(knowledge.parts)
        } else {
            DkgCurrentState::WaitingForMoreParts
        }
    }

    /// Sign, log and return the vote
    fn cast_vote(&mut self, vote: DkgVote) -> Result<DkgSignedVote> {
        let sig = self.secret_key.sign(&bincode::serialize(&vote)?);
        let signed_vote = DkgSignedVote::new(vote, self.id, sig);
        self.all_votes.insert(signed_vote.clone());
        Ok(signed_vote)
    }

    /// Handles all the Acks
    fn handle_all_acks(&mut self, all_acks: BTreeMap<IdPart, BTreeSet<IdAck>>) -> Result<()> {
        for ((part_id, _part), acks) in all_acks {
            for (sender_id, ack) in acks {
                let outcome = self.keygen.handle_ack(&sender_id, ack.clone())?;
                if let AckOutcome::Invalid(fault) = outcome {
                    return Err(Error::FaultyVote(format!(
                        "Ack fault: {:?} by {:?} for part by {:?}",
                        fault, sender_id, part_id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Handles the Parts to create the Acks
    fn parts_into_acks(&mut self, parts: BTreeSet<IdPart>) -> Result<DkgVote> {
        let mut acks = BTreeMap::new();
        for (sender_id, part) in parts {
            match self
                .keygen
                .handle_part(&sender_id, part.clone(), &mut self.rng)?
            {
                PartOutcome::Valid(Some(ack)) => {
                    acks.insert((sender_id, part), ack);
                }
                PartOutcome::Invalid(fault) => {
                    return Err(Error::FaultyVote(format!(
                        "Part fault: {:?} by {:?}",
                        fault, sender_id
                    )));
                }
                PartOutcome::Valid(None) => {
                    // code smell: we don't have observer nodes and we can't end up here if we've
                    // handled parts and given our acks already, this should not happen unless our
                    // votes were corrupted
                    return Err(Error::FaultyVote("unexpected part outcome, node is faulty or keygen already handled this part".to_string()));
                }
            }
        }
        Ok(DkgVote::SingleAck(acks))
    }

    /// Returns all the votes that we received as an anti entropy update
    pub fn handle_ae(&self) -> VoteResponse {
        VoteResponse::AntiEntropy(self.all_votes.clone())
    }

    /// Handle a DKG vote, save the information if we learned any, broadcast:
    /// - SingleAck when got all parts
    /// - AllAcks when got all acks
    /// Consider we reached completion when we received everyone's signatures over the AllAcks
    pub fn handle_signed_vote(&mut self, msg: DkgSignedVote) -> Result<VoteResponse> {
        // immediately bail if signature check fails
        self.get_validated_vote(&msg)?;

        // update knowledge with vote
        self.all_votes.insert(msg);
        let votes = self.all_checked_votes()?;
        let dkg_state = self.current_dkg_state(votes);

        // act accordingly
        match dkg_state {
            DkgCurrentState::NeedAntiEntropy => Ok(VoteResponse::RequestAntiEntropy),
            DkgCurrentState::Termination(acks) => {
                self.handle_all_acks(acks)?;
                if let (pubs, Some(sec)) = self.keygen.generate()? {
                    Ok(VoteResponse::DkgComplete(pubs, sec))
                } else {
                    Err(Error::FailedToGenerateSecretKeyShare)
                }
            }
            DkgCurrentState::GotAllAcks(acks) => {
                let vote = DkgVote::AllAcks(acks);
                Ok(VoteResponse::BroadcastVote(Box::new(self.cast_vote(vote)?)))
            }
            DkgCurrentState::GotAllParts(parts) => {
                let vote = self.parts_into_acks(parts)?;
                Ok(VoteResponse::BroadcastVote(Box::new(self.cast_vote(vote)?)))
            }
            DkgCurrentState::WaitingForMoreParts
            | DkgCurrentState::WaitingForMoreAcks
            | DkgCurrentState::WaitingForTotalAgreement => Ok(VoteResponse::WaitingForMoreVotes),
            DkgCurrentState::IncompatibleVotes => {
                Err(Error::FaultyVote("got incompatible votes".to_string()))
            }
        }
    }
}
