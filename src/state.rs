// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls::{PublicKey, PublicKeySet, SecretKey, SecretKeyShare, Signature};
use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::knowledge::{Knowledge, KnowledgeFault};
use crate::sdkg::{AckOutcome, Part, PartOutcome, SyncKeyGen};
use crate::vote::{DkgSignedVote, DkgVote, IdAck, IdPart, NodeId};

/// State of the Dkg session, contains the sync keygen and currently known Parts and Acks
/// Can handle votes coming from other participants
pub struct DkgState {
    id: NodeId,
    secret_key: SecretKey,
    pub_keys: BTreeMap<NodeId, PublicKey>,
    keygen: SyncKeyGen<NodeId>,
    our_part: Part,
    all_votes: BTreeSet<DkgSignedVote>,
}

/// State after handling a vote
pub enum VoteResponse {
    /// We need more votes to decide on anything yet
    WaitingForMoreVotes,
    /// Broadcast our vote to the other participants
    BroadcastVote(Box<DkgSignedVote>),
    /// We are missing information to understand this vote
    RequestAntiEntropy,
    /// DKG is completed on our side
    DkgComplete(PublicKeySet, SecretKeyShare),
}

enum DkgCurrentState {
    IncompatibleVotes,
    MissingParts,
    MissingAcks,
    Termination(BTreeMap<IdPart, BTreeSet<IdAck>>),
    WaitingForTotalAgreement(BTreeMap<IdPart, BTreeSet<IdAck>>),
    GotAllAcks(BTreeMap<IdPart, BTreeSet<IdAck>>),
    WaitingForMoreAcks(BTreeSet<IdPart>),
    GotAllParts(BTreeSet<IdPart>),
    WaitingForMoreParts,
}

impl DkgState {
    /// Creates a new DkgState for a new DKG session with all the participants in `pub_keys`
    /// Each participant needs to have a unique NodeId and a unique public key
    /// The threshold is the desired threshold for the generated bls key set
    pub fn new<R: bls::rand::RngCore>(
        our_id: NodeId,
        secret_key: SecretKey,
        pub_keys: BTreeMap<NodeId, PublicKey>,
        threshold: usize,
        mut rng: R,
    ) -> Result<Self> {
        let (sync_key_gen, opt_part) = SyncKeyGen::new(
            our_id,
            secret_key.clone(),
            pub_keys.clone(),
            threshold,
            &mut rng,
        )?;
        Ok(DkgState {
            id: our_id,
            secret_key,
            pub_keys,
            keygen: sync_key_gen,
            all_votes: BTreeSet::new(),
            our_part: opt_part.ok_or(Error::NotInPubKeySet)?,
        })
    }

    /// Our own NodeId
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Return the 1st vote with our Part and save it in our knowledge
    pub fn first_vote(&mut self) -> Result<DkgSignedVote> {
        let vote = DkgVote::SinglePart(self.our_part.clone());
        let signed_vote = self.signed_vote(vote)?;
        self.all_votes.insert(signed_vote.clone());
        Ok(signed_vote)
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
            Err(KnowledgeFault::MissingParts) => {
                return DkgCurrentState::MissingParts;
            }
            Err(KnowledgeFault::MissingAcks) => {
                return DkgCurrentState::MissingAcks;
            }
            Ok(k) => k,
        };

        let num_participants = self.pub_keys.len();
        if knowledge.agreed_with_all_acks.len() == num_participants {
            DkgCurrentState::Termination(knowledge.part_acks)
        } else if !knowledge.agreed_with_all_acks.is_empty() {
            DkgCurrentState::WaitingForTotalAgreement(knowledge.part_acks)
        } else if knowledge.got_all_acks(num_participants) {
            DkgCurrentState::GotAllAcks(knowledge.part_acks)
        } else if !knowledge.part_acks.is_empty() {
            DkgCurrentState::WaitingForMoreAcks(knowledge.parts)
        } else if knowledge.parts.len() == num_participants {
            DkgCurrentState::GotAllParts(knowledge.parts)
        } else {
            DkgCurrentState::WaitingForMoreParts
        }
    }

    // checks in our current knowledge if we sent our AllAcks
    fn we_sent_our_all_acks(&self) -> bool {
        let our_id = self.id();
        self.all_votes
            .iter()
            .filter(|v| v.is_all_acks())
            .any(|v| v.voter == our_id)
    }

    // Current DKG state taking last vote's type into account
    fn dkg_state_with_vote(
        &self,
        votes: Vec<(DkgVote, NodeId)>,
        vote: &DkgVote,
    ) -> DkgCurrentState {
        let dkg_state = self.current_dkg_state(votes);
        match dkg_state {
            // This case happens when we receive the last Part but we already received
            // someone's acks before, making us skip GotAllParts as we already have an Ack
            DkgCurrentState::WaitingForMoreAcks(parts)
                if matches!(vote, DkgVote::SinglePart(_)) =>
            {
                DkgCurrentState::GotAllParts(parts)
            }
            // Another case is when we didn't send our own AllAcks yet
            DkgCurrentState::WaitingForTotalAgreement(part_acks)
                if !self.we_sent_our_all_acks() =>
            {
                DkgCurrentState::GotAllAcks(part_acks)
            }
            // This is when we already have votes for the next step in store so our global state
            // is that we're missing votes, since this vote is of the expected type,
            // we don't need to report the error again
            DkgCurrentState::MissingParts if matches!(vote, DkgVote::SinglePart(_)) => {
                DkgCurrentState::WaitingForMoreParts
            }
            DkgCurrentState::MissingAcks if matches!(vote, DkgVote::SingleAck(_)) => {
                DkgCurrentState::WaitingForMoreAcks(Default::default())
            }
            _ => dkg_state,
        }
    }

    pub fn sign_vote(&self, vote: &DkgVote) -> Result<Signature> {
        let sig = self.secret_key.sign(&bincode::serialize(vote)?);
        Ok(sig)
    }

    /// Sign and return the vote
    fn signed_vote(&mut self, vote: DkgVote) -> Result<DkgSignedVote> {
        let sig = self.sign_vote(&vote)?;
        let signed_vote = DkgSignedVote::new(vote, self.id, sig);
        Ok(signed_vote)
    }

    /// Handles all the Acks
    fn handle_all_acks(&mut self, all_acks: BTreeMap<IdPart, BTreeSet<IdAck>>) -> Result<()> {
        for ((part_id, _part), acks) in all_acks {
            for (sender_id, ack) in acks {
                let outcome = self.keygen.handle_ack(&sender_id, ack.clone())?;
                if let AckOutcome::Invalid(fault) = outcome {
                    return Err(Error::FaultyVote(format!(
                        "Ack fault: {fault:?} by {sender_id:?} for part by {part_id:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Handles the Parts to create the Acks
    fn parts_into_acks<R: bls::rand::RngCore>(
        &mut self,
        parts: BTreeSet<IdPart>,
        mut rng: R,
    ) -> Result<DkgVote> {
        let mut acks = BTreeMap::new();
        for (sender_id, part) in parts {
            match self
                .keygen
                .handle_part(&sender_id, part.clone(), &mut rng)?
            {
                PartOutcome::Valid(Some(ack)) => {
                    acks.insert((sender_id, part), ack);
                }
                PartOutcome::Invalid(fault) => {
                    return Err(Error::FaultyVote(format!(
                        "Part fault: {fault:?} by {sender_id:?}"
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

    /// Returns all the votes that we received
    pub fn all_votes(&self) -> Vec<DkgSignedVote> {
        self.all_votes.iter().cloned().collect()
    }

    /// After termination, returns Some keypair else returns None
    /// This function assumes that the Acks have been processed before hand
    /// when receiving the final ack vote
    pub fn outcome(&self) -> Result<Option<(PublicKeySet, SecretKeyShare)>> {
        let votes = self.all_checked_votes()?;
        if let DkgCurrentState::Termination(_) = self.current_dkg_state(votes) {
            if let (pubs, Some(sec)) = self.keygen.generate()? {
                Ok(Some((pubs, sec)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Checks if we reached termination
    pub fn reached_termination(&self) -> Result<bool> {
        let votes = self.all_checked_votes()?;
        let state = self.current_dkg_state(votes);
        Ok(matches!(state, DkgCurrentState::Termination(_)))
    }

    /// Handle a DKG vote, save the information if we learned any, broadcast:
    /// - SingleAck when got all parts
    /// - AllAcks when got all acks
    /// Consider we reached completion when we received everyone's signatures over the AllAcks
    /// Return a vec with the reactions to the handled vote
    /// An empty vec means we didn't learn anything from this msg because we alread received it
    pub fn handle_signed_vote<R: bls::rand::RngCore>(
        &mut self,
        msg: DkgSignedVote,
        mut rng: R,
    ) -> Result<Vec<VoteResponse>> {
        // if already seen it, ignore it
        if self.all_votes.contains(&msg) {
            return Ok(vec![]);
        }

        // immediately bail if signature check fails
        let last_vote = self.get_validated_vote(&msg)?;

        // update knowledge with vote
        let _ = self.all_votes.insert(msg);
        let votes = self.all_checked_votes()?;
        let dkg_state = self.dkg_state_with_vote(votes, &last_vote);

        // act accordingly
        match dkg_state {
            DkgCurrentState::MissingParts | DkgCurrentState::MissingAcks => {
                Ok(vec![VoteResponse::RequestAntiEntropy])
            }
            DkgCurrentState::Termination(acks) => {
                self.handle_all_acks(acks)?;
                if let (pubs, Some(sec)) = self.keygen.generate()? {
                    Ok(vec![VoteResponse::DkgComplete(pubs, sec)])
                } else {
                    Err(Error::FailedToGenerateSecretKeyShare)
                }
            }
            DkgCurrentState::GotAllAcks(acks) => {
                let vote = DkgVote::AllAcks(acks);
                let signed_vote = self.signed_vote(vote)?;
                let mut res = vec![VoteResponse::BroadcastVote(Box::new(signed_vote.clone()))];
                let our_vote_res = self.handle_signed_vote(signed_vote, rng)?;
                if !matches!(our_vote_res.as_slice(), [VoteResponse::WaitingForMoreVotes]) {
                    res.extend(our_vote_res);
                }
                Ok(res)
            }
            DkgCurrentState::GotAllParts(parts) => {
                let vote = self.parts_into_acks(parts, &mut rng)?;
                let signed_vote = self.signed_vote(vote)?;
                let mut res = vec![VoteResponse::BroadcastVote(Box::new(signed_vote.clone()))];
                let our_vote_res = self.handle_signed_vote(signed_vote, rng)?;
                if !matches!(our_vote_res.as_slice(), [VoteResponse::WaitingForMoreVotes]) {
                    res.extend(our_vote_res);
                }
                Ok(res)
            }
            DkgCurrentState::WaitingForMoreParts
            | DkgCurrentState::WaitingForMoreAcks(_)
            | DkgCurrentState::WaitingForTotalAgreement(_) => {
                Ok(vec![VoteResponse::WaitingForMoreVotes])
            }
            DkgCurrentState::IncompatibleVotes => {
                Err(Error::FaultyVote("got incompatible votes".to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recursive_handle_vote() {
        let mut rng = bls::rand::rngs::OsRng;
        let sec_key0: SecretKey = bls::rand::random();
        let pub_keys: BTreeMap<u8, PublicKey> = BTreeMap::from([(0, sec_key0.public_key())]);

        let threshold = 1;
        let mut dkg_state0 = DkgState::new(0, sec_key0, pub_keys, threshold, &mut rng)
            .expect("Failed to create DKG state");

        // Get the first votes: Parts
        let part0 = dkg_state0.first_vote().expect("Failed to get first vote");

        // Remove our own vote from knowledge
        dkg_state0.all_votes = BTreeSet::new();

        // Handle our own vote and recursively reach termination
        let res = dkg_state0
            .handle_signed_vote(part0, &mut rng)
            .expect("failed to handle vote");
        assert!(matches!(res[0], VoteResponse::BroadcastVote(_)));
        assert!(matches!(res[1], VoteResponse::BroadcastVote(_)));
        assert!(matches!(res[2], VoteResponse::DkgComplete(_, _)));
        assert_eq!(res.len(), 3);
    }
}
