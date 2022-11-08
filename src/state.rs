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
    reached_termination: bool,
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
            reached_termination: false,
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
        let sig = self.secret_key.sign(bincode::serialize(vote)?);
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
        Ok(self.reached_termination)
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
                    self.reached_termination = true;
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
                res.extend(
                    our_vote_res
                        .into_iter()
                        .filter(|r| !matches!(r, VoteResponse::WaitingForMoreVotes)),
                );
                Ok(res)
            }
            DkgCurrentState::GotAllParts(parts) => {
                let vote = self.parts_into_acks(parts, &mut rng)?;
                let signed_vote = self.signed_vote(vote)?;
                let mut res = vec![VoteResponse::BroadcastVote(Box::new(signed_vote.clone()))];
                let our_vote_res = self.handle_signed_vote(signed_vote, rng)?;
                res.extend(
                    our_vote_res
                        .into_iter()
                        .filter(|r| !matches!(r, VoteResponse::WaitingForMoreVotes)),
                );
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
    use crate::{sdkg::tests::verify_threshold, vote::test_utils::*};
    use bls::rand::{rngs::StdRng, seq::IteratorRandom, thread_rng, Rng, RngCore, SeedableRng};
    use eyre::{eyre, Result};
    use std::env;

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

    #[test]
    fn fuzz_test() -> Result<()> {
        let mut fuzz_count = if let Ok(count) = env::var("FUZZ_TEST_COUNT") {
            count.parse::<isize>().map_err(|err| eyre!("{err}"))?
        } else {
            20
        };
        let mut rng_for_seed = thread_rng();
        let num_nodes = 7;
        let threshold = 4;

        while fuzz_count != 0 {
            let seed = rng_for_seed.gen();
            println!(" SEED {seed:?} => count_remaining: {fuzz_count}");
            let mut rng = StdRng::seed_from_u64(seed);

            let mut nodes = generate_nodes(num_nodes, threshold, &mut rng)?;
            let mut parts: BTreeMap<usize, DkgSignedVote> = BTreeMap::new();
            let mut acks: BTreeMap<usize, DkgSignedVote> = BTreeMap::new();
            let mut all_acks: BTreeMap<usize, DkgSignedVote> = BTreeMap::new();
            let mut sk_shares: BTreeMap<usize, SecretKeyShare> = BTreeMap::new();
            let mut pk_set: BTreeSet<PublicKeySet> = BTreeSet::new();

            for node in nodes.iter_mut() {
                parts.insert(node.id() as usize, node.first_vote()?);
            }

            for cmd in fuzz_commands(num_nodes, seed) {
                // println!("==> {cmd:?}");
                let (to_nodes, vote) = match cmd {
                    SendVote::Parts(from, to_nodes) => (to_nodes, parts[&from].clone()),
                    SendVote::Acks(from, to_nodes) => (to_nodes, acks[&from].clone()),
                    SendVote::AllAcks(from, to_nodes) => (to_nodes, all_acks[&from].clone()),
                };
                // send the vote to each `to` node
                for (to, expt_resp) in to_nodes {
                    let actual_resp = nodes[to].handle_signed_vote(vote.clone(), &mut rng)?;
                    assert_eq!(expt_resp.len(), actual_resp.len());
                    expt_resp
                        .into_iter()
                        .zip(actual_resp.into_iter())
                        .for_each(|(exp, actual)| {
                            assert!(exp.match_resp(
                                actual,
                                &mut acks,
                                &mut all_acks,
                                &mut sk_shares,
                                &mut pk_set,
                                to
                            ));
                        })
                }
            }

            assert_eq!(pk_set.len(), 1);
            let pk_set = pk_set.into_iter().collect::<Vec<_>>()[0].clone();
            let sk_shares: Vec<_> = sk_shares.into_iter().collect();

            assert!(verify_threshold(threshold, &sk_shares, &pk_set).is_ok());
            fuzz_count -= 1;
        }
        Ok(())
    }

    // Returns a list of `SendVote` which when executed in that order will simulate a DKG round from start to completion
    // for each node
    fn fuzz_commands(num_nodes: usize, seed: u64) -> Vec<SendVote> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut nodes = MockNode::new(num_nodes);
        // probability for a node to resend vote to another node which has already handled it.
        let resend_probability = Some((1, 5));
        // these nodes are required to help other nodes terminate
        let mut active_nodes = MockNode::active_nodes(&nodes);
        let mut commands = Vec::new();

        while !active_nodes.is_empty() {
            // get a random active node
            let current_node = active_nodes[rng.gen::<usize>() % active_nodes.len()];

            // check if current_node can send part/acks/all_acks.
            let parts = nodes[current_node].can_send_parts(&nodes, resend_probability, &mut rng);
            let acks = nodes[current_node].can_send_acks(&nodes, resend_probability, &mut rng);
            let all_acks =
                nodes[current_node].can_send_all_acks(&nodes, resend_probability, &mut rng);

            // continue if current_node cant progress
            if parts.is_empty() && acks.is_empty() && all_acks.is_empty() {
                continue;
            }

            let mut done = false;
            // randomly send out part/acks/all_acks
            while !done {
                match rng.gen::<usize>() % 3 {
                    0 if !parts.is_empty() => {
                        let to_nodes = MockNode::sample_nodes(&parts, &mut rng);

                        // update each `to` node and get its (id, response)
                        let to_nodes_resp = to_nodes
                            .into_iter()
                            .map(|to| {
                                let mut resp = Vec::new();
                                // skip if already handled
                                if let Some(val) = nodes[to].handled_parts.get(&current_node) {
                                    if *val {
                                        return (to, resp);
                                    }
                                }

                                if let Some(val) =
                                    nodes[to].handled_parts.insert(current_node, true)
                                {
                                    if nodes[to].parts_done() {
                                        resp.push(MockVoteResponse::BroadcastVote(
                                            MockDkgVote::SingleAck,
                                        ));
                                        // if we have handled the all the `Acks` before the parts
                                        if nodes[to].acks_done() {
                                            resp.push(MockVoteResponse::BroadcastVote(
                                                MockDkgVote::AllAcks,
                                            ));
                                        }
                                    } else {
                                        // if false, we need more votes
                                        if !val {
                                            resp.push(MockVoteResponse::WaitingForMoreVotes)
                                        }
                                    }
                                }

                                (to, resp)
                            })
                            .collect();

                        commands.push(SendVote::Parts(current_node, to_nodes_resp));
                        done = true;
                    }
                    1 if !acks.is_empty() => {
                        let to_nodes = MockNode::sample_nodes(&acks, &mut rng);

                        let to_nodes_resp = to_nodes
                            .into_iter()
                            .map(|to| {
                                let mut resp = Vec::new();
                                // skip if already handled
                                if let Some(val) = nodes[to].handled_acks.get(&current_node) {
                                    if *val {
                                        return (to, resp);
                                    }
                                }
                                let res = nodes[to].handled_acks.insert(current_node, true);
                                // if our parts are not done, we will not understand this vote
                                if !nodes[to].parts_done() {
                                    resp.push(MockVoteResponse::RequestAntiEntropy)
                                } else if let Some(val) = res {
                                    if nodes[to].acks_done() {
                                        resp.push(MockVoteResponse::BroadcastVote(
                                            MockDkgVote::AllAcks,
                                        ));
                                        // if we have handled the all the `AllAcks` before the Acks
                                        if nodes[to].all_acks_done() {
                                            resp.push(MockVoteResponse::DkgComplete);
                                        }
                                    } else {
                                        // if false, we need more votes
                                        if !val {
                                            resp.push(MockVoteResponse::WaitingForMoreVotes)
                                        }
                                    }
                                };

                                (to, resp)
                            })
                            .collect();

                        commands.push(SendVote::Acks(current_node, to_nodes_resp));
                        done = true
                    }
                    2 if !all_acks.is_empty() => {
                        let to_nodes = MockNode::sample_nodes(&all_acks, &mut rng);

                        let to_nodes_resp = to_nodes
                            .into_iter()
                            .map(|to| {
                                let mut resp = Vec::new();
                                // skip if already handled
                                if let Some(val) = nodes[to].handled_all_acks.get(&current_node) {
                                    if *val {
                                        return (to, resp);
                                    }
                                }
                                let res = nodes[to].handled_all_acks.insert(current_node, true);

                                // if our Acks are not done, we will not understand this vote
                                if !nodes[to].acks_done() {
                                    resp.push(MockVoteResponse::RequestAntiEntropy);
                                } else if let Some(val) = res {
                                    if nodes[to].all_acks_done() {
                                        resp.push(MockVoteResponse::DkgComplete)
                                    } else {
                                        // if false, we need more votes
                                        if !val {
                                            resp.push(MockVoteResponse::WaitingForMoreVotes)
                                        }
                                    }
                                };
                                (to, resp)
                            })
                            .collect();

                        commands.push(SendVote::AllAcks(current_node, to_nodes_resp));
                        done = true;
                    }
                    // happens if the rng lands on a vote list (e.g., all_acks) that is empty
                    _ => {}
                }
            }

            active_nodes = MockNode::active_nodes(&nodes);
        }
        commands
    }

    // Test helpers
    fn generate_nodes<R: RngCore>(
        num_nodes: usize,
        threshold: usize,
        mut rng: &mut R,
    ) -> Result<Vec<DkgState>> {
        let secret_keys: Vec<SecretKey> = (0..num_nodes).map(|_| bls::rand::random()).collect();
        let pub_keys: BTreeMap<_, _> = secret_keys
            .iter()
            .enumerate()
            .map(|(id, sk)| (id as u8, sk.public_key()))
            .collect();
        secret_keys
            .iter()
            .enumerate()
            .map(|(id, sk)| {
                DkgState::new(id as u8, sk.clone(), pub_keys.clone(), threshold, &mut rng)
                    .map_err(|err| eyre!("{err}"))
            })
            .collect()
    }

    #[derive(Debug)]
    enum SendVote {
        // from_node, list of (to_node, vec of response when handled)
        Parts(usize, Vec<(usize, Vec<MockVoteResponse>)>),
        Acks(usize, Vec<(usize, Vec<MockVoteResponse>)>),
        AllAcks(usize, Vec<(usize, Vec<MockVoteResponse>)>),
    }

    #[derive(Debug)]
    enum MockVoteResponse {
        WaitingForMoreVotes,
        BroadcastVote(MockDkgVote),
        RequestAntiEntropy,
        DkgComplete,
    }

    impl PartialEq<VoteResponse> for MockVoteResponse {
        fn eq(&self, other: &VoteResponse) -> bool {
            match self {
                MockVoteResponse::WaitingForMoreVotes
                    if matches!(other, VoteResponse::WaitingForMoreVotes) =>
                {
                    true
                }
                MockVoteResponse::BroadcastVote(mock_vote) => {
                    if let VoteResponse::BroadcastVote(signed_vote) = other {
                        *mock_vote == **signed_vote
                    } else {
                        false
                    }
                }

                MockVoteResponse::RequestAntiEntropy
                    if matches!(other, VoteResponse::RequestAntiEntropy) =>
                {
                    true
                }
                MockVoteResponse::DkgComplete
                    if matches!(other, VoteResponse::DkgComplete(_, _)) =>
                {
                    true
                }
                _ => false,
            }
        }
    }

    impl MockVoteResponse {
        pub fn match_resp(
            &self,
            actual_resp: VoteResponse,
            update_acks: &mut BTreeMap<usize, DkgSignedVote>,
            update_all_acks: &mut BTreeMap<usize, DkgSignedVote>,
            update_sk: &mut BTreeMap<usize, SecretKeyShare>,
            update_pk: &mut BTreeSet<PublicKeySet>,
            id: usize,
        ) -> bool {
            if *self == actual_resp {
                match actual_resp {
                    VoteResponse::BroadcastVote(vote) if MockDkgVote::SingleAck == *vote => {
                        update_acks.insert(id, *vote);
                    }
                    VoteResponse::BroadcastVote(vote) if MockDkgVote::AllAcks == *vote => {
                        update_all_acks.insert(id, *vote);
                    }
                    VoteResponse::DkgComplete(pk, sk) => {
                        update_pk.insert(pk);
                        update_sk.insert(id, sk);
                    }
                    _ => {}
                }
                true
            } else {
                false
            }
        }
    }

    #[derive(Debug)]
    struct MockNode {
        id: usize,
        // Has the current node handled parts, acks, all_acks from another node?
        handled_parts: BTreeMap<usize, bool>,
        handled_acks: BTreeMap<usize, bool>,
        handled_all_acks: BTreeMap<usize, bool>,
    }

    impl MockNode {
        pub fn new(num_nodes: usize) -> Vec<MockNode> {
            let mut status: BTreeMap<usize, bool> = BTreeMap::new();
            (0..num_nodes).for_each(|id| {
                let _ = status.insert(id, false);
            });
            (0..num_nodes)
                .map(|id| {
                    // we have handled our parts/acks/all_acks by default
                    let mut our_status = status.clone();
                    our_status.insert(id, true);
                    MockNode {
                        id,
                        handled_parts: our_status.clone(),
                        handled_acks: our_status.clone(),
                        handled_all_acks: our_status,
                    }
                })
                .collect()
        }

        // return the node IDs that have not handled self's part; Also choose nodes which have already handled
        // self's part with a probability of (num/den)
        pub fn can_send_parts<R: RngCore>(
            &self,
            nodes: &[MockNode],
            resend_probability: Option<(u32, u32)>,
            rng: &mut R,
        ) -> Vec<usize> {
            nodes
                .iter()
                .filter_map(|node| {
                    // if node has not handled self's part
                    if !node.handled_parts[&self.id] {
                        Some(node.id)
                    } else {
                        // resend to the node which has already handled self's part with the provided probability
                        if let Some((num, den)) = resend_probability {
                            if rng.gen_ratio(num, den) {
                                Some(node.id)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                })
                .collect()
        }

        pub fn can_send_acks<R: RngCore>(
            &self,
            nodes: &[MockNode],
            resend_probability: Option<(u32, u32)>,
            rng: &mut R,
        ) -> Vec<usize> {
            // if self has not handled the parts from other nodes, then it cant produce an ack
            if !self.parts_done() {
                return Vec::new();
            }
            // the other node should not have handled self's ack
            nodes
                .iter()
                .filter_map(|node| {
                    if !node.handled_acks[&self.id] {
                        Some(node.id)
                    } else {
                        // resend to the node which has already handled self's ack with the provided probability
                        if let Some((num, den)) = resend_probability {
                            if rng.gen_ratio(num, den) {
                                Some(node.id)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                })
                .collect()
        }

        pub fn can_send_all_acks<R: RngCore>(
            &self,
            nodes: &[MockNode],
            resend_probability: Option<(u32, u32)>,
            rng: &mut R,
        ) -> Vec<usize> {
            // // self should've handled all the acks/parts (except self's)
            if !self.parts_done() {
                return Vec::new();
            }
            if !self.acks_done() {
                return Vec::new();
            }
            // the other node should not have handled self's all_ack
            nodes
                .iter()
                .filter_map(|node| {
                    if !node.handled_all_acks[&self.id] {
                        Some(node.id)
                    } else if let Some((num, den)) = resend_probability {
                        if rng.gen_ratio(num, den) {
                            Some(node.id)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        }

        // returns true if self has received/handled all the parts (except itself)
        pub fn parts_done(&self) -> bool {
            self.handled_parts
                .iter()
                .filter(|(&id, _)| id != self.id)
                .all(|(_, &val)| val)
        }

        pub fn acks_done(&self) -> bool {
            self.handled_acks
                .iter()
                .filter(|(&id, _)| id != self.id)
                .all(|(_, &val)| val)
        }

        pub fn all_acks_done(&self) -> bool {
            // check if current_node has completed the dkg round; i.e., it has handled all_acks from all other nodes
            self.handled_all_acks
                .iter()
                .filter(|(&id, _)| id != self.id)
                .all(|(_, &val)| val)
        }

        pub fn active_nodes(nodes: &[MockNode]) -> Vec<usize> {
            // a node is active if any of the other node still requires votes from the current node
            // filter out current node as we don't necessarily have to deal with our votes to move forward
            let mut active_nodes = BTreeSet::new();
            nodes.iter().for_each(|node| {
                // check parts
                node.handled_parts.iter().for_each(|(&id, &val)| {
                    // if current node has not handled a part from another node (i.e. false), we need the other node
                    if id != node.id && !val {
                        active_nodes.insert(id);
                    };
                });

                node.handled_acks.iter().for_each(|(&id, &val)| {
                    if id != node.id && !val {
                        active_nodes.insert(id);
                    };
                });

                node.handled_all_acks.iter().for_each(|(&id, &val)| {
                    if id != node.id && !val {
                        active_nodes.insert(id);
                    };
                });
            });
            active_nodes.into_iter().collect()
        }

        // select a subset of node i's from the given list
        pub fn sample_nodes<R: RngCore>(nodes: &Vec<usize>, rng: &mut R) -> Vec<usize> {
            let sample_n_nodes = (rng.gen::<usize>() % nodes.len()) + 1;
            nodes.iter().cloned().choose_multiple(rng, sample_n_nodes)
        }
    }
}
