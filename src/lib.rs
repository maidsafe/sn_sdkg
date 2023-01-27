// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod debug;
pub(crate) mod error;
pub(crate) mod knowledge;
pub mod sdkg;
mod state;
pub(crate) mod vote;

pub use error::Error;
pub use state::{DkgState, VoteResponse};
pub use vote::{DkgSignedVote, NodeId};

// For testing purposes
pub use vote::DkgVote;

// fancy assert_match that returns inside content
// usage:
// `let data = assert_match(item_with_data, Enum::Pattern(data) => data)`
#[cfg(test)]
macro_rules! assert_match {
   ($obj:expr, $pattern:pat $(if $pred:expr)* => $result:expr) => {
       match $obj {
           $pattern $(if $pred)* => $result,
           _ => panic!("Assertion failed")
       }
   }
}
#[cfg(test)]
pub(crate) use assert_match;

// Test of sn_sdkg with explanations and usage example
#[cfg(test)]
mod tests {
    use super::*;
    use bls::{PublicKey, SecretKey, SignatureShare};
    use std::collections::BTreeMap;

    /// This test explains how sn_sdkg should be used
    #[test]
    fn test_dkg_for_the_rest_of_us() {
        // Use the OS random number generator for any randomness:
        let mut rng = bls::rand::rngs::OsRng;

        // Generate individual key pairs for encryption. These are not suitable for threshold schemes.
        let sec_key0: SecretKey = bls::rand::random();
        let sec_key1: SecretKey = bls::rand::random();
        let sec_key2: SecretKey = bls::rand::random();

        let pub_keys: BTreeMap<u8, PublicKey> = BTreeMap::from([
            (0, sec_key0.public_key()),
            (1, sec_key1.public_key()),
            (2, sec_key2.public_key()),
        ]);

        // Create a DkgState for each participants
        let threshold = 1;
        let mut dkg_state0 = DkgState::new(0, sec_key0, pub_keys.clone(), threshold, &mut rng)
            .expect("Failed to create DKG state");
        let mut dkg_state1 = DkgState::new(1, sec_key1, pub_keys.clone(), threshold, &mut rng)
            .expect("Failed to create DKG state");
        let mut dkg_state2 = DkgState::new(2, sec_key2, pub_keys, threshold, &mut rng)
            .expect("Failed to create DKG state");

        // Get the first votes: Parts
        let part0 = dkg_state0.first_vote().expect("Failed to get first vote");
        let part1 = dkg_state1.first_vote().expect("Failed to get first vote");
        let part2 = dkg_state2.first_vote().expect("Failed to get first vote");

        // Handle the other participants Parts, obtain Acks
        // No need to handle our own vote
        // Participant 0 handles Parts
        // We already know this vote (it's ours), just checking that it gives vec![]
        let res = &dkg_state0.handle_signed_vote(part0.clone(), &mut rng);
        assert!(matches!(res.as_deref(), Ok([])));
        let res = &dkg_state0.handle_signed_vote(part1.clone(), &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state0.handle_signed_vote(part2.clone(), &mut rng);
        let acks0 =
            assert_match!(res.as_deref(), Ok([VoteResponse::BroadcastVote(acks)]) => *acks.clone());
        // Participant 1 handles Parts
        let res = &dkg_state1.handle_signed_vote(part0.clone(), &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state1.handle_signed_vote(part2, &mut rng);
        let acks1 =
            assert_match!(res.as_deref(), Ok([VoteResponse::BroadcastVote(acks)]) => *acks.clone());
        // Participant 2 handles Parts
        let res = &dkg_state2.handle_signed_vote(part0, &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state2.handle_signed_vote(part1, &mut rng);
        let acks2 =
            assert_match!(res.as_deref(), Ok([VoteResponse::BroadcastVote(acks)]) => *acks.clone());

        // Now that every participant handled the Parts and submitted their Acks, we handle the Acks
        // Participant 0 handles Acks
        let res = &dkg_state0.handle_signed_vote(acks1.clone(), &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state0.handle_signed_vote(acks2.clone(), &mut rng);
        let all_acks0 = assert_match!(res.as_deref(), Ok([VoteResponse::BroadcastVote(all_acks)]) => *all_acks.clone());
        // Participant 1 handles Acks
        let res = &dkg_state1.handle_signed_vote(acks0.clone(), &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state1.handle_signed_vote(acks2, &mut rng);
        let all_acks1 = assert_match!(res.as_deref(), Ok([VoteResponse::BroadcastVote(all_acks)]) => *all_acks.clone());
        // Participant 2 handles Acks
        let res = &dkg_state2.handle_signed_vote(acks0, &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state2.handle_signed_vote(acks1, &mut rng);
        let all_acks2 = assert_match!(res.as_deref(), Ok([VoteResponse::BroadcastVote(all_acks)]) => *all_acks.clone());

        // Now that we have all the Acks, we check that everyone has the same set
        // Handle the set of all acks to check everyone agreed on the same set
        // Participant 0 handles AllAcks
        let res = &dkg_state0.handle_signed_vote(all_acks1.clone(), &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state0.handle_signed_vote(all_acks2.clone(), &mut rng);
        let (pubs0, sec0) = assert_match!(res.as_deref(), Ok([VoteResponse::DkgComplete(pubs0, sec0)]) => (pubs0, sec0));

        // Participant 1 handles AllAcks
        let res = &dkg_state1.handle_signed_vote(all_acks0.clone(), &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state1.handle_signed_vote(all_acks2, &mut rng);
        let (pubs1, sec1) = assert_match!(res.as_deref(), Ok([VoteResponse::DkgComplete(pubs1, sec1)]) => (pubs1, sec1));

        // Participant 2 handles AllAcks
        let res = &dkg_state2.handle_signed_vote(all_acks0, &mut rng);
        assert!(matches!(
            res.as_deref(),
            Ok([VoteResponse::WaitingForMoreVotes])
        ));
        let res = &dkg_state2.handle_signed_vote(all_acks1, &mut rng);
        let (pubs2, sec2) = assert_match!(res.as_deref(), Ok([VoteResponse::DkgComplete(pubs2, sec2)]) => (pubs2, sec2));

        // The pubkey sets should be identical
        assert_eq!(pubs0, pubs1);
        assert_eq!(pubs1, pubs2);

        // Two sigs should be enough to sign a message
        let msg = "signed message";
        let sig_shares: BTreeMap<usize, SignatureShare> =
            BTreeMap::from([(0, sec0.sign(msg)), (1, sec1.sign(msg))]);
        let sig = pubs2
            .combine_signatures(&sig_shares)
            .expect("Failed to combine signatures");
        assert!(pubs2.public_key().verify(&sig, msg));

        let sig_shares: BTreeMap<usize, SignatureShare> =
            BTreeMap::from([(1, sec1.sign(msg)), (2, sec2.sign(msg))]);
        let sig = pubs0
            .combine_signatures(&sig_shares)
            .expect("Failed to combine signatures");
        assert!(pubs0.public_key().verify(&sig, msg));
    }
}
