// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use log::debug;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::vote::{DkgVote, IdAck, IdPart, NodeId};

pub(crate) struct Knowledge {
    pub parts: BTreeSet<IdPart>,
    pub part_acks: BTreeMap<IdPart, BTreeSet<IdAck>>,
    pub agreed_with_all_acks: BTreeSet<NodeId>,
}

#[derive(Error, Debug)]
pub(crate) enum KnowledgeFault {
    #[error("Missing Parts to deal with Acks in received vote")]
    MissingParts,
    #[error("Parts in received vote differ from ours")]
    IncompatibleParts,
    #[error("Missing Acks to deal with AllAcks in received vote")]
    MissingAcks,
    #[error("Acks received in vote differ from ours")]
    IncompatibleAcks,
}

impl Knowledge {
    fn new() -> Self {
        Knowledge {
            parts: BTreeSet::new(),
            part_acks: BTreeMap::new(),
            agreed_with_all_acks: BTreeSet::new(),
        }
    }

    pub fn from_votes(mut votes: Vec<(DkgVote, NodeId)>) -> Result<Self, KnowledgeFault> {
        votes.sort();
        let mut knowledge = Knowledge::new();
        for (vote, voter_id) in votes {
            knowledge.handle_vote(vote, voter_id)?;
        }

        Ok(knowledge)
    }

    pub fn got_all_acks(&self, num_participants: usize) -> bool {
        self.part_acks.len() == num_participants
            && self
                .part_acks
                .iter()
                .all(|(_, a)| a.len() == num_participants)
    }

    fn handle_vote(&mut self, vote: DkgVote, id: NodeId) -> Result<(), KnowledgeFault> {
        match vote {
            DkgVote::SinglePart(part) => {
                self.parts.insert((id, part));
            }
            DkgVote::SingleAck(acked_parts) => {
                let parts: BTreeSet<_> = acked_parts.keys().cloned().collect();
                if self.parts.len() < parts.len() {
                    return Err(KnowledgeFault::MissingParts);
                } else if self.parts != parts {
                    debug!(
                        "IncompatibleParts: ours: {:?}, theirs: {:?}",
                        self.parts, parts
                    );
                    return Err(KnowledgeFault::IncompatibleParts);
                }
                for (id_part, ack) in acked_parts {
                    let acks = self.part_acks.entry(id_part).or_default();
                    acks.insert((id, ack));
                }
            }
            DkgVote::AllAcks(all_acks) => {
                if !self.got_all_acks(self.parts.len()) {
                    return Err(KnowledgeFault::MissingAcks);
                } else if all_acks != self.part_acks {
                    debug!(
                        "IncompatibleAcks: ours: {:?}, theirs: {:?}",
                        self.part_acks, all_acks
                    );
                    return Err(KnowledgeFault::IncompatibleAcks);
                }
                self.agreed_with_all_acks.insert(id);
            }
        }
        Ok(())
    }
}
