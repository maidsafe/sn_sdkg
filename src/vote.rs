// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::sdkg::{Ack, Part};

pub(crate) type NodeId = u8;
pub(crate) type IdPart = (NodeId, Part);
pub(crate) type IdAck = (NodeId, Ack);

// The order of entries in this enum is IMPORTANT
// Its the order in which they should be handled
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Serialize, Deserialize)]
pub enum DkgVote {
    /// Participant's own Part
    SinglePart(Part),
    /// Participant's own Ack over everybody's Parts
    SingleAck(BTreeMap<IdPart, Ack>),
    /// All participants' Acks over every Parts, should be identical for all participants
    AllAcks(BTreeMap<IdPart, BTreeSet<IdAck>>),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Serialize, Deserialize)]
pub struct DkgSignedVote {
    /// This field is private to ensure votes are always signature-checked
    vote: DkgVote,
    /// The id of the voter
    pub voter: NodeId,
    /// The bls signature of the voter
    pub sig: Signature,
}

fn verify_sig<M: Serialize>(msg: &M, sig: &Signature, public_key: &PublicKey) -> Result<()> {
    let msg_bytes = bincode::serialize(msg)?;
    if public_key.verify(sig, msg_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

impl DkgSignedVote {
    /// Creates a new DkgSignedVote from a DkgVote
    pub fn from(vote: DkgVote, voter: NodeId, sig: Signature) -> Self {
        DkgSignedVote { vote, voter, sig }
    }

    /// Gets a DkgVote out of a DkgSignedVote and checks the signature as well as the content
    /// This method is the only way to obtain the underlying DkgVote,
    /// this helps ensure signatures are always checked before we can access votes
    pub fn get_validated_vote(&self, public_key: &PublicKey) -> Result<DkgVote> {
        verify_sig(&self.vote, &self.sig, public_key)?;
        Ok(self.vote.clone())
    }
}
