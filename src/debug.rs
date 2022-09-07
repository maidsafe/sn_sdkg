// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::state::VoteResponse;
use crate::vote::DkgVote;
use std::fmt;

// Manual impl of Debug to skip vote content details
impl fmt::Debug for DkgVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DkgVote::SinglePart(_) => write!(f, "SinglePart"),
            DkgVote::SingleAck(_) => write!(f, "SingleAck"),
            DkgVote::AllAcks(_) => write!(f, "AllAcks"),
        }
    }
}

// Manual impl of Debug to avoid printing SecretKeyShare
impl fmt::Debug for VoteResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VoteResponse::WaitingForMoreVotes => write!(f, "WaitingForMoreVotes"),
            VoteResponse::IgnoringKnownVote => write!(f, "IgnoringKnownVote"),
            VoteResponse::BroadcastVote(v) => write!(f, "BroadcastVote {:?}", *v),
            VoteResponse::RequestAntiEntropy => write!(f, "RequestAntiEntropy"),
            VoteResponse::DkgComplete(_, _) => write!(f, "DkgComplete"),
        }
    }
}
