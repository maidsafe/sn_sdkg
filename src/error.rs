// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::sdkg::Error as DkgError;
use thiserror::Error;

/// All the Dkg Errors
#[derive(Error, Debug)]
pub enum Error {
    /// SDKG faults and errors
    #[error("Dkg Error")]
    Sdkg(#[from] DkgError),
    /// Encoding
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),
    /// Invalid DkgState init input parameters
    #[error("Failed to initialize DkgState: secret key is not in provided pub key set")]
    NotInPubKeySet,
    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,
    /// Got vote from an unknown sender id
    #[error("Unknown sender")]
    UnknownSender,
    /// Got a faulty vote, some nodes are dishonest or dysfunctional
    #[error("Faulty vote {0}")]
    FaultyVote(String),
    /// Unexpectedly failed to generate secret key share
    #[error("Unexpectedly failed to generate secret key share")]
    FailedToGenerateSecretKeyShare,
}

pub type Result<T> = std::result::Result<T, Error>;
