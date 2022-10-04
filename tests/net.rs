// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bls::rand::rngs::OsRng;
use bls::{PublicKey, SecretKey};
use log::info;
use rand::prelude::{IteratorRandom, StdRng};
use rand::Rng;

use sn_sdkg::{DkgSignedVote, DkgState, DkgVote, Error, NodeId, VoteResponse};
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub source: NodeId,
    pub dest: NodeId,
    pub vote: DkgSignedVote,
}

pub struct Net {
    pub procs: Vec<DkgState>,
    pub packets: BTreeMap<NodeId, VecDeque<Packet>>,
    pub delivered_packets: Vec<Packet>,
}

impl Net {
    pub fn with_procs(threshold: usize, n: usize, mut rng: OsRng) -> Self {
        let sec_keys: Vec<SecretKey> = (0..n).map(|_| bls::rand::random()).collect();
        let pub_keys: BTreeMap<NodeId, PublicKey> = sec_keys
            .iter()
            .map(SecretKey::public_key)
            .enumerate()
            .map(|(i, p)| (i as NodeId, p))
            .collect();

        let procs = sec_keys
            .iter()
            .enumerate()
            .map(|(id, sec_key)| {
                DkgState::new(
                    id as NodeId,
                    sec_key.clone(),
                    pub_keys.clone(),
                    threshold,
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        Self {
            procs,
            packets: BTreeMap::new(),
            delivered_packets: Vec::new(),
        }
    }

    /// Pick a random public key from the set of procs
    // #[allow(dead_code)]
    pub fn pick_id(&self, rng: &mut StdRng) -> NodeId {
        rng.gen_range(0, self.procs.len()) as NodeId
    }

    pub fn bad_vote(&self, sender: NodeId) -> DkgSignedVote {
        let bad_vote = DkgVote::SingleAck(BTreeMap::new());
        let faulty_node = self.procs.get(sender as usize).unwrap();
        let sig = faulty_node.sign_vote(&bad_vote).unwrap();

        DkgSignedVote::new(bad_vote, sender, sig)
    }

    /// Generate a random faulty vote
    #[allow(dead_code)]
    pub fn gen_faulty_vote(
        &self,
        faulty_nodes: &BTreeSet<NodeId>,
        rng: &mut StdRng,
    ) -> DkgSignedVote {
        let sender_id = faulty_nodes.iter().choose(rng).unwrap();

        self.bad_vote(*sender_id)
    }

    /// Generate a faulty random packet
    #[allow(dead_code)]
    pub fn gen_faulty_packet(&self, faulty: &BTreeSet<NodeId>, rng: &mut StdRng) -> Packet {
        Packet {
            source: *faulty.iter().choose(rng).unwrap(),
            dest: self.pick_id(rng),
            vote: self.gen_faulty_vote(faulty, rng),
        }
    }

    #[allow(dead_code)]
    pub fn drop_packet_from_source(&mut self, source: NodeId) {
        self.packets.get_mut(&source).map(VecDeque::pop_front);
    }

    pub fn deliver_packet_from_source(&mut self, source: NodeId, rng: &mut OsRng) -> Result<()> {
        let packet = match self.packets.get_mut(&source).map(|ps| ps.pop_front()) {
            Some(Some(p)) => p,
            _ => return Ok(()), // nothing to do
        };
        self.purge_empty_queues();

        self.delivered_packets.push(packet.clone());

        let dest_proc = match self.procs.get_mut(packet.dest as usize) {
            Some(proc) => proc,
            None => {
                info!(
                    "[NET] destination proc does not exist, dropping packet for {:?}",
                    packet.dest
                );
                return Ok(());
            }
        };

        let resp = dest_proc.handle_signed_vote(packet.vote.clone(), rng);
        info!(
            "[NET] vote {:?} resp from {}: {:?}",
            packet.vote, packet.dest, resp
        );
        let res = match resp {
            Ok(res) => res,
            Err(Error::UnknownSender) => {
                assert!(self.procs.len() as u8 <= packet.source);
                vec![]
            }
            Err(err) => return Err(err),
        };
        for r in res {
            match r {
                VoteResponse::WaitingForMoreVotes => {}
                VoteResponse::BroadcastVote(vote) => {
                    let dest_actor = packet.dest;
                    self.broadcast(dest_actor, *vote);
                }
                VoteResponse::RequestAntiEntropy => {
                    // AE TODO
                }
                VoteResponse::DkgComplete(_pub_keys, _sec_key) => {
                    info!("[NET] DkgComplete for {:?}", packet.dest);
                    // Termination TODO
                }
            }
        }
        Ok(())
    }

    pub fn enqueue_packets(&mut self, packets: impl IntoIterator<Item = Packet>) {
        for packet in packets {
            self.packets
                .entry(packet.source)
                .or_default()
                .push_back(packet)
        }
    }

    pub fn broadcast(&mut self, source: NodeId, vote: DkgSignedVote) {
        let packets = Vec::from_iter(self.procs.iter().map(DkgState::id).map(|dest| Packet {
            source,
            dest,
            vote: vote.clone(),
        }));
        self.enqueue_packets(packets);
    }

    pub fn drain_queued_packets(&mut self, mut rng: OsRng) -> Result<()> {
        while let Some(source) = self.packets.keys().next().cloned() {
            self.deliver_packet_from_source(source, &mut rng)?;
            self.purge_empty_queues();
        }
        Ok(())
    }

    pub fn purge_empty_queues(&mut self) {
        self.packets = core::mem::take(&mut self.packets)
            .into_iter()
            .filter(|(_, queue)| !queue.is_empty())
            .collect();
    }

    // use std::fs::File;
    // use std::io::Write;
    //     #[allow(dead_code)]
    //     pub fn generate_msc(&self, name: &str) -> Result<()> {
    //         // See: http://www.mcternan.me.uk/mscgen/
    //         let mut msc = String::from(
    //             "
    // msc {\n
    //   hscale = \"2\";\n
    // ",
    //         );
    //         let procs = self
    //             .procs
    //             .iter()
    //             .map(|p| p.id())
    //             .collect::<BTreeSet<_>>() // sort by actor id
    //             .into_iter()
    //             .map(|id| format!("{:?}", id))
    //             .collect::<Vec<_>>()
    //             .join(",");
    //         msc.push_str(&procs);
    //         msc.push_str(";\n");
    //         for packet in self.delivered_packets.iter() {
    //             msc.push_str(&format!(
    //                 "{:?} -> {:?} [ label=\"{:?}\"];\n",
    //                 packet.source, packet.dest, packet.vote
    //             ));
    //         }
    //         msc.push_str("}\n");
    //
    //         let mut msc_file = File::create(name)?;
    //         msc_file.write_all(msc.as_bytes())?;
    //         Ok(())
    //     }
}
