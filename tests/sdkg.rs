// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use rand::prelude::StdRng;
use rand::SeedableRng;
use std::collections::BTreeSet;

mod net;
use net::Net;
use sn_sdkg::Error;

static INIT: std::sync::Once = std::sync::Once::new();

fn init() {
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

#[test]
fn test_normal_dkg_no_packet_drops() {
    init();
    // make network of 10 members
    let rng = bls::rand::rngs::OsRng;
    let mut net = Net::with_procs(7, 10, rng);

    // bcast everyone's first Part
    let all_parts: Vec<_> = net
        .procs
        .iter_mut()
        .map(|node| {
            (
                node.id(),
                node.first_vote()
                    .expect("Unexpectedly failed to get first_vote"),
            )
        })
        .collect();
    for (id, v) in all_parts {
        net.broadcast(id, v);
    }

    // let everyone vote
    net.drain_queued_packets(rng).unwrap();

    // check that everyone reached termination on the same pubkeyset
    let mut pubs = BTreeSet::new();
    for node in net.procs.into_iter() {
        let (pks, _sks) = node
            .outcome()
            .expect("Unexpectedly failed to generate keypair")
            .unwrap();
        pubs.insert(pks);
    }
    assert!(pubs.len() == 1);
}

#[test]
fn test_dkg_inconsistant_votes() {
    init();
    // make network of 1 evil doer (id 0) and 2 good members
    let rng = bls::rand::rngs::OsRng;
    let mut net = Net::with_procs(2, 3, rng);

    // get everyone's first Part
    let all_parts: Vec<_> = net
        .procs
        .iter_mut()
        .map(|node| {
            (
                node.id(),
                node.first_vote()
                    .expect("Unexpectedly failed to get first_vote"),
            )
        })
        .collect();
    for (id, v) in all_parts {
        net.broadcast(id, v);
    }

    // evil doer sends a faulty vote to a node
    let mut rng = StdRng::from_seed([0u8; 32]);
    let faulty_packet = net.gen_faulty_packet(&BTreeSet::from([0]), &mut rng);
    net.enqueue_packets([faulty_packet].into_iter());

    // let everyone vote, make sure voting process triggers FaultyVote error
    let rng = bls::rand::rngs::OsRng;
    let res = net.drain_queued_packets(rng);
    assert!(matches!(res, Err(Error::FaultyVote(_))));

    // check that no one reached termination
    for node in net.procs.into_iter() {
        assert!(node.outcome().unwrap().is_none())
    }
}
