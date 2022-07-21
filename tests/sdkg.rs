// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeSet;

mod net;
use net::Net;

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
    let mut rng = bls::rand::rngs::OsRng;
    let mut net = Net::with_procs(7, 10, &mut rng);

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
    net.drain_queued_packets().unwrap();

    // check that everyone reached termination on the same pubkeyset
    let mut pubs = BTreeSet::new();
    for mut node in net.procs.into_iter() {
        let (pks, _sks) = node
            .outcome()
            .expect("Unexpectedly failed to generate keypair")
            .unwrap();
        pubs.insert(pks);
    }
    assert!(pubs.len() == 1);
}
