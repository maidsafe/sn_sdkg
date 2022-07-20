// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

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
    // make network of 5 members
    let mut rng = bls::rand::rngs::OsRng;
    let mut net = Net::with_procs(2, 2, &mut rng);

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
    for (id, v) in all_parts.iter() {
        net.broadcast(*id, v.clone());
    }

    // let everyone vote
    net.drain_queued_packets().unwrap();

    // check that everyone reached termination
    for mut node in net.procs.into_iter() {
        assert!(node.outcome().unwrap().is_some())
    }
}
