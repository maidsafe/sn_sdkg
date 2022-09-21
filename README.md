# sn_sdkg

Synchronous Distributed Key Generation

[MaidSafe website](http://maidsafe.net) | [Safe Network Forum](https://safenetforum.org/)
:-------------------------------------: | :---------------------------------------------:

## About

This Safe Network SDKG module enables sections to create a Section Key without a trusted dealer.
It is based on the Audited code from poanetwork's [hbbft](https://github.com/poanetwork/hbbft).

## How it works

- Participants know of each other's `bls public key`
- Each create a `Part` and share it with the others
- They check each `Part` and share their `Ack` over each `Part`
- Participants share their set of `AllAcks` signed, and check that all the others have the same set
- Once everyone has all the participants signatures over this set they generate the key

We differ from poanetwork's original implementation in that we require total participation: in the Part validation process, we require an Ack from everyone instead of just a threshold amount.

## Links

- [hbbft keygen docs](https://docs.rs/hbbft/latest/hbbft/sync_key_gen/index.html)
- [hbbft keygen code](https://github.com/poanetwork/hbbft/blob/master/src/sync_key_gen.rs)
