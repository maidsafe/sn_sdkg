# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [3.0.1](https://github.com/maidsafe/sn_sdkg/compare/v3.0.0...v3.0.1) (2022-10-10)

## [3.0.0](https://github.com/maidsafe/sn_sdkg/compare/v2.0.0...v3.0.0) (2022-10-04)


### ⚠ BREAKING CHANGES

* vote response API changes

### Features

* empty vec for known votes ([#29](https://github.com/maidsafe/sn_sdkg/issues/29)) ([69200f5](https://github.com/maidsafe/sn_sdkg/commit/69200f59440a0644e02d179bcdde3f63ac7ef4d5))

## [2.0.0](https://github.com/maidsafe/sn_sdkg/compare/v1.1.2...v2.0.0) (2022-10-04)


### ⚠ BREAKING CHANGES

* now returns a vec of vote responses instead of one

* chore: small improvements

* chore: more improvements

* Recursive vote handling (#27) ([ffe3ff7](https://github.com/maidsafe/sn_sdkg/commit/ffe3ff7a011a2dbe2eb3b2c6dd357e4b0e111e2c)), closes [#27](https://github.com/maidsafe/sn_sdkg/issues/27)

### [1.1.2](https://github.com/maidsafe/sn_sdkg/compare/v1.1.1...v1.1.2) (2022-09-29)


### Bug Fixes

* excessive AE requests ([#25](https://github.com/maidsafe/sn_sdkg/issues/25)) ([384b1db](https://github.com/maidsafe/sn_sdkg/commit/384b1dbb24ab972def016bc6a6b4abe365faf259))

### [1.1.1](https://github.com/maidsafe/sn_sdkg/compare/v1.1.0...v1.1.1) (2022-09-26)


### Bug Fixes

* issue when we are last to ack, we dont send allacks ([#22](https://github.com/maidsafe/sn_sdkg/issues/22)) ([32b6b3e](https://github.com/maidsafe/sn_sdkg/commit/32b6b3ee9b6a40c5e53a703861d61373dfd5b691))

## 1.1.0 (2022-09-22)


### Features

* dkg votes, sigs, knowledge and AE ground work ([2850e32](https://github.com/maidsafe/sn_sdkg/commit/2850e324fac8ebc8586697950b060d8e681f9389))
* docs and API test ([#18](https://github.com/maidsafe/sn_sdkg/issues/18)) ([e9ac94c](https://github.com/maidsafe/sn_sdkg/commit/e9ac94c36b08e6cbb65c15b187a9f3595bd06e41))
* ignore known votes ([#15](https://github.com/maidsafe/sn_sdkg/issues/15)) ([0784a01](https://github.com/maidsafe/sn_sdkg/commit/0784a01ca9df5a320a449219b3296c65286516dd))
* initial code offering ([225219b](https://github.com/maidsafe/sn_sdkg/commit/225219b1869231e42a60d512566102b0d31ee62a))
* make DkgSignedVote public ([6e23df2](https://github.com/maidsafe/sn_sdkg/commit/6e23df215e8108d1c98d97ca9de42f99578e216a))
* make outcome imut ([#17](https://github.com/maidsafe/sn_sdkg/issues/17)) ([5c21993](https://github.com/maidsafe/sn_sdkg/commit/5c2199353cfe0b3c0e88e206a409e505bd807310))
* pump bls version ([#12](https://github.com/maidsafe/sn_sdkg/issues/12)) ([267e027](https://github.com/maidsafe/sn_sdkg/commit/267e0273f941e5bc5f1c52e55543bb3c6f4c8b6a))
* termination check ([#16](https://github.com/maidsafe/sn_sdkg/issues/16)) ([05a5a7d](https://github.com/maidsafe/sn_sdkg/commit/05a5a7d6494df97a323956983582cf9ffdc8e297))
* **vote:** remove ae vote response ([da59eed](https://github.com/maidsafe/sn_sdkg/commit/da59eed52aeb1d6199e457085575d680eb8bec4b))
* remove unecessary outcome field ([c2a04b3](https://github.com/maidsafe/sn_sdkg/commit/c2a04b34b0e3b4577456eaf9ac9eafa05bcc3547))
* test infrastructure, simple DKG test case ([21a6630](https://github.com/maidsafe/sn_sdkg/commit/21a6630f13a04842e7cfc1a66dfcf37d9823784b))


### Bug Fixes

* unsafe rng cloning ([#14](https://github.com/maidsafe/sn_sdkg/issues/14)) ([25af57a](https://github.com/maidsafe/sn_sdkg/commit/25af57ae77ccdb6da48ba26e983cb570aaf6e5e1))
* **ci:** fix main master mismatch ([#11](https://github.com/maidsafe/sn_sdkg/issues/11)) ([2f24053](https://github.com/maidsafe/sn_sdkg/commit/2f2405328d666770cedc410124b3ce389735d13a))
* unordered vote issue ([6845cc2](https://github.com/maidsafe/sn_sdkg/commit/6845cc292b8260b22589893cfde60655d4c54b2e))
