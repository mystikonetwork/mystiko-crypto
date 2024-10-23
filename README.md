# Mystiko Typescript Crypto Library

[![build status](https://github.com/mystikonetwork/mystiko-crypto/actions/workflows/build.yml/badge.svg)](https://github.com/mystikonetwork/mystiko-crypto/actions/workflows/build.yml)

This is a typescript library that provides a set of cryptographic functions for Mystiko protocol.
It includes the following packages:

* [@mystikonetwork/ecies](packages/ecies) - Elliptic Curve Integrated Encryption Scheme implementation.
* [@mystikonetwork/merkle](packages/merkle) - Merkle tree implementation.
* [@mystikonetwork/protocol](packages/protocol) - Core protocol implementation.
* [@mystikonetwork/secret-share](packages/secret-share) - Secret sharing implementation.
* [@mystikonetwork/zkp](packages/zkp) - Zero Knowledge Proof abstract wrappers.
* [@mystikonetwork/zkp-browser](packages/zkp-browser) - Zero Knowledge Proof wrapper for browser.
* [@mystikonetwork/zkp-node](packages/zkp-node) - Zero Knowledge Proof wrapper for NodeJs.
* [@mystikonetwork/zkp-wasm](packages/zkp-wasm) - Zero Knowledge Proof wrapper for WebAssembly.
* [@mystikonetwork/zkp-nop](packages/zkp-nop) - Zero Knowledge Proof wrapper for No Operation.
* [@mystikonetwork/zokrates-js](packages/zokrates-js) - [Zokrates](https://github.com/Zokrates/ZoKrates) javascript wrapper.

To use these packages, you can install them via npm:

```bash
# Use your github username and PAC token to login
npm login --scope=@mystikonetwork --registry=https://npm.pkg.github.com
npm install @mystikonetwork/ecies
npm install @mystikonetwork/merkle
npm install @mystikonetwork/protocol
npm install @mystikonetwork/secret-share
npm install @mystikonetwork/zkp
npm install @mystikonetwork/zkp-browser
npm install @mystikonetwork/zkp-node
npm install @mystikonetwork/zkp-wasm
npm install @mystikonetwork/zkp-nop
npm install @mystikonetwork/zokrates-js
```
