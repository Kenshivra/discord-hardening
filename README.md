# Discord Cryptographic Architecture Proposal

Independent security research. Published without affiliation.

This repository contains a technical proposal for improving Discord's
cryptographic architecture, and a proof-of-concept implementation of
one of the proposed primitives.

---

## What this is

A structured analysis of Discord's current cryptographic limitations
and concrete proposals for each — grounded in primitives that are
deployed in production elsewhere and have been formally verified.

The proposals cover five areas: end-to-end encryption for direct
messages, cryptographic token binding, metadata reduction, age
verification without identity storage, and third-party data
compartmentalisation.

The full document is in `DISCORD_CRYPTOGRAPHIC_PROPOSAL.txt`.

---

## Proof of concept

`poc/` contains a working commitment scheme for age verification in Rust.

One thing stated plainly upfront: this is a **commitment scheme**, not
a zero-knowledge proof in the strict sense. The verifier receives the
birth date and blinding factor to reconstruct and check the commitment.
A production ZKP — Groth16 or PLONK over an arithmetic circuit — would
allow verification from a 192-byte proof alone, with no private input
transmitted. The document explains both paths and what separates them.

What the PoC does demonstrate:
- A birth date can be committed to without revealing it
- The commitment is binding — it cannot be changed after the fact  
- A fraudulent proof against a different commitment is rejected
- No identity document is collected or stored at any point

**Build and run**

```
cd poc
cargo run
cargo test
```

Rust stable is sufficient. No nightly features, no external C
dependencies. All cryptographic primitives are pure Rust.

Dependencies: `blake3`, `rand_core`, `thiserror`, `zeroize`.

---

## Structure

```
DISCORD_CRYPTOGRAPHIC_PROPOSAL.txt   full proposal
poc/
  Cargo.toml
  src/
    main.rs                          commitment scheme + tests
```

---

## License

MIT
