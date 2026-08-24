"""Independent offline verifier for UEG evidence bundles.

Canonicalization, Ed25519, Merkle and strict-JSON helpers are taken from the
Reality Layer V1 contract pack so that this verifier and the Go implementation
in internal/ are two separate readings of the same contract. A bundle is only
believable if both of them accept it.
"""
