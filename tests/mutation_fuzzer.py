#!/usr/bin/env python3
"""
Sigstore Bundle Mutation Fuzzer

This test takes valid sigstore bundles and applies intelligent mutations
to create test cases that should be rejected by the verifier.

The mutations are designed to test specific failure modes:
- Cryptographic integrity (signatures, hashes, certificates)
- Structural validity (missing fields, wrong types)
- Temporal validity (timestamps, certificate validity)
- Merkle tree verification (inclusion proofs, checkpoints)
"""

import base64
import copy
import hashlib
import json
import os
import random
import sys
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable


class MutationType(Enum):
    """Categories of mutations that should cause verification to fail."""
    SIGNATURE_CORRUPTION = auto()
    CERTIFICATE_CORRUPTION = auto()
    MERKLE_PROOF_CORRUPTION = auto()
    CHECKPOINT_CORRUPTION = auto()
    HASH_MISMATCH = auto()
    STRUCTURAL_INVALID = auto()
    TEMPORAL_INVALID = auto()
    ENCODING_INVALID = auto()


@dataclass
class Mutation:
    """Represents a single mutation to apply to a bundle."""
    name: str
    mutation_type: MutationType
    apply: Callable[[dict], dict]
    description: str


def flip_random_bit_in_base64(data: str) -> str:
    """Flip a random bit in base64-encoded data."""
    try:
        decoded = base64.b64decode(data)
        if len(decoded) == 0:
            return data
        byte_array = bytearray(decoded)
        byte_idx = random.randint(0, len(byte_array) - 1)
        bit_idx = random.randint(0, 7)
        byte_array[byte_idx] ^= (1 << bit_idx)
        return base64.b64encode(bytes(byte_array)).decode('utf-8')
    except Exception:
        return data


def truncate_base64(data: str, bytes_to_remove: int = 4) -> str:
    """Truncate base64-encoded data by removing bytes."""
    try:
        decoded = base64.b64decode(data)
        if len(decoded) <= bytes_to_remove:
            return base64.b64encode(b"").decode('utf-8')
        truncated = decoded[:-bytes_to_remove]
        return base64.b64encode(truncated).decode('utf-8')
    except Exception:
        return data


def corrupt_base64_random_byte(data: str) -> str:
    """Replace a random byte in base64-encoded data."""
    try:
        decoded = base64.b64decode(data)
        if len(decoded) == 0:
            return data
        byte_array = bytearray(decoded)
        byte_idx = random.randint(0, len(byte_array) - 1)
        byte_array[byte_idx] = random.randint(0, 255)
        return base64.b64encode(bytes(byte_array)).decode('utf-8')
    except Exception:
        return data


def generate_random_base64(length: int = 32) -> str:
    """Generate random base64-encoded data."""
    return base64.b64encode(os.urandom(length)).decode('utf-8')


# =============================================================================
# Signature Mutations
# =============================================================================

def mutate_dsse_signature_flip_bit(bundle: dict) -> dict:
    """Flip a bit in the DSSE signature."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        sigs = bundle["dsseEnvelope"].get("signatures", [])
        if sigs:
            sigs[0]["sig"] = flip_random_bit_in_base64(sigs[0]["sig"])
    return bundle


def mutate_dsse_signature_truncate(bundle: dict) -> dict:
    """Truncate the DSSE signature."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        sigs = bundle["dsseEnvelope"].get("signatures", [])
        if sigs:
            sigs[0]["sig"] = truncate_base64(sigs[0]["sig"], 8)
    return bundle


def mutate_dsse_signature_empty(bundle: dict) -> dict:
    """Set DSSE signature to empty."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        sigs = bundle["dsseEnvelope"].get("signatures", [])
        if sigs:
            sigs[0]["sig"] = ""
    return bundle


def mutate_dsse_signature_random(bundle: dict) -> dict:
    """Replace DSSE signature with random bytes."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        sigs = bundle["dsseEnvelope"].get("signatures", [])
        if sigs:
            sigs[0]["sig"] = generate_random_base64(64)
    return bundle


def mutate_message_signature_flip_bit(bundle: dict) -> dict:
    """Flip a bit in the message signature."""
    bundle = copy.deepcopy(bundle)
    if "messageSignature" in bundle:
        sig = bundle["messageSignature"].get("signature", "")
        bundle["messageSignature"]["signature"] = flip_random_bit_in_base64(sig)
    return bundle


def mutate_message_signature_random(bundle: dict) -> dict:
    """Replace message signature with random bytes."""
    bundle = copy.deepcopy(bundle)
    if "messageSignature" in bundle:
        bundle["messageSignature"]["signature"] = generate_random_base64(64)
    return bundle


def mutate_remove_all_signatures(bundle: dict) -> dict:
    """Remove all signatures from DSSE envelope."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        bundle["dsseEnvelope"]["signatures"] = []
    return bundle


def mutate_add_extra_dsse_signature(bundle: dict) -> dict:
    """Add an extra signature to DSSE envelope (should have exactly 1)."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        sigs = bundle["dsseEnvelope"].get("signatures", [])
        if sigs:
            extra_sig = copy.deepcopy(sigs[0])
            extra_sig["sig"] = generate_random_base64(64)
            sigs.append(extra_sig)
    return bundle


# =============================================================================
# Certificate Mutations
# =============================================================================

def mutate_certificate_flip_bit(bundle: dict) -> dict:
    """Flip a bit in the certificate."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    if "certificate" in vm:
        raw = vm["certificate"].get("rawBytes", "")
        vm["certificate"]["rawBytes"] = flip_random_bit_in_base64(raw)
    elif "x509CertificateChain" in vm:
        certs = vm["x509CertificateChain"].get("certificates", [])
        if certs:
            raw = certs[0].get("rawBytes", "")
            certs[0]["rawBytes"] = flip_random_bit_in_base64(raw)
    return bundle


def mutate_certificate_truncate(bundle: dict) -> dict:
    """Truncate the certificate."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    if "certificate" in vm:
        raw = vm["certificate"].get("rawBytes", "")
        vm["certificate"]["rawBytes"] = truncate_base64(raw, 32)
    elif "x509CertificateChain" in vm:
        certs = vm["x509CertificateChain"].get("certificates", [])
        if certs:
            raw = certs[0].get("rawBytes", "")
            certs[0]["rawBytes"] = truncate_base64(raw, 32)
    return bundle


def mutate_certificate_random(bundle: dict) -> dict:
    """Replace certificate with random bytes."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    if "certificate" in vm:
        vm["certificate"]["rawBytes"] = generate_random_base64(512)
    elif "x509CertificateChain" in vm:
        certs = vm["x509CertificateChain"].get("certificates", [])
        if certs:
            certs[0]["rawBytes"] = generate_random_base64(512)
    return bundle


def mutate_certificate_empty(bundle: dict) -> dict:
    """Set certificate to empty."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    if "certificate" in vm:
        vm["certificate"]["rawBytes"] = ""
    elif "x509CertificateChain" in vm:
        vm["x509CertificateChain"]["certificates"] = []
    return bundle


def is_v03_bundle(bundle: dict) -> bool:
    """Check if a bundle is v0.3 format (handles both media type formats)."""
    media_type = bundle.get("mediaType", "")
    # Handle both formats:
    # - application/vnd.dev.sigstore.bundle.v0.3+json
    # - application/vnd.dev.sigstore.bundle+json;version=0.3
    return "v0.3" in media_type or "version=0.3" in media_type


def mutate_swap_to_certificate_chain_for_v3(bundle: dict) -> dict:
    """For v0.3 bundles, swap single cert to chain (invalid for v0.3)."""
    bundle = copy.deepcopy(bundle)
    if is_v03_bundle(bundle):
        vm = bundle.get("verificationMaterial", {})
        if "certificate" in vm:
            cert = vm.pop("certificate")
            vm["x509CertificateChain"] = {
                "certificates": [cert]
            }
    return bundle


# =============================================================================
# Merkle Proof Mutations
# =============================================================================

def mutate_inclusion_proof_hash_flip_bit(bundle: dict) -> dict:
    """Flip a bit in one of the inclusion proof hashes."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        hashes = proof.get("hashes", [])
        if hashes:
            idx = random.randint(0, len(hashes) - 1)
            hashes[idx] = flip_random_bit_in_base64(hashes[idx])
    return bundle


def mutate_inclusion_proof_hash_random(bundle: dict) -> dict:
    """Replace an inclusion proof hash with random data."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        hashes = proof.get("hashes", [])
        if hashes:
            idx = random.randint(0, len(hashes) - 1)
            hashes[idx] = generate_random_base64(32)
    return bundle


def mutate_inclusion_proof_remove_hash(bundle: dict) -> dict:
    """Remove a hash from the inclusion proof."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        hashes = proof.get("hashes", [])
        if hashes:
            hashes.pop(random.randint(0, len(hashes) - 1))
    return bundle


def mutate_inclusion_proof_add_hash(bundle: dict) -> dict:
    """Add an extra hash to the inclusion proof."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        hashes = proof.get("hashes", [])
        hashes.append(generate_random_base64(32))
    return bundle


def mutate_inclusion_proof_wrong_root_hash(bundle: dict) -> dict:
    """Change the root hash in inclusion proof."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        if "rootHash" in proof:
            proof["rootHash"] = generate_random_base64(32)
    return bundle


def mutate_inclusion_proof_wrong_tree_size(bundle: dict) -> dict:
    """Change tree size to invalid value."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        if "treeSize" in proof:
            # Make it smaller than log index
            log_idx = int(proof.get("logIndex", "1"))
            proof["treeSize"] = str(max(0, log_idx - 10))
    return bundle


def mutate_inclusion_proof_negative_log_index(bundle: dict) -> dict:
    """Set log index to negative value."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        if "logIndex" in proof:
            proof["logIndex"] = "-1"
    return bundle


def mutate_remove_inclusion_proof(bundle: dict) -> dict:
    """Remove inclusion proof entirely."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        entries[0].pop("inclusionProof", None)
    return bundle


# =============================================================================
# Checkpoint Mutations
# =============================================================================

def mutate_checkpoint_signature_flip_bit(bundle: dict) -> dict:
    """Flip a bit in the checkpoint signature."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        checkpoint = proof.get("checkpoint", {})
        if "envelope" in checkpoint:
            envelope = checkpoint["envelope"]
            # Find the signature line and corrupt it
            lines = envelope.split('\n')
            for i, line in enumerate(lines):
                if line.startswith('— ') or line.startswith('\u2014 '):
                    # This is the signature line
                    parts = line.split(' ')
                    if len(parts) >= 3:
                        sig = parts[-1]
                        corrupted = flip_random_bit_in_base64(sig)
                        parts[-1] = corrupted
                        lines[i] = ' '.join(parts)
                        break
            checkpoint["envelope"] = '\n'.join(lines)
    return bundle


def mutate_checkpoint_wrong_root_hash(bundle: dict) -> dict:
    """Change the root hash in checkpoint to not match proof."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        checkpoint = proof.get("checkpoint", {})
        if "envelope" in checkpoint:
            envelope = checkpoint["envelope"]
            lines = envelope.split('\n')
            # Root hash is typically line 3 (0-indexed: line 2)
            if len(lines) > 2:
                lines[2] = generate_random_base64(32)
            checkpoint["envelope"] = '\n'.join(lines)
    return bundle


def mutate_checkpoint_wrong_tree_size(bundle: dict) -> dict:
    """Change the tree size in checkpoint."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        checkpoint = proof.get("checkpoint", {})
        if "envelope" in checkpoint:
            envelope = checkpoint["envelope"]
            lines = envelope.split('\n')
            # Tree size is typically line 2 (0-indexed: line 1)
            if len(lines) > 1:
                lines[1] = "999999999999"
            checkpoint["envelope"] = '\n'.join(lines)
    return bundle


def mutate_remove_checkpoint(bundle: dict) -> dict:
    """Remove checkpoint from inclusion proof."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        proof.pop("checkpoint", None)
    return bundle


# =============================================================================
# Hash/Digest Mutations
# =============================================================================

def mutate_message_digest_wrong(bundle: dict) -> dict:
    """Change the message digest to wrong value."""
    bundle = copy.deepcopy(bundle)
    if "messageSignature" in bundle:
        digest = bundle["messageSignature"].get("messageDigest", {})
        if "digest" in digest:
            digest["digest"] = generate_random_base64(32)
    return bundle


def mutate_message_digest_algorithm(bundle: dict) -> dict:
    """Change the digest algorithm to invalid value."""
    bundle = copy.deepcopy(bundle)
    if "messageSignature" in bundle:
        digest = bundle["messageSignature"].get("messageDigest", {})
        if "algorithm" in digest:
            digest["algorithm"] = "MD5"  # Not supported
    return bundle


def mutate_dsse_payload_flip_bit(bundle: dict) -> dict:
    """Flip a bit in the DSSE payload."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        payload = bundle["dsseEnvelope"].get("payload", "")
        bundle["dsseEnvelope"]["payload"] = flip_random_bit_in_base64(payload)
    return bundle


def mutate_dsse_payload_wrong_subject(bundle: dict) -> dict:
    """Change the subject in DSSE payload to wrong artifact."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        payload_b64 = bundle["dsseEnvelope"].get("payload", "")
        try:
            payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
            if "subject" in payload and payload["subject"]:
                # Change the digest
                for subj in payload["subject"]:
                    if "digest" in subj:
                        for algo in subj["digest"]:
                            subj["digest"][algo] = hashlib.sha256(b"wrong artifact").hexdigest()
            bundle["dsseEnvelope"]["payload"] = base64.b64encode(
                json.dumps(payload).encode('utf-8')
            ).decode('utf-8')
        except Exception:
            pass
    return bundle


def mutate_canonicalized_body_flip_bit(bundle: dict) -> dict:
    """Flip a bit in the canonicalized body."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        body = entries[0].get("canonicalizedBody", "")
        entries[0]["canonicalizedBody"] = flip_random_bit_in_base64(body)
    return bundle


def mutate_canonicalized_body_random(bundle: dict) -> dict:
    """Replace canonicalized body with random data."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        entries[0]["canonicalizedBody"] = generate_random_base64(256)
    return bundle


# =============================================================================
# Structural Mutations
# =============================================================================

def mutate_wrong_media_type(bundle: dict) -> dict:
    """Change media type to invalid value."""
    bundle = copy.deepcopy(bundle)
    bundle["mediaType"] = "application/json"
    return bundle


def mutate_unknown_bundle_version(bundle: dict) -> dict:
    """Change to unknown bundle version."""
    bundle = copy.deepcopy(bundle)
    bundle["mediaType"] = "application/vnd.dev.sigstore.bundle.v99.9+json"
    return bundle


def mutate_remove_verification_material(bundle: dict) -> dict:
    """Remove verification material entirely."""
    bundle = copy.deepcopy(bundle)
    bundle.pop("verificationMaterial", None)
    return bundle


def mutate_remove_tlog_entries(bundle: dict) -> dict:
    """Remove all tlog entries."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    vm["tlogEntries"] = []
    return bundle


def mutate_remove_content(bundle: dict) -> dict:
    """Remove signature content (dsseEnvelope or messageSignature)."""
    bundle = copy.deepcopy(bundle)
    bundle.pop("dsseEnvelope", None)
    bundle.pop("messageSignature", None)
    return bundle


def mutate_wrong_log_id(bundle: dict) -> dict:
    """Change log ID to unknown value."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        entries[0]["logId"] = {"keyId": generate_random_base64(32)}
    return bundle


def mutate_wrong_kind_version(bundle: dict) -> dict:
    """Change kind/version to invalid combination."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        entries[0]["kindVersion"] = {
            "kind": "unknown_kind",
            "version": "99.0.0"
        }
    return bundle


# =============================================================================
# Temporal Mutations
# =============================================================================

def mutate_integrated_time_future(bundle: dict) -> dict:
    """Set integrated time far in the future."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        # Set to year 2099
        entries[0]["integratedTime"] = "4102444800"
    return bundle


def mutate_integrated_time_ancient(bundle: dict) -> dict:
    """Set integrated time to very old (before certificate validity)."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        # Set to year 1970
        entries[0]["integratedTime"] = "0"
    return bundle


def mutate_integrated_time_zero(bundle: dict) -> dict:
    """Set integrated time to zero."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        entries[0]["integratedTime"] = "0"
    return bundle


def mutate_integrated_time_negative(bundle: dict) -> dict:
    """Set integrated time to negative value."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        entries[0]["integratedTime"] = "-1000000"
    return bundle


# =============================================================================
# Encoding Mutations
# =============================================================================

def mutate_invalid_base64_signature(bundle: dict) -> dict:
    """Set signature to invalid base64."""
    bundle = copy.deepcopy(bundle)
    if "dsseEnvelope" in bundle:
        sigs = bundle["dsseEnvelope"].get("signatures", [])
        if sigs:
            sigs[0]["sig"] = "!!!not-valid-base64!!!"
    elif "messageSignature" in bundle:
        bundle["messageSignature"]["signature"] = "!!!not-valid-base64!!!"
    return bundle


def mutate_invalid_base64_certificate(bundle: dict) -> dict:
    """Set certificate to invalid base64."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    if "certificate" in vm:
        vm["certificate"]["rawBytes"] = "!!!not-valid-base64!!!"
    return bundle


def mutate_invalid_base64_root_hash(bundle: dict) -> dict:
    """Set root hash to invalid base64."""
    bundle = copy.deepcopy(bundle)
    vm = bundle.get("verificationMaterial", {})
    entries = vm.get("tlogEntries", [])
    if entries:
        proof = entries[0].get("inclusionProof", {})
        proof["rootHash"] = "!!!not-valid-base64!!!"
    return bundle


# =============================================================================
# Mutation Registry
# =============================================================================

ALL_MUTATIONS: list[Mutation] = [
    # Signature mutations
    Mutation("dsse_signature_flip_bit", MutationType.SIGNATURE_CORRUPTION,
             mutate_dsse_signature_flip_bit, "Flip a bit in DSSE signature"),
    Mutation("dsse_signature_truncate", MutationType.SIGNATURE_CORRUPTION,
             mutate_dsse_signature_truncate, "Truncate DSSE signature"),
    Mutation("dsse_signature_empty", MutationType.SIGNATURE_CORRUPTION,
             mutate_dsse_signature_empty, "Empty DSSE signature"),
    Mutation("dsse_signature_random", MutationType.SIGNATURE_CORRUPTION,
             mutate_dsse_signature_random, "Random DSSE signature"),
    Mutation("message_signature_flip_bit", MutationType.SIGNATURE_CORRUPTION,
             mutate_message_signature_flip_bit, "Flip a bit in message signature"),
    Mutation("message_signature_random", MutationType.SIGNATURE_CORRUPTION,
             mutate_message_signature_random, "Random message signature"),
    Mutation("remove_all_signatures", MutationType.SIGNATURE_CORRUPTION,
             mutate_remove_all_signatures, "Remove all DSSE signatures"),
    Mutation("add_extra_dsse_signature", MutationType.STRUCTURAL_INVALID,
             mutate_add_extra_dsse_signature, "Add extra DSSE signature (must be exactly 1)"),

    # Certificate mutations
    Mutation("certificate_flip_bit", MutationType.CERTIFICATE_CORRUPTION,
             mutate_certificate_flip_bit, "Flip a bit in certificate"),
    Mutation("certificate_truncate", MutationType.CERTIFICATE_CORRUPTION,
             mutate_certificate_truncate, "Truncate certificate"),
    Mutation("certificate_random", MutationType.CERTIFICATE_CORRUPTION,
             mutate_certificate_random, "Random certificate bytes"),
    Mutation("certificate_empty", MutationType.CERTIFICATE_CORRUPTION,
             mutate_certificate_empty, "Empty certificate"),
    Mutation("swap_to_chain_for_v3", MutationType.STRUCTURAL_INVALID,
             mutate_swap_to_certificate_chain_for_v3, "Use cert chain in v0.3 bundle"),

    # Merkle proof mutations
    Mutation("inclusion_proof_hash_flip_bit", MutationType.MERKLE_PROOF_CORRUPTION,
             mutate_inclusion_proof_hash_flip_bit, "Flip bit in inclusion proof hash"),
    Mutation("inclusion_proof_hash_random", MutationType.MERKLE_PROOF_CORRUPTION,
             mutate_inclusion_proof_hash_random, "Random inclusion proof hash"),
    Mutation("inclusion_proof_remove_hash", MutationType.MERKLE_PROOF_CORRUPTION,
             mutate_inclusion_proof_remove_hash, "Remove hash from proof"),
    Mutation("inclusion_proof_add_hash", MutationType.MERKLE_PROOF_CORRUPTION,
             mutate_inclusion_proof_add_hash, "Add extra hash to proof"),
    Mutation("inclusion_proof_wrong_root_hash", MutationType.MERKLE_PROOF_CORRUPTION,
             mutate_inclusion_proof_wrong_root_hash, "Wrong root hash in proof"),
    Mutation("inclusion_proof_wrong_tree_size", MutationType.MERKLE_PROOF_CORRUPTION,
             mutate_inclusion_proof_wrong_tree_size, "Invalid tree size"),
    Mutation("inclusion_proof_negative_log_index", MutationType.MERKLE_PROOF_CORRUPTION,
             mutate_inclusion_proof_negative_log_index, "Negative log index"),
    Mutation("remove_inclusion_proof", MutationType.STRUCTURAL_INVALID,
             mutate_remove_inclusion_proof, "Remove inclusion proof"),

    # Checkpoint mutations
    Mutation("checkpoint_signature_flip_bit", MutationType.CHECKPOINT_CORRUPTION,
             mutate_checkpoint_signature_flip_bit, "Flip bit in checkpoint signature"),
    Mutation("checkpoint_wrong_root_hash", MutationType.CHECKPOINT_CORRUPTION,
             mutate_checkpoint_wrong_root_hash, "Wrong root hash in checkpoint"),
    Mutation("checkpoint_wrong_tree_size", MutationType.CHECKPOINT_CORRUPTION,
             mutate_checkpoint_wrong_tree_size, "Wrong tree size in checkpoint"),
    Mutation("remove_checkpoint", MutationType.STRUCTURAL_INVALID,
             mutate_remove_checkpoint, "Remove checkpoint"),

    # Hash/digest mutations
    Mutation("message_digest_wrong", MutationType.HASH_MISMATCH,
             mutate_message_digest_wrong, "Wrong message digest"),
    Mutation("message_digest_algorithm", MutationType.HASH_MISMATCH,
             mutate_message_digest_algorithm, "Invalid digest algorithm"),
    Mutation("dsse_payload_flip_bit", MutationType.HASH_MISMATCH,
             mutate_dsse_payload_flip_bit, "Flip bit in DSSE payload"),
    Mutation("dsse_payload_wrong_subject", MutationType.HASH_MISMATCH,
             mutate_dsse_payload_wrong_subject, "Wrong artifact in DSSE subject"),
    Mutation("canonicalized_body_flip_bit", MutationType.HASH_MISMATCH,
             mutate_canonicalized_body_flip_bit, "Flip bit in canonicalized body"),
    Mutation("canonicalized_body_random", MutationType.HASH_MISMATCH,
             mutate_canonicalized_body_random, "Random canonicalized body"),

    # Structural mutations
    Mutation("wrong_media_type", MutationType.STRUCTURAL_INVALID,
             mutate_wrong_media_type, "Invalid media type"),
    Mutation("unknown_bundle_version", MutationType.STRUCTURAL_INVALID,
             mutate_unknown_bundle_version, "Unknown bundle version"),
    Mutation("remove_verification_material", MutationType.STRUCTURAL_INVALID,
             mutate_remove_verification_material, "Remove verification material"),
    Mutation("remove_tlog_entries", MutationType.STRUCTURAL_INVALID,
             mutate_remove_tlog_entries, "Remove tlog entries"),
    Mutation("remove_content", MutationType.STRUCTURAL_INVALID,
             mutate_remove_content, "Remove signature content"),
    Mutation("wrong_log_id", MutationType.STRUCTURAL_INVALID,
             mutate_wrong_log_id, "Wrong log ID"),
    Mutation("wrong_kind_version", MutationType.STRUCTURAL_INVALID,
             mutate_wrong_kind_version, "Wrong kind/version"),

    # Temporal mutations
    Mutation("integrated_time_future", MutationType.TEMPORAL_INVALID,
             mutate_integrated_time_future, "Integrated time in far future"),
    Mutation("integrated_time_ancient", MutationType.TEMPORAL_INVALID,
             mutate_integrated_time_ancient, "Integrated time before cert validity"),
    Mutation("integrated_time_zero", MutationType.TEMPORAL_INVALID,
             mutate_integrated_time_zero, "Integrated time is zero"),
    Mutation("integrated_time_negative", MutationType.TEMPORAL_INVALID,
             mutate_integrated_time_negative, "Negative integrated time"),

    # Encoding mutations
    Mutation("invalid_base64_signature", MutationType.ENCODING_INVALID,
             mutate_invalid_base64_signature, "Invalid base64 in signature"),
    Mutation("invalid_base64_certificate", MutationType.ENCODING_INVALID,
             mutate_invalid_base64_certificate, "Invalid base64 in certificate"),
    Mutation("invalid_base64_root_hash", MutationType.ENCODING_INVALID,
             mutate_invalid_base64_root_hash, "Invalid base64 in root hash"),
]


def is_v01_bundle(bundle: dict) -> bool:
    """Check if a bundle is v0.1 format."""
    media_type = bundle.get("mediaType", "")
    return "version=0.1" in media_type


def get_mutations_for_bundle(bundle: dict) -> list[Mutation]:
    """Get applicable mutations for a given bundle type."""
    has_dsse = "dsseEnvelope" in bundle
    has_message_sig = "messageSignature" in bundle
    is_v03 = is_v03_bundle(bundle)
    is_v01 = is_v01_bundle(bundle)
    has_single_cert = "certificate" in bundle.get("verificationMaterial", {})

    # Mutations that only apply to DSSE bundles
    dsse_only_mutations = {
        "dsse_signature_flip_bit",
        "dsse_signature_truncate",
        "dsse_signature_empty",
        "dsse_signature_random",
        "remove_all_signatures",
        "add_extra_dsse_signature",
        "dsse_payload_flip_bit",
        "dsse_payload_wrong_subject",
    }

    # Mutations that only apply to messageSignature bundles
    message_sig_only_mutations = {
        "message_signature_flip_bit",
        "message_signature_random",
        "message_digest_wrong",
        "message_digest_algorithm",
    }

    # Mutations that only apply to v0.3 bundles with single certificate
    v03_single_cert_mutations = {
        "swap_to_chain_for_v3",
    }

    # Mutations that should be skipped for v0.1 bundles (which only require promise, not proof)
    v02_v03_only_mutations = {
        "remove_inclusion_proof",  # v0.1 doesn't require inclusion proof
    }

    # Mutations that only apply to bundles with single certificate (not chain)
    single_cert_only_mutations = {
        "invalid_base64_certificate",  # Only targets single certificate
    }

    applicable = []
    for mutation in ALL_MUTATIONS:
        name = mutation.name

        # Filter out mutations that don't apply to this bundle type
        if name in dsse_only_mutations and not has_dsse:
            continue
        if name in message_sig_only_mutations and not has_message_sig:
            continue
        if name in v03_single_cert_mutations and (not is_v03 or not has_single_cert):
            continue
        if name in v02_v03_only_mutations and is_v01:
            continue
        if name in single_cert_only_mutations and not has_single_cert:
            continue

        applicable.append(mutation)

    return applicable


class VerifierType(Enum):
    """Supported verifier types."""
    SIGSTORE_RUST = auto()  # Our verify_bundle example
    COSIGN = auto()         # sigstore/cosign
    SIGSTORE_PYTHON = auto()  # sigstore-python


class BundleMutationFuzzer:
    """Fuzzer that applies mutations to valid bundles."""

    def __init__(self, verifier_type: VerifierType = VerifierType.SIGSTORE_RUST,
                 verifier_command: list[str] | None = None):
        """
        Initialize the fuzzer.

        Args:
            verifier_type: Which verifier to use
            verifier_command: Custom command override (optional)
        """
        self.verifier_type = verifier_type

        if verifier_command:
            self.verifier_command = verifier_command
        else:
            self.verifier_command = self._default_command_for_type(verifier_type)

        self._check_verifier()

    def _default_command_for_type(self, vtype: VerifierType) -> list[str]:
        """Get default command for verifier type."""
        if vtype == VerifierType.SIGSTORE_RUST:
            return ["./target/release/examples/verify_bundle"]
        elif vtype == VerifierType.COSIGN:
            return ["cosign", "verify-blob"]
        elif vtype == VerifierType.SIGSTORE_PYTHON:
            return ["python", "-m", "sigstore", "verify", "bundle"]
        else:
            raise ValueError(f"Unknown verifier type: {vtype}")

    def _check_verifier(self) -> None:
        """Check that the verifier binary exists."""
        verifier_path = Path(self.verifier_command[0])
        if not verifier_path.exists():
            # Also check in PATH
            import shutil
            if shutil.which(self.verifier_command[0]) is None:
                raise RuntimeError(
                    f"Verifier not found: {self.verifier_command[0]}\n"
                    "Build it with: cargo build --release --examples"
                )

    def load_bundle(self, path: Path) -> dict:
        """Load a bundle from disk."""
        with open(path, 'r') as f:
            return json.load(f)

    def save_bundle(self, bundle: dict, path: Path) -> None:
        """Save a bundle to disk."""
        with open(path, 'w') as f:
            json.dump(bundle, f, indent=2)

    def extract_identity_from_bundle(self, bundle: dict) -> tuple[str, str]:
        """
        Extract identity and issuer from bundle certificate.

        Returns:
            Tuple of (identity, issuer) or defaults if extraction fails.
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import ObjectIdentifier

            vm = bundle.get("verificationMaterial", {})

            # Get certificate bytes
            cert_b64 = None
            if "certificate" in vm:
                cert_b64 = vm["certificate"].get("rawBytes")
            elif "x509CertificateChain" in vm:
                certs = vm["x509CertificateChain"].get("certificates", [])
                if certs:
                    cert_b64 = certs[0].get("rawBytes")

            if not cert_b64:
                return (".*", ".*")

            cert_der = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(cert_der)

            # Extract identity from SAN (Subject Alternative Name)
            identity = ".*"
            try:
                san = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                for name in san.value:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        identity = name.value
                        break
                    elif isinstance(name, x509.RFC822Name):
                        identity = name.value
                        break
            except x509.ExtensionNotFound:
                pass

            # Extract issuer from Fulcio extension OID 1.3.6.1.4.1.57264.1.1
            issuer = ".*"
            FULCIO_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
            try:
                ext = cert.extensions.get_extension_for_oid(FULCIO_ISSUER_OID)
                # The value is a UTF8String wrapped in an OCTET STRING
                issuer = ext.value.value.decode('utf-8')
            except (x509.ExtensionNotFound, Exception):
                pass

            return (identity, issuer)
        except Exception:
            # Fallback - use wildcards (requires verify_bundle example with regexp support)
            return (".*", ".*")

    def verify_bundle(self, bundle_path: Path, artifact_path: Path,
                      trust_root_path: Path | None = None) -> tuple[bool, str]:
        """
        Verify a bundle using the configured verifier.

        Returns:
            Tuple of (success, output)
        """
        cmd = self._build_verify_command(bundle_path, artifact_path, trust_root_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return (result.returncode == 0, result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Verifier timed out")
        except FileNotFoundError:
            raise RuntimeError(
                f"Verifier not found: {cmd[0]}\n"
                "Build it with: cargo build --release --examples"
            )
        except Exception as e:
            raise RuntimeError(f"Error running verifier: {e}")

    def _build_verify_command(self, bundle_path: Path, artifact_path: Path,
                               trust_root_path: Path | None) -> list[str]:
        """Build the verification command for the configured verifier type."""
        cmd = list(self.verifier_command)

        if self.verifier_type == VerifierType.SIGSTORE_RUST:
            # Our verify_bundle example
            cmd.extend(["--certificate-identity-regexp", ".*"])
            cmd.append(str(artifact_path))
            cmd.append(str(bundle_path))

        elif self.verifier_type == VerifierType.COSIGN:
            # cosign verify-blob --bundle <bundle> --certificate-identity-regexp '.*' \
            #   --certificate-oidc-issuer-regexp '.*' <artifact>
            cmd.extend(["--bundle", str(bundle_path)])
            cmd.extend(["--certificate-identity-regexp", ".*"])
            cmd.extend(["--certificate-oidc-issuer-regexp", ".*"])
            if trust_root_path:
                cmd.extend(["--trusted-root", str(trust_root_path)])
            cmd.append(str(artifact_path))

        elif self.verifier_type == VerifierType.SIGSTORE_PYTHON:
            # python -m sigstore verify bundle --bundle <bundle> \
            #   --cert-identity '.*' --cert-oidc-issuer-regexp '.*' <artifact>
            cmd.extend(["--bundle", str(bundle_path)])
            cmd.extend(["--cert-identity", ".*"])  # sigstore-python uses regex by default
            cmd.extend(["--cert-oidc-issuer-regexp", ".*"])
            if trust_root_path:
                cmd.extend(["--trusted-root", str(trust_root_path)])
            cmd.append(str(artifact_path))

        return cmd

    def run_mutation_test(
        self,
        bundle: dict,
        artifact_path: Path,
        mutation: Mutation,
        trust_root_path: Path | None = None
    ) -> tuple[bool, str, str]:
        """
        Apply a mutation and verify the result should fail.

        Returns:
            Tuple of (correctly_rejected, mutation_name, details)
        """
        mutated = mutation.apply(bundle)

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(mutated, f, indent=2)
            mutated_path = Path(f.name)

        try:
            success, output = self.verify_bundle(
                mutated_path, artifact_path, trust_root_path
            )

            # Mutation should cause rejection (success=False)
            correctly_rejected = not success

            if correctly_rejected:
                details = f"Correctly rejected: {output[:200]}"
            else:
                details = f"INCORRECTLY ACCEPTED! Mutation: {mutation.description}"

            return (correctly_rejected, mutation.name, details)
        finally:
            mutated_path.unlink(missing_ok=True)

    def fuzz_bundle(
        self,
        bundle_path: Path,
        artifact_path: Path,
        trust_root_path: Path | None = None,
        mutations: list[Mutation] | None = None
    ) -> list[tuple[bool, str, str]]:
        """
        Run all applicable mutations on a bundle.

        Returns:
            List of (correctly_rejected, mutation_name, details) tuples
        """
        bundle = self.load_bundle(bundle_path)

        # Get mutations applicable to this bundle type
        applicable = get_mutations_for_bundle(bundle)
        applicable_names = {m.name for m in applicable}

        if mutations is None:
            mutations = applicable
        else:
            # Filter provided mutations to only those applicable to this bundle
            mutations = [m for m in mutations if m.name in applicable_names]

        results = []
        for mutation in mutations:
            result = self.run_mutation_test(
                bundle, artifact_path, mutation, trust_root_path
            )
            results.append(result)

        return results


def find_test_bundles() -> list[tuple[Path, Path, Path | None]]:
    """Find valid bundle/artifact/trust-root tuples for testing."""
    base = Path(__file__).parent.parent

    test_cases = []

    # Look in conformance test directories for happy-path cases
    conformance_dir = base / "sigstore-conformance" / "test" / "assets" / "bundle-verify"
    if conformance_dir.exists():
        # Default artifact used by most tests
        default_artifact = conformance_dir / "a.txt"

        for test_dir in conformance_dir.iterdir():
            if not test_dir.is_dir():
                continue
            if "_fail" in test_dir.name:
                continue

            bundle = test_dir / "bundle.sigstore.json"
            trust_root = test_dir / "trusted_root.json"

            if not bundle.exists():
                continue

            # Use custom artifact if provided, otherwise default
            artifact = test_dir / "artifact"
            if not artifact.exists():
                artifact = default_artifact

            if artifact.exists():
                tr = trust_root if trust_root.exists() else None
                test_cases.append((bundle, artifact, tr))

    return test_cases


def main():
    """Run the mutation fuzzer on all test bundles."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Sigstore Bundle Mutation Fuzzer"
    )
    parser.add_argument(
        "--bundle", type=Path,
        help="Path to a specific bundle to test"
    )
    parser.add_argument(
        "--artifact", type=Path,
        help="Path to the artifact for the bundle"
    )
    parser.add_argument(
        "--trust-root", type=Path,
        help="Path to trusted root JSON"
    )
    parser.add_argument(
        "--verifier", type=str, default=None,
        help="Custom path to verifier binary"
    )
    parser.add_argument(
        "--verifier-type", type=str, default="rust",
        choices=["rust", "cosign", "python"],
        help="Verifier to use: rust (default), cosign, or python (sigstore-python)"
    )
    parser.add_argument(
        "--list-mutations", action="store_true",
        help="List all available mutations"
    )
    parser.add_argument(
        "--mutation", type=str, action="append",
        help="Run only specific mutation(s) by name"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility"
    )

    args = parser.parse_args()
    random.seed(args.seed)

    if args.list_mutations:
        print("Available mutations:")
        print("-" * 60)
        for mut in ALL_MUTATIONS:
            print(f"  {mut.name}")
            print(f"    Type: {mut.mutation_type.name}")
            print(f"    Description: {mut.description}")
            print()
        return 0

    # Map verifier type string to enum
    verifier_type_map = {
        "rust": VerifierType.SIGSTORE_RUST,
        "cosign": VerifierType.COSIGN,
        "python": VerifierType.SIGSTORE_PYTHON,
    }
    verifier_type = verifier_type_map[args.verifier_type]

    verifier_cmd = None
    if args.verifier:
        verifier_cmd = [args.verifier]

    try:
        fuzzer = BundleMutationFuzzer(verifier_type, verifier_cmd)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Determine which mutations to run
    selected_mutations = None
    if args.mutation:
        mutation_map = {m.name: m for m in ALL_MUTATIONS}
        selected_mutations = []
        for name in args.mutation:
            if name in mutation_map:
                selected_mutations.append(mutation_map[name])
            else:
                print(f"Unknown mutation: {name}")
                return 1

    if args.bundle:
        if not args.artifact:
            print("Error: --artifact required with --bundle")
            return 1

        results = fuzzer.fuzz_bundle(
            args.bundle, args.artifact, args.trust_root, selected_mutations
        )
    else:
        # Run on all discovered test bundles
        test_cases = find_test_bundles()
        if not test_cases:
            print("No test bundles found. Use --bundle to specify one.")
            return 1

        all_results = []
        for bundle_path, artifact_path, trust_root_path in test_cases:
            if artifact_path is None:
                continue  # Skip bundles without artifacts

            # Use command-line trust root if provided, otherwise use discovered one
            tr = args.trust_root if args.trust_root else trust_root_path

            print(f"\nTesting: {bundle_path.parent.name}/{bundle_path.name}")
            results = fuzzer.fuzz_bundle(
                bundle_path, artifact_path, tr, selected_mutations
            )
            all_results.extend(results)

        results = all_results

    # Report results
    print("\n" + "=" * 60)
    print("MUTATION FUZZING RESULTS")
    print("=" * 60)

    passed = 0
    failed = 0

    for correctly_rejected, name, details in results:
        status = "PASS" if correctly_rejected else "FAIL"
        if correctly_rejected:
            passed += 1
        else:
            failed += 1
        print(f"[{status}] {name}")
        if not correctly_rejected:
            print(f"       {details}")

    print("-" * 60)
    print(f"Total: {len(results)} | Passed: {passed} | Failed: {failed}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
