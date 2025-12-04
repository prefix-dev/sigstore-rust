#!/usr/bin/env python3
"""Compare two Sigstore bundles to ensure structural compatibility.

This script checks that bundles produced by different implementations
(e.g., sigstore-rust vs cosign) have the same structure and format.
"""

import json
import sys
from pathlib import Path


def get_structure(obj, path=""):
    """Recursively get the structure of a JSON object."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            result[key] = get_structure(value, new_path)
        return {"type": "object", "keys": result}
    elif isinstance(obj, list):
        if len(obj) > 0:
            # Get structure of first element as representative
            return {"type": "array", "element": get_structure(obj[0], f"{path}[0]")}
        return {"type": "array", "element": None}
    elif isinstance(obj, str):
        return {"type": "string", "length": len(obj)}
    elif isinstance(obj, int):
        return {"type": "int"}
    elif isinstance(obj, float):
        return {"type": "float"}
    elif isinstance(obj, bool):
        return {"type": "bool"}
    elif obj is None:
        return {"type": "null"}
    else:
        return {"type": str(type(obj))}


def compare_structures(struct1, struct2, path="root"):
    """Compare two structures and report differences."""
    differences = []

    if struct1["type"] != struct2["type"]:
        differences.append(f"{path}: type mismatch - {struct1['type']} vs {struct2['type']}")
        return differences

    if struct1["type"] == "object":
        keys1 = set(struct1["keys"].keys())
        keys2 = set(struct2["keys"].keys())

        only_in_1 = keys1 - keys2
        only_in_2 = keys2 - keys1
        common = keys1 & keys2

        for key in only_in_1:
            differences.append(f"{path}.{key}: only in first bundle")
        for key in only_in_2:
            differences.append(f"{path}.{key}: only in second bundle")

        for key in common:
            differences.extend(
                compare_structures(
                    struct1["keys"][key],
                    struct2["keys"][key],
                    f"{path}.{key}"
                )
            )

    elif struct1["type"] == "array":
        if struct1["element"] is not None and struct2["element"] is not None:
            differences.extend(
                compare_structures(
                    struct1["element"],
                    struct2["element"],
                    f"{path}[]"
                )
            )

    return differences


def check_bundle_format(bundle, name):
    """Check that a bundle follows expected format conventions."""
    issues = []

    # Check media type
    if "mediaType" not in bundle:
        issues.append(f"{name}: missing mediaType")
    elif not bundle["mediaType"].startswith("application/vnd.dev.sigstore.bundle"):
        issues.append(f"{name}: unexpected mediaType format: {bundle['mediaType']}")

    # Check verification material
    vm = bundle.get("verificationMaterial", {})

    # Check certificate format
    if "certificate" in vm:
        cert = vm["certificate"]
        if "rawBytes" not in cert:
            issues.append(f"{name}: certificate missing rawBytes")
    elif "x509CertificateChain" in vm:
        chain = vm["x509CertificateChain"]
        if "certificates" not in chain:
            issues.append(f"{name}: x509CertificateChain missing certificates")

    # Check tlog entries
    tlog_entries = vm.get("tlogEntries", [])
    for i, entry in enumerate(tlog_entries):
        prefix = f"{name}.tlogEntries[{i}]"

        # Required fields
        required = ["logIndex", "logId", "kindVersion", "canonicalizedBody"]
        for field in required:
            if field not in entry:
                issues.append(f"{prefix}: missing required field '{field}'")

        # Check logIndex is string (per protobuf spec)
        if "logIndex" in entry:
            if not isinstance(entry["logIndex"], str):
                issues.append(f"{prefix}.logIndex: should be string, got {type(entry['logIndex']).__name__}")

        # Check integratedTime format if present
        if "integratedTime" in entry:
            if not isinstance(entry["integratedTime"], str):
                issues.append(f"{prefix}.integratedTime: should be string, got {type(entry['integratedTime']).__name__}")

        # Check inclusion proof
        if "inclusionProof" in entry:
            proof = entry["inclusionProof"]
            if "logIndex" in proof and not isinstance(proof["logIndex"], str):
                issues.append(f"{prefix}.inclusionProof.logIndex: should be string")
            if "treeSize" in proof and not isinstance(proof["treeSize"], str):
                issues.append(f"{prefix}.inclusionProof.treeSize: should be string")

    return issues


def main():
    if len(sys.argv) < 3:
        print("Usage: compare_bundles.py <bundle1.json> <bundle2.json>")
        print("       compare_bundles.py --check <bundle.json>")
        sys.exit(1)

    if sys.argv[1] == "--check":
        # Single bundle format check
        bundle_path = Path(sys.argv[2])
        with open(bundle_path) as f:
            bundle = json.load(f)

        issues = check_bundle_format(bundle, bundle_path.name)

        if issues:
            print(f"Format issues in {bundle_path.name}:")
            for issue in issues:
                print(f"  - {issue}")
            sys.exit(1)
        else:
            print(f"✅ {bundle_path.name} format OK")
            sys.exit(0)

    # Compare two bundles
    bundle1_path = Path(sys.argv[1])
    bundle2_path = Path(sys.argv[2])

    with open(bundle1_path) as f:
        bundle1 = json.load(f)
    with open(bundle2_path) as f:
        bundle2 = json.load(f)

    print(f"Comparing {bundle1_path.name} vs {bundle2_path.name}")
    print()

    # Check individual bundle formats
    issues1 = check_bundle_format(bundle1, bundle1_path.name)
    issues2 = check_bundle_format(bundle2, bundle2_path.name)

    if issues1:
        print(f"Format issues in {bundle1_path.name}:")
        for issue in issues1:
            print(f"  - {issue}")
        print()

    if issues2:
        print(f"Format issues in {bundle2_path.name}:")
        for issue in issues2:
            print(f"  - {issue}")
        print()

    # Compare structures
    struct1 = get_structure(bundle1)
    struct2 = get_structure(bundle2)

    differences = compare_structures(struct1, struct2)

    if differences:
        print("Structural differences:")
        for diff in differences:
            print(f"  - {diff}")
        print()

    # Summary
    total_issues = len(issues1) + len(issues2) + len(differences)
    if total_issues == 0:
        print("✅ Bundles are structurally identical and properly formatted")
        sys.exit(0)
    else:
        print(f"❌ Found {total_issues} issue(s)")
        sys.exit(1)


if __name__ == "__main__":
    main()
