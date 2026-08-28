from flask import Flask, request, jsonify
import hashlib
import json
import math
import threading
import copy

app = Flask(__name__)

LOCK = threading.RLock()

# Persistent state, isolated by freezeId.
FREEZES = {}

MAX_SAFE_INTEGER = 2**53 - 1


# ============================================================
# BASIC HELPERS
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(value):
    return sha256_text(compact_json(value))


def nonempty_string(value):
    return isinstance(value, str) and len(value) > 0


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def utf8_key(value):
    return value.encode("utf-8")


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=utf8_key,
    )


def error400():
    return jsonify({"error": "INVALID_INPUT"}), 400


def error409(code):
    return jsonify({"error": code}), 409


# ============================================================
# FILE MANIFEST
# ============================================================

def valid_files(files):
    if not isinstance(files, dict) or len(files) == 0:
        return False

    names = set()

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return False

        if filename in names:
            return False

        names.add(filename)

        if not isinstance(text, str):
            return False

        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            return False

    return True


def make_inventory(files):
    """
    Inventory is sorted by UTF-8 filename.

    Object key order:
        name, bytes, sha256
    """

    if not valid_files(files):
        return None

    inventory = []

    for filename in sorted(
        files.keys(),
        key=utf8_key,
    ):
        raw = files[filename].encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        })

    return inventory


def make_manifest(files):
    inventory = make_inventory(files)

    if inventory is None:
        return None, None, None

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_json(inventory)

    return (
        inventory,
        total_bytes,
        package_digest,
    )


# ============================================================
# CANDIDATE VALIDATION
# ============================================================

REQUIRED_CANDIDATE_FIELDS = {
    "name",
    "files",
    "loadable",
    "calibrationDigest",
    "tokenizerDigest",
    "unsupportedReason",
}


def candidate_shape_valid(candidate):
    if not isinstance(candidate, dict):
        return False

    # EXTRA METADATA IS ALLOWED.
    if not REQUIRED_CANDIDATE_FIELDS.issubset(
        candidate.keys()
    ):
        return False

    if not nonempty_string(candidate["name"]):
        return False

    if not isinstance(candidate["loadable"], bool):
        return False

    if not nonempty_string(
        candidate["calibrationDigest"]
    ):
        return False

    if not nonempty_string(
        candidate["tokenizerDigest"]
    ):
        return False

    reason = candidate["unsupportedReason"]

    if reason is not None and not nonempty_string(reason):
        return False

    return True


def freeze_candidate(
    candidate,
    calibration_digest,
    tokenizer_digest,
    allowed_reasons,
):
    """
    Build the stored freeze response candidate.
    """

    name = (
        candidate.get("name")
        if isinstance(candidate, dict)
        else ""
    )

    # Bad candidate structure means invalid candidate.
    if not candidate_shape_valid(candidate):

        return {
            "name": name if isinstance(name, str) else "",
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [
                "INVALID_INPUT"
            ],
        }

    inventory, total_bytes, package_digest = (
        make_manifest(candidate["files"])
    )

    # Invalid files have empty/null manifest.
    if inventory is None:

        return {
            "name": candidate["name"],
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [
                "INVALID_INPUT"
            ],
        }

    reasons = []

    unsupported_reason = candidate[
        "unsupportedReason"
    ]

    if unsupported_reason is not None:

        if unsupported_reason not in allowed_reasons:

            reasons.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

            status = "invalid"

        else:

            status = "unsupported"

    else:

        status = "frozen"

        if not candidate["loadable"]:
            reasons.append("NOT_LOADABLE")

        if (
            candidate["calibrationDigest"]
            != calibration_digest
        ):
            reasons.append(
                "CALIBRATION_MISMATCH"
            )

        if (
            candidate["tokenizerDigest"]
            != tokenizer_digest
        ):
            reasons.append(
                "TOKENIZER_MISMATCH"
            )

        if reasons:
            status = "invalid"

    return {
        "name": candidate["name"],
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sorted_codes(reasons),
    }


# ============================================================
# FREEZE REQUEST VALIDATION
# ============================================================

def valid_freeze_request(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not nonempty_string(freeze_id):
        return False

    if len(freeze_id) > 128:
        return False

    if not nonempty_string(
        body.get("calibrationDigest")
    ):
        return False

    if not nonempty_string(
        body.get("tokenizerDigest")
    ):
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    allowed_seen = set()

    for reason in allowed:

        if not nonempty_string(reason):
            return False

        if reason in allowed_seen:
            return False

        allowed_seen.add(reason)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        if name in names:
            return False

        names.add(name)

    return True


# ============================================================
# FREEZE FINGERPRINT
# ============================================================

def freeze_fingerprint(body):
    """
    Freeze identity is based on the complete freeze input,
    including extra metadata.

    JSON object ordering does not matter.
    Array ordering does matter.
    """

    return json.dumps(
        body,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        fingerprint = freeze_fingerprint(body)

        # Existing freeze.
        if freeze_id in FREEZES:

            stored = FREEZES[freeze_id]

            if stored["fingerprint"] == fingerprint:

                # Identical replay.
                return (
                    jsonify(
                        copy.deepcopy(
                            stored["response"]
                        )
                    ),
                    200,
                )

            return error409(
                "FREEZE_ID_CONFLICT"
            )

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        candidates = []

        for candidate in body["candidates"]:

            result = freeze_candidate(
                candidate,
                body["calibrationDigest"],
                body["tokenizerDigest"],
                allowed,
            )

            candidates.append(result)

        # UTF-8 candidate-name ordering.
        candidates.sort(
            key=lambda x: utf8_key(x["name"])
        )

        response = {
            "freezeId": freeze_id,
            "candidates": candidates,
        }

        # Store a complete immutable snapshot.
        FREEZES[freeze_id] = {
            "fingerprint": fingerprint,
            "request": copy.deepcopy(body),
            "response": copy.deepcopy(response),
        }

        return jsonify(response), 200


# ============================================================
# SELECT VALIDATION
# ============================================================

def valid_select_request(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(
        body.get("freezeId")
    ):
        return False

    if not isinstance(
        body.get("candidates"),
        list,
    ):
        return False

    if not isinstance(
        body.get("rows"),
        list,
    ):
        return False

    if not isinstance(
        body.get("policy"),
        dict,
    ):
        return False

    if not isinstance(
        body.get("latencies"),
        dict,
    ):
        return False

    return True


def valid_policy(policy):

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if not required.issubset(policy.keys()):
        return False

    if not safe_integer(
        policy["maxBytes"]
    ):
        return False

    floor = policy["aggregateFloor"]

    if (
        not finite_number(floor)
        or float(floor) < 0
        or float(floor) > 1
    ):
        return False

    slices = policy["requiredSlices"]

    if not isinstance(slices, dict):
        return False

    for name, value in slices.items():

        if not nonempty_string(name):
            return False

        if (
            not finite_number(value)
            or float(value) < 0
            or float(value) > 1
        ):
            return False

    max_latency = policy["maxLatencyMs"]

    if (
        not finite_number(max_latency)
        or float(max_latency) < 0
    ):
        return False

    order = policy["candidateOrder"]

    if not isinstance(order, list):
        return False

    seen = set()

    for name in order:

        if not nonempty_string(name):
            return False

        if name in seen:
            return False

        seen.add(name)

    return True


# ============================================================
# PREDICTIONS
# ============================================================

def valid_binary(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


def calculate_predictions(rows, candidate_name):

    if len(rows) == 0:
        return None, {}, False

    correct = 0

    totals = {}
    correct_by_slice = {}

    for row in rows:

        if not isinstance(row, dict):
            return None, {}, False

        if "label" not in row:
            return None, {}, False

        if not valid_binary(row["label"]):
            return None, {}, False

        slice_name = row.get("slice")

        if not nonempty_string(slice_name):
            return None, {}, False

        predictions = row.get("predictions")

        if not isinstance(predictions, dict):
            return None, {}, False

        if candidate_name not in predictions:
            return None, {}, False

        prediction = predictions[
            candidate_name
        ]

        if not valid_binary(prediction):
            return None, {}, False

        totals[slice_name] = (
            totals.get(slice_name, 0) + 1
        )

        if prediction == row["label"]:

            correct += 1

            correct_by_slice[
                slice_name
            ] = (
                correct_by_slice.get(
                    slice_name,
                    0,
                )
                + 1
            )

    aggregate = round(
        correct / len(rows),
        12,
    )

    slices = {}

    for slice_name in sorted(
        totals.keys(),
        key=utf8_key,
    ):

        slices[slice_name] = round(
            correct_by_slice.get(
                slice_name,
                0,
            )
            / totals[slice_name],
            12,
        )

    return aggregate, slices, True


# ============================================================
# LINEAGE
# ============================================================

def frozen_candidate_map(freeze):

    return {
        candidate["name"]: candidate
        for candidate in freeze[
            "response"
        ]["candidates"]
    }


def supplied_candidate_names(candidates):

    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return None

        name = candidate.get("name")

        if not nonempty_string(name):
            return None

        names.append(name)

    if len(set(names)) != len(names):
        return None

    return names


def manifest_matches_frozen(
    supplied,
    frozen_response,
):
    """
    Validate submitted files by recomputing:
      inventory
      totalBytes
      packageDigest

    Never trust submitted totals because select candidates
    contain the actual file data.
    """

    if not candidate_shape_valid(supplied):
        return False, False, None, None, None

    # Name and frozen candidate identity.
    if (
        supplied["name"]
        != frozen_response["name"]
    ):
        return False, False, None, None, None

    inventory, total_bytes, package_digest = (
        make_manifest(supplied["files"])
    )

    if inventory is None:
        return True, False, None, None, None

    # Compare against the recorded frozen manifest.
    if (
        inventory
        != frozen_response["inventory"]
    ):
        return True, False, inventory, total_bytes, package_digest

    if (
        total_bytes
        != frozen_response["totalBytes"]
    ):
        return True, False, inventory, total_bytes, package_digest

    if (
        package_digest
        != frozen_response["packageDigest"]
    ):
        return True, False, inventory, total_bytes, package_digest

    return (
        True,
        True,
        inventory,
        total_bytes,
        package_digest,
    )


# ============================================================
# SELECT
# ============================================================

def do_select(body):

    freeze_id = body["freezeId"]

    with LOCK:

        if freeze_id not in FREEZES:
            return jsonify({
                "error": "NOT_FROZEN"
            }), 200

        freeze = FREEZES[freeze_id]

        if not valid_policy(
            body["policy"]
        ):
            return jsonify({
                "error": "INVALID_POLICY"
            }), 200

        policy = body["policy"]

        frozen_candidates = freeze[
            "response"
        ]["candidates"]

        frozen_map = frozen_candidate_map(
            freeze
        )

        frozen_names = set(
            frozen_map.keys()
        )

        supplied = body["candidates"]

        names = supplied_candidate_names(
            supplied
        )

        if names is None:
            return jsonify({
                "error": "INVALID_LINEAGE"
            }), 200

        supplied_names = set(names)

        order = policy[
            "candidateOrder"
        ]

        order_set = set(order)

        # Candidate names must be the same unique set.
        if (
            supplied_names != frozen_names
            or order_set != frozen_names
        ):
            return jsonify({
                "error": "INVALID_POLICY"
            }), 200

        supplied_map = {
            candidate["name"]: candidate
            for candidate in supplied
        }

        results_by_name = {}

        for name in names:

            supplied_candidate = (
                supplied_map[name]
            )

            frozen_candidate = (
                frozen_map[name]
            )

            reasons = []

            # ------------------------------------------------
            # Frozen status / lineage
            # ------------------------------------------------

            lineage_ok, manifest_ok, inventory, total_bytes, package_digest = (
                manifest_matches_frozen(
                    supplied_candidate,
                    frozen_candidate,
                )
            )

            if not lineage_ok:
                reasons.append(
                    "INVALID_LINEAGE"
                )

            if not manifest_ok:
                reasons.append(
                    "INVALID_MANIFEST"
                )

            # Only genuinely frozen candidates may win.
            if (
                frozen_candidate["status"]
                != "frozen"
            ):
                reasons.append(
                    "INVALID_LINEAGE"
                )

            # ------------------------------------------------
            # Predictions
            # ------------------------------------------------

            aggregate, slices, prediction_ok = (
                calculate_predictions(
                    body["rows"],
                    name,
                )
            )

            if not prediction_ok:

                aggregate = None
                slices = {}

                reasons.append(
                    "INVALID_PREDICTIONS"
                )

            # ------------------------------------------------
            # Size
            # ------------------------------------------------

            if manifest_ok:

                candidate_total_bytes = (
                    total_bytes
                )

                if (
                    total_bytes
                    > policy["maxBytes"]
                ):
                    reasons.append(
                        "SIZE_LIMIT"
                    )

            else:

                candidate_total_bytes = None

            # ------------------------------------------------
            # Latency
            # ------------------------------------------------

            latency = body[
                "latencies"
            ].get(name)

            if (
                not finite_number(latency)
                or float(latency) < 0
            ):

                candidate_latency = None

            else:

                candidate_latency = latency

                if (
                    float(latency)
                    > float(
                        policy[
                            "maxLatencyMs"
                        ]
                    )
                ):
                    reasons.append(
                        "LATENCY_LIMIT"
                    )

            # ------------------------------------------------
            # Aggregate
            # ------------------------------------------------

            if prediction_ok:

                if (
                    aggregate
                    < float(
                        policy[
                            "aggregateFloor"
                        ]
                    )
                ):
                    reasons.append(
                        "AGGREGATE_FLOOR"
                    )

                # ------------------------------------------------
                # Required slices
                # ------------------------------------------------

                for slice_name in sorted(
                    policy[
                        "requiredSlices"
                    ].keys(),
                    key=utf8_key,
                ):

                    if slice_name not in slices:

                        reasons.append(
                            "MISSING_SLICE:"
                            + slice_name
                        )

                    elif (
                        slices[slice_name]
                        < float(
                            policy[
                                "requiredSlices"
                            ][slice_name]
                        )
                    ):

                        reasons.append(
                            "SLICE_FLOOR:"
                            + slice_name
                        )

            reasons = sorted_codes(
                reasons
            )

            admitted = (
                len(reasons) == 0
            )

            results_by_name[name] = {
                "name": name,
                "aggregate": aggregate,
                "slices": slices,
                "totalBytes": candidate_total_bytes,
                "latencyMs": candidate_latency,
                "admitted": admitted,
                "reasonCodes": reasons,
            }

        # ----------------------------------------------------
        # Results in candidateOrder.
        # ----------------------------------------------------

        order_index = {
            name: index
            for index, name in enumerate(order)
        }

        results = sorted(
            results_by_name.values(),
            key=lambda result: (
                order_index.get(
                    result["name"],
                    len(order),
                ),
                utf8_key(result["name"]),
            ),
        )

        # ----------------------------------------------------
        # Select winner.
        #
        # bytes, latency, candidate order.
        # ----------------------------------------------------

        admitted = [
            result
            for result in results
            if result["admitted"]
        ]

        winner = None

        if admitted:

            winner = min(
                admitted,
                key=lambda result: (
                    result["totalBytes"],
                    float(
                        result["latencyMs"]
                    ),
                    order_index.get(
                        result["name"],
                        len(order),
                    ),
                    utf8_key(
                        result["name"]
                    ),
                ),
            )

        if winner is None:

            selected = None
            package_manifest = None

        else:

            selected = winner["name"]

            # EXACT recorded frozen candidate object.
            package_manifest = copy.deepcopy(
                freeze["request"]["candidates"]
            )

            package_manifest = next(
                candidate
                for candidate in package_manifest
                if candidate["name"]
                == selected
            )

        return jsonify({
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest": package_manifest,
        }), 200


# ============================================================
# ENDPOINT
# ============================================================

@app.route(
    "/quantize",
    methods=["POST"],
)
def quantize():

    if not request.is_json:
        return error400()

    try:
        body = request.get_json()
    except Exception:
        return error400()

    if not isinstance(body, dict):
        return error400()

    phase = body.get("phase")

    if phase == "freeze":

        if not valid_freeze_request(body):
            return error400()

        return do_freeze(body)

    if phase == "select":

        if not valid_select_request(body):
            return error400()

        return do_select(body)

    return error400()


@app.route("/", methods=["GET"])
def root():
    return "quantize controller running", 200


if __name__ == "__main__":
    import os

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                8000,
            )
        ),
    )
