from flask import Flask, request, jsonify
import hashlib
import json
import math
import threading

app = Flask(__name__)

LOCK = threading.RLock()

# Persistent in-process state.
# freezeId -> {
#     "fingerprint": ...,
#     "response": ...,
#     "candidates": ...
# }
FREEZES = {}

MAX_SAFE_INTEGER = 2**53 - 1


# ============================================================
# JSON / hashing helpers
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_utf8(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def sha256_json(value):
    return sha256_utf8(compact_json(value))


def utf8_bytes(text):
    return len(text.encode("utf-8"))


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def positive_safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= MAX_SAFE_INTEGER
    )


def nonempty_string(value):
    return isinstance(value, str) and len(value) > 0


def finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def finite_floor(value):
    return finite_number(value) and 0 <= float(value) <= 1


def utf8_sort_key(value):
    return value.encode("utf-8")


def sorted_unique_strings(values):
    return sorted(
        set(values),
        key=utf8_sort_key,
    )


# ============================================================
# Error response
# ============================================================

def error400():
    return jsonify({
        "error": "INVALID_INPUT"
    }), 400


def conflict(code):
    return jsonify({
        "error": code
    }), 409


# ============================================================
# Candidate/file validation
# ============================================================

def validate_file_map(files):
    if not isinstance(files, dict):
        return False

    if len(files) == 0:
        return False

    seen = set()

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return False

        if filename in seen:
            return False

        seen.add(filename)

        if not isinstance(text, str):
            return False

        # Python strings can represent arbitrary Unicode.
        # encode() confirms that the supplied text is valid UTF-8.
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            return False

    return True


def inventory_for(files):
    """
    Inventory order is UTF-8 filename order.

    Each object has EXACT key order:
        name, bytes, sha256
    """

    if not validate_file_map(files):
        return None

    inventory = []

    for filename in sorted(
        files.keys(),
        key=utf8_sort_key,
    ):
        text = files[filename]
        encoded = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        })

    return inventory


def package_digest(inventory):
    return sha256_json(inventory)


def calculate_manifest(files):
    inventory = inventory_for(files)

    if inventory is None:
        return None, None, None

    total = sum(
        item["bytes"]
        for item in inventory
    )

    digest = package_digest(inventory)

    return inventory, total, digest


# ============================================================
# Freeze candidate classification
# ============================================================

def candidate_has_required_shape(candidate):
    if not isinstance(candidate, dict):
        return False

    required = {
        "name",
        "files",
        "loadable",
        "calibrationDigest",
        "tokenizerDigest",
        "unsupportedReason",
    }

    # The candidate schema is fixed.
    if set(candidate.keys()) != required:
        return False

    if not nonempty_string(candidate["name"]):
        return False

    if not isinstance(candidate["loadable"], bool):
        return False

    if not nonempty_string(candidate["calibrationDigest"]):
        return False

    if not nonempty_string(candidate["tokenizerDigest"]):
        return False

    if candidate["unsupportedReason"] is not None:
        if not nonempty_string(
            candidate["unsupportedReason"]
        ):
            return False

    return True


def classify_candidate(
    candidate,
    freeze_calibration,
    freeze_tokenizer,
    allowed_reasons,
):
    """
    Returns:
        status
        inventory
        totalBytes
        packageDigest
        reasonCodes
    """

    name = candidate.get("name")

    # Invalid candidate shape / files.
    if not candidate_has_required_shape(candidate):
        return {
            "name": name if nonempty_string(name) else "",
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"],
        }

    files = candidate["files"]

    inventory, total, digest = calculate_manifest(files)

    # File errors mean empty/null manifest fields.
    if inventory is None:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"],
        }

    reason_codes = []

    unsupported = candidate["unsupportedReason"]

    if unsupported is not None:

        if unsupported not in allowed_reasons:
            reason_codes.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

        status = (
            "unsupported"
            if not reason_codes
            else "invalid"
        )

    else:

        status = "frozen"

        if not candidate["loadable"]:
            reason_codes.append("NOT_LOADABLE")

        if (
            candidate["calibrationDigest"]
            != freeze_calibration
        ):
            reason_codes.append(
                "CALIBRATION_MISMATCH"
            )

        if (
            candidate["tokenizerDigest"]
            != freeze_tokenizer
        ):
            reason_codes.append(
                "TOKENIZER_MISMATCH"
            )

        if reason_codes:
            status = "invalid"

    reason_codes = sort_codes(reason_codes)

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": digest,
        "reasonCodes": reason_codes,
    }


# ============================================================
# Reason code ordering
# ============================================================

def sort_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: x.encode("utf-8"),
    )


# ============================================================
# Freeze validation
# ============================================================

def valid_freeze_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    if not nonempty_string(body.get("freezeId")):
        return False

    if len(body["freezeId"]) > 128:
        return False

    if not nonempty_string(
        body.get("calibrationDigest")
    ):
        return False

    if not nonempty_string(
        body.get("tokenizerDigest")
    ):
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not isinstance(allowed, list):
        return False

    seen = set()

    for reason in allowed:
        if not nonempty_string(reason):
            return False

        if reason in seen:
            return False

        seen.add(reason)

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
# Freeze
# ============================================================

def freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # ----------------------------------------------------
        # Construct a complete immutable input fingerprint.
        #
        # sort_keys=True means object ordering is irrelevant,
        # while arrays remain ordered.
        # ----------------------------------------------------

        fingerprint = compact_json({
            "phase": body["phase"],
            "freezeId": body["freezeId"],
            "calibrationDigest": body[
                "calibrationDigest"
            ],
            "tokenizerDigest": body[
                "tokenizerDigest"
            ],
            "allowedUnsupportedReasons": body[
                "allowedUnsupportedReasons"
            ],
            "candidates": body["candidates"],
        })

        # ----------------------------------------------------
        # Existing freeze ID.
        # ----------------------------------------------------

        if freeze_id in FREEZES:

            previous = FREEZES[freeze_id]

            if previous["fingerprint"] == fingerprint:
                # Identical replay: return exact stored response.
                return jsonify(
                    json.loads(
                        json.dumps(previous["response"])
                    )
                ), 200

            return conflict(
                "FREEZE_ID_CONFLICT"
            )

        # ----------------------------------------------------
        # Construct candidate responses.
        # ----------------------------------------------------

        candidates = []

        for candidate in body["candidates"]:

            result = classify_candidate(
                candidate,
                body["calibrationDigest"],
                body["tokenizerDigest"],
                set(body["allowedUnsupportedReasons"]),
            )

            candidates.append(result)

        # Candidate output sorted by UTF-8 name.
        candidates.sort(
            key=lambda x: x["name"].encode("utf-8")
        )

        response = {
            "freezeId": freeze_id,
            "candidates": candidates,
        }

        # ----------------------------------------------------
        # Store immutable freeze.
        # ----------------------------------------------------

        FREEZES[freeze_id] = {
            "fingerprint": fingerprint,
            "response": json.loads(
                json.dumps(response)
            ),
            "candidates": json.loads(
                json.dumps(body["candidates"])
            ),
        }

        return jsonify(response), 200


# ============================================================
# Select request validation
# ============================================================

def valid_select_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(body.get("freezeId")):
        return False

    if not isinstance(body.get("candidates"), list):
        return False

    if not isinstance(body.get("rows"), list):
        return False

    if not isinstance(body.get("policy"), dict):
        return False

    if not isinstance(body.get("latencies"), dict):
        return False

    return True


# ============================================================
# Policy validation
# ============================================================

def validate_policy(policy):
    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if set(policy.keys()) != required:
        return False

    if not safe_integer(policy["maxBytes"]):
        return False

    if not finite_floor(
        policy["aggregateFloor"]
    ):
        return False

    if not isinstance(
        policy["requiredSlices"], dict
    ):
        return False

    for name, floor in policy[
        "requiredSlices"
    ].items():

        if not nonempty_string(name):
            return False

        if not finite_floor(floor):
            return False

    if not finite_number(
        policy["maxLatencyMs"]
    ):
        return False

    if float(policy["maxLatencyMs"]) < 0:
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
# Select candidate integrity
# ============================================================

def canonical_candidate_for_comparison(candidate):
    """
    Candidate supplied during selection is compared against
    the frozen candidate's complete content.

    File contents are data, so do not interpret them.
    """

    return compact_json(candidate)


def validate_supplied_candidate_against_frozen(
    supplied,
    frozen,
):
    """
    Validate lineage and recompute the manifest.
    """

    if not candidate_has_required_shape(supplied):
        return False, False, None, None, None

    if (
        canonical_candidate_for_comparison(supplied)
        != canonical_candidate_for_comparison(frozen)
    ):
        return False, False, None, None, None

    inventory, total, digest = calculate_manifest(
        supplied["files"]
    )

    if inventory is None:
        return True, False, None, None, None

    return (
        True,
        True,
        inventory,
        total,
        digest,
    )


# ============================================================
# Prediction validation
# ============================================================

def binary_prediction(value):
    """
    Valid prediction is exactly integer 0 or 1.
    bool is rejected.
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


def calculate_accuracy(rows, candidate_name):
    """
    Returns:
        aggregate,
        slices,
        valid
    """

    if len(rows) == 0:
        return None, {}, False

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            return None, {}, False

        if "label" not in row:
            return None, {}, False

        if not binary_prediction(row["label"]):
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

        if not binary_prediction(prediction):
            return None, {}, False

        label = row["label"]

        if prediction == label:
            correct += 1
            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )

        slice_total[slice_name] = (
            slice_total.get(slice_name, 0) + 1
        )

    aggregate = round(
        correct / len(rows),
        12,
    )

    slices = {}

    for name in sorted(
        slice_total.keys(),
        key=utf8_sort_key,
    ):
        slices[name] = round(
            slice_correct.get(name, 0)
            / slice_total[name],
            12,
        )

    return aggregate, slices, True


# ============================================================
# Selection
# ============================================================

def select(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # ----------------------------------------------------
        # Freeze must exist.
        # ----------------------------------------------------

        if freeze_id not in FREEZES:

            return jsonify({
                "error": "NOT_FROZEN"
            }), 200

        frozen = FREEZES[freeze_id]

        # ----------------------------------------------------
        # Validate policy.
        # ----------------------------------------------------

        if not validate_policy(
            body["policy"]
        ):

            return error400()

        policy = body["policy"]

        # ----------------------------------------------------
        # Candidate name sets.
        # ----------------------------------------------------

        frozen_candidates = frozen[
            "candidates"
        ]

        frozen_names = {
            c["name"]
            for c in frozen_candidates
        }

        supplied = body["candidates"]

        supplied_names = []

        for c in supplied:

            if not isinstance(c, dict):
                return error400()

            if not nonempty_string(
                c.get("name")
            ):
                return error400()

            supplied_names.append(c["name"])

        if len(set(supplied_names)) != len(
            supplied_names
        ):
            return error400()

        supplied_set = set(supplied_names)

        order = policy["candidateOrder"]

        order_set = set(order)

        # Candidate set must match the frozen set.
        if supplied_set != frozen_names:
            candidate_set_error = True
        else:
            candidate_set_error = False

        if order_set != frozen_names:
            candidate_set_error = True

        if candidate_set_error:
            return jsonify({
                "error": "INVALID_POLICY"
            }), 200

        # ----------------------------------------------------
        # Map frozen candidates.
        # ----------------------------------------------------

        frozen_by_name = {
            c["name"]: c
            for c in frozen_candidates
        }

        supplied_by_name = {
            c["name"]: c
            for c in supplied
        }

        # ----------------------------------------------------
        # Rows.
        # ----------------------------------------------------

        rows = body["rows"]

        # ----------------------------------------------------
        # Latencies.
        # ----------------------------------------------------

        latencies = body["latencies"]

        results = []

        for name in order:

            supplied_candidate = (
                supplied_by_name[name]
            )

            frozen_candidate = (
                frozen_by_name[name]
            )

            reasons = []

            # ------------------------------------------------
            # Lineage + manifest
            # ------------------------------------------------

            lineage_ok, manifest_ok, inventory, total, digest = (
                validate_supplied_candidate_against_frozen(
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

            # ------------------------------------------------
            # Predictions
            # ------------------------------------------------

            aggregate, slices, prediction_ok = (
                calculate_accuracy(
                    rows,
                    name,
                )
            )

            if not prediction_ok:
                reasons.append(
                    "INVALID_PREDICTIONS"
                )
                aggregate = None
                slices = {}

            # ------------------------------------------------
            # Size
            # ------------------------------------------------

            if manifest_ok:
                total_bytes = total

                if total > policy["maxBytes"]:
                    reasons.append(
                        "SIZE_LIMIT"
                    )
            else:
                total_bytes = None

            # ------------------------------------------------
            # Latency
            # ------------------------------------------------

            latency_value = latencies.get(name)

            if not finite_number(
                latency_value
            ) or float(latency_value) < 0:

                latency_ms = None

            else:

                latency_ms = latency_value

                if (
                    float(latency_value)
                    > float(policy["maxLatencyMs"])
                ):
                    reasons.append(
                        "LATENCY_LIMIT"
                    )

            # ------------------------------------------------
            # Accuracy floors
            # ------------------------------------------------

            if prediction_ok:

                if (
                    aggregate
                    < float(policy["aggregateFloor"])
                ):
                    reasons.append(
                        "AGGREGATE_FLOOR"
                    )

                # Every required slice must exist.
                for slice_name in sorted(
                    policy["requiredSlices"].keys(),
                    key=utf8_sort_key,
                ):

                    if slice_name not in slices:

                        reasons.append(
                            f"MISSING_SLICE:{slice_name}"
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
                            f"SLICE_FLOOR:{slice_name}"
                        )

            reasons = sort_codes(reasons)

            admitted = (
                len(reasons) == 0
                and frozen_candidate[
                    "status"
                ] == "frozen"
                and prediction_ok
                and manifest_ok
                and lineage_ok
            )

            results.append({
                "name": name,
                "aggregate": aggregate,
                "slices": slices,
                "totalBytes": total_bytes,
                "latencyMs": latency_ms,
                "admitted": admitted,
                "reasonCodes": reasons,
            })

        # ----------------------------------------------------
        # Deterministic result order.
        #
        # candidateOrder first, UTF-8 name fallback.
        # ----------------------------------------------------

        order_index = {
            name: i
            for i, name in enumerate(order)
        }

        results.sort(
            key=lambda x: (
                order_index.get(
                    x["name"],
                    len(order),
                ),
                utf8_sort_key(x["name"]),
            )
        )

        # ----------------------------------------------------
        # Winner:
        #
        # admitted candidates:
        #   1. smaller bytes
        #   2. lower latency
        #   3. candidate order
        # ----------------------------------------------------

        admitted = [
            r
            for r in results
            if r["admitted"]
        ]

        winner = None

        if admitted:

            winner = min(
                admitted,
                key=lambda r: (
                    r["totalBytes"],
                    float(r["latencyMs"]),
                    order_index.get(
                        r["name"],
                        len(order),
                    ),
                    utf8_sort_key(r["name"]),
                )
            )

        # ----------------------------------------------------
        # packageManifest
        #
        # Exactly the recorded frozen candidate object.
        # ----------------------------------------------------

        if winner is None:

            manifest = None

        else:

            winner_name = winner["name"]

            manifest = frozen_by_name[
                winner_name
            ]

        # ----------------------------------------------------
        # Selected name
        # ----------------------------------------------------

        selected = (
            winner["name"]
            if winner is not None
            else None
        )

        return jsonify({
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest": manifest,
        }), 200


# ============================================================
# POST /quantize
# ============================================================

@app.route("/quantize", methods=["POST"])
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

    # --------------------------------------------------------
    # Unknown / missing phase.
    # --------------------------------------------------------

    if phase not in {"freeze", "select"}:
        return error400()

    # --------------------------------------------------------
    # Freeze.
    # --------------------------------------------------------

    if phase == "freeze":

        if not valid_freeze_request(body):
            return error400()

        return freeze(body)

    # --------------------------------------------------------
    # Select.
    # --------------------------------------------------------

    if phase == "select":

        if not valid_select_request(body):
            return error400()

        return select(body)

    return error400()


# ============================================================
# Health
# ============================================================

@app.route("/", methods=["GET"])
def index():
    return "quantize controller running", 200


if __name__ == "__main__":
    import os

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
    )
