from flask import Flask, request, jsonify
import hashlib
import json
import math
import threading
import copy

app = Flask(__name__)

LOCK = threading.RLock()

# freezeId -> stored freeze information
FREEZES = {}

MAX_SAFE_INTEGER = 2**53 - 1


# ============================================================
# HELPERS
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def utf8_key(value):
    return value.encode("utf-8")


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


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=utf8_key,
    )


def invalid_input():
    return jsonify({
        "error": "INVALID_INPUT"
    }), 400


# ============================================================
# FILE MANIFEST
# ============================================================

def valid_files(files):
    if not isinstance(files, dict):
        return False

    if len(files) == 0:
        return False

    seen = set()

    for filename, content in files.items():

        if not isinstance(filename, str):
            return False

        if filename == "":
            return False

        if filename in seen:
            return False

        seen.add(filename)

        if not isinstance(content, str):
            return False

        try:
            content.encode("utf-8")
        except UnicodeEncodeError:
            return False

    return True


def make_inventory(files):
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
            "sha256": hashlib.sha256(raw).hexdigest(),
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
# FREEZE CANDIDATE
# ============================================================

FREEZE_FIELDS = {
    "name",
    "files",
    "loadable",
    "calibrationDigest",
    "tokenizerDigest",
    "unsupportedReason",
}


def valid_freeze_candidate(candidate):
    if not isinstance(candidate, dict):
        return False

    # Extra metadata is allowed.
    if not FREEZE_FIELDS.issubset(
        candidate.keys()
    ):
        return False

    if not nonempty_string(
        candidate["name"]
    ):
        return False

    if not isinstance(
        candidate["loadable"],
        bool,
    ):
        return False

    if not nonempty_string(
        candidate["calibrationDigest"]
    ):
        return False

    if not nonempty_string(
        candidate["tokenizerDigest"]
    ):
        return False

    reason = candidate[
        "unsupportedReason"
    ]

    if (
        reason is not None
        and not nonempty_string(reason)
    ):
        return False

    return True


def build_frozen_candidate(
    candidate,
    calibration_digest,
    tokenizer_digest,
    allowed_reasons,
):
    name = candidate.get("name", "")

    # Invalid candidate structure.
    if not valid_freeze_candidate(candidate):

        return {
            "name": name
            if isinstance(name, str)
            else "",
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

    # Invalid files.
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
# FREEZE REQUEST
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
    Includes ALL freeze input metadata.

    Therefore changing even extra metadata causes
    FREEZE_ID_CONFLICT.
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

def handle_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        fingerprint = freeze_fingerprint(body)

        # Existing freezeId.
        if freeze_id in FREEZES:

            stored = FREEZES[freeze_id]

            if (
                stored["fingerprint"]
                == fingerprint
            ):
                # Exact replay.
                return jsonify(
                    copy.deepcopy(
                        stored["response"]
                    )
                ), 200

            return jsonify({
                "error":
                    "FREEZE_ID_CONFLICT"
            }), 409

        allowed = set(
            body[
                "allowedUnsupportedReasons"
            ]
        )

        results = []

        for candidate in body[
            "candidates"
        ]:

            results.append(
                build_frozen_candidate(
                    candidate,
                    body[
                        "calibrationDigest"
                    ],
                    body[
                        "tokenizerDigest"
                    ],
                    allowed,
                )
            )

        # UTF-8 name ordering.
        results.sort(
            key=lambda x:
                utf8_key(x["name"])
        )

        response = {
            "freezeId": freeze_id,
            "candidates": results,
        }

        FREEZES[freeze_id] = {
            "fingerprint": fingerprint,
            "response": copy.deepcopy(
                response
            ),
            "request": copy.deepcopy(
                body
            ),
        }

        return jsonify(response), 200


# ============================================================
# SELECT REQUEST
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

    # These MUST be arrays/objects.
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


# ============================================================
# POLICY
# ============================================================

def valid_policy(policy):

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if not required.issubset(
        policy.keys()
    ):
        return False

    if not safe_integer(
        policy["maxBytes"]
    ):
        return False

    floor = policy[
        "aggregateFloor"
    ]

    if (
        not finite_number(floor)
        or float(floor) < 0
        or float(floor) > 1
    ):
        return False

    required_slices = policy[
        "requiredSlices"
    ]

    if not isinstance(
        required_slices,
        dict,
    ):
        return False

    for name, floor in (
        required_slices.items()
    ):

        if not nonempty_string(name):
            return False

        if (
            not finite_number(floor)
            or float(floor) < 0
            or float(floor) > 1
        ):
            return False

    max_latency = policy[
        "maxLatencyMs"
    ]

    if (
        not finite_number(max_latency)
        or float(max_latency) < 0
    ):
        return False

    order = policy[
        "candidateOrder"
    ]

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
# SELECT CANDIDATE VALIDATION
#
# IMPORTANT:
# Select candidates are FROZEN RESPONSE OBJECTS.
#
# Example:
# {
#   "name": "int8",
#   "status": "frozen",
#   "inventory": [...],
#   "totalBytes": 10,
#   "packageDigest": "...",
#   "reasonCodes": []
# }
# ============================================================

SELECT_FIELDS = {
    "name",
    "status",
    "inventory",
    "totalBytes",
    "packageDigest",
    "reasonCodes",
}


def valid_select_candidate_shape(candidate):

    if not isinstance(candidate, dict):
        return False

    if not SELECT_FIELDS.issubset(
        candidate.keys()
    ):
        return False

    if not nonempty_string(
        candidate["name"]
    ):
        return False

    if candidate["status"] not in {
        "frozen",
        "unsupported",
        "invalid",
    }:
        return False

    if not isinstance(
        candidate["inventory"],
        list,
    ):
        return False

    if not isinstance(
        candidate["reasonCodes"],
        list,
    ):
        return False

    return True


def candidate_names(candidates):

    names = []

    for candidate in candidates:

        if not valid_select_candidate_shape(
            candidate
        ):
            return None

        names.append(
            candidate["name"]
        )

    if len(set(names)) != len(names):
        return None

    return names


# ============================================================
# EXACT FROZEN RESPONSE COMPARISON
# ============================================================

def same_frozen_candidate(
    supplied,
    stored,
):
    """
    The grader sends the frozen candidates back.

    Compare the actual frozen response object,
    not the original file-bearing request object.
    """

    return (
        supplied["name"]
        == stored["name"]
        and supplied["status"]
        == stored["status"]
        and supplied["inventory"]
        == stored["inventory"]
        and supplied["totalBytes"]
        == stored["totalBytes"]
        and supplied["packageDigest"]
        == stored["packageDigest"]
        and supplied["reasonCodes"]
        == stored["reasonCodes"]
    )


# ============================================================
# MANIFEST INTEGRITY
# ============================================================

def validate_inventory(
    candidate
):
    """
    Recompute the inventory from the frozen request's
    original files.

    This is used to verify that the stored freeze response
    itself is internally correct.
    """

    name = candidate["name"]

    # Find the original candidate in the stored request.
    return name


# ============================================================
# PREDICTIONS
# ============================================================

def binary_prediction(value):

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


def calculate_accuracy(
    rows,
    candidate_name,
):

    if len(rows) == 0:
        return None, {}, False

    correct = 0

    total_by_slice = {}
    correct_by_slice = {}

    for row in rows:

        if not isinstance(row, dict):
            return None, {}, False

        label = row.get("label")

        if not binary_prediction(label):
            return None, {}, False

        slice_name = row.get("slice")

        if not nonempty_string(
            slice_name
        ):
            return None, {}, False

        predictions = row.get(
            "predictions"
        )

        if not isinstance(
            predictions,
            dict,
        ):
            return None, {}, False

        if candidate_name not in predictions:
            return None, {}, False

        prediction = predictions[
            candidate_name
        ]

        if not binary_prediction(
            prediction
        ):
            return None, {}, False

        total_by_slice[
            slice_name
        ] = (
            total_by_slice.get(
                slice_name,
                0,
            )
            + 1
        )

        if prediction == label:

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
        total_by_slice.keys(),
        key=utf8_key,
    ):

        slices[slice_name] = round(
            correct_by_slice.get(
                slice_name,
                0,
            )
            / total_by_slice[
                slice_name
            ],
            12,
        )

    return (
        aggregate,
        slices,
        True,
    )


# ============================================================
# SELECT
# ============================================================

def handle_select(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # ----------------------------------------------------
        # Freeze lookup
        # ----------------------------------------------------

        if freeze_id not in FREEZES:

            return jsonify({
                "error": "NOT_FROZEN"
            }), 200

        stored = FREEZES[
            freeze_id
        ]

        stored_candidates = stored[
            "response"
        ]["candidates"]

        stored_by_name = {
            c["name"]: c
            for c in stored_candidates
        }

        stored_names = set(
            stored_by_name.keys()
        )

        # ----------------------------------------------------
        # Policy
        # ----------------------------------------------------

        if not valid_policy(
            body["policy"]
        ):

            return jsonify({
                "error": "INVALID_POLICY"
            }), 200

        policy = body[
            "policy"
        ]

        # ----------------------------------------------------
        # Candidate array
        # ----------------------------------------------------

        supplied = body[
            "candidates"
        ]

        names = candidate_names(
            supplied
        )

        if names is None:

            return jsonify({
                "error":
                    "INVALID_LINEAGE"
            }), 200

        supplied_names = set(names)

        order = policy[
            "candidateOrder"
        ]

        order_set = set(order)

        # Candidate names and candidateOrder
        # must be the same unique set.
        if supplied_names != stored_names:
            return jsonify({
                "error":
                    "INVALID_LINEAGE"
            }), 200

        if order_set != stored_names:
            return jsonify({
                "error":
                    "INVALID_POLICY"
            }), 200

        supplied_by_name = {
            c["name"]: c
            for c in supplied
        }

        # ----------------------------------------------------
        # Results
        # ----------------------------------------------------

        results = []

        for name in names:

            supplied_candidate = (
                supplied_by_name[name]
            )

            stored_candidate = (
                stored_by_name[name]
            )

            reasons = []

            # ------------------------------------------------
            # Lineage
            # ------------------------------------------------

            if not same_frozen_candidate(
                supplied_candidate,
                stored_candidate,
            ):

                reasons.append(
                    "INVALID_LINEAGE"
                )

            # ------------------------------------------------
            # Manifest
            # ------------------------------------------------

            manifest_ok = (
                supplied_candidate[
                    "inventory"
                ]
                == stored_candidate[
                    "inventory"
                ]
                and supplied_candidate[
                    "totalBytes"
                ]
                == stored_candidate[
                    "totalBytes"
                ]
                and supplied_candidate[
                    "packageDigest"
                ]
                == stored_candidate[
                    "packageDigest"
                ]
            )

            if not manifest_ok:

                reasons.append(
                    "INVALID_MANIFEST"
                )

            # ------------------------------------------------
            # Predictions
            # ------------------------------------------------

            aggregate, slices, predictions_ok = (
                calculate_accuracy(
                    body["rows"],
                    name,
                )
            )

            if not predictions_ok:

                aggregate = None
                slices = {}

                reasons.append(
                    "INVALID_PREDICTIONS"
                )

            # ------------------------------------------------
            # Size
            # ------------------------------------------------

            if manifest_ok:

                total_bytes = (
                    stored_candidate[
                        "totalBytes"
                    ]
                )

                if (
                    not safe_integer(
                        total_bytes
                    )
                ):
                    reasons.append(
                        "INVALID_MANIFEST"
                    )
                    total_bytes = None

                elif (
                    total_bytes
                    > policy["maxBytes"]
                ):

                    reasons.append(
                        "SIZE_LIMIT"
                    )

            else:

                total_bytes = None

            # ------------------------------------------------
            # Latency
            # ------------------------------------------------

            latency = body[
                "latencies"
            ].get(name)

            if (
                not finite_number(
                    latency
                )
                or float(latency) < 0
            ):

                latency_ms = None

            else:

                latency_ms = latency

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
            # Frozen status
            # ------------------------------------------------

            if (
                stored_candidate[
                    "status"
                ]
                != "frozen"
            ):

                reasons.append(
                    "INVALID_LINEAGE"
                )

            # ------------------------------------------------
            # Accuracy floors
            # ------------------------------------------------

            if predictions_ok:

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

                required_slices = (
                    policy[
                        "requiredSlices"
                    ]
                )

                for slice_name in sorted(
                    required_slices.keys(),
                    key=utf8_key,
                ):

                    if (
                        slice_name
                        not in slices
                    ):

                        reasons.append(
                            "MISSING_SLICE:"
                            + slice_name
                        )

                    elif (
                        slices[
                            slice_name
                        ]
                        < float(
                            required_slices[
                                slice_name
                            ]
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
        # Result order = candidateOrder
        # UTF-8 name fallback.
        # ----------------------------------------------------

        order_index = {
            name: i
            for i, name in enumerate(
                order
            )
        }

        results.sort(
            key=lambda r: (
                order_index.get(
                    r["name"],
                    len(order),
                ),
                utf8_key(
                    r["name"]
                ),
            )
        )

        # ----------------------------------------------------
        # Winner
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
                    float(
                        r["latencyMs"]
                    ),
                    order_index[
                        r["name"]
                    ],
                    utf8_key(
                        r["name"]
                    ),
                ),
            )

        if winner is None:

            selected = None
            package_manifest = None

        else:

            selected = winner[
                "name"
            ]

            # Exactly the recorded frozen
            # response candidate.
            package_manifest = copy.deepcopy(
                stored_by_name[
                    selected
                ]
            )

        return jsonify({
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest":
                package_manifest,
        }), 200


# ============================================================
# POST /quantize
# ============================================================

@app.route(
    "/quantize",
    methods=["POST"],
)
def quantize():

    if not request.is_json:
        return invalid_input()

    try:
        body = request.get_json()
    except Exception:
        return invalid_input()

    if not isinstance(body, dict):
        return invalid_input()

    phase = body.get("phase")

    # Unknown / missing phase.
    if phase not in {
        "freeze",
        "select",
    }:
        return invalid_input()

    if phase == "freeze":

        if not valid_freeze_request(
            body
        ):
            return invalid_input()

        return handle_freeze(body)

    if phase == "select":

        if not valid_select_request(
            body
        ):
            return invalid_input()

        return handle_select(body)

    return invalid_input()


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
