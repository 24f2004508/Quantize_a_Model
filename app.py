from flask import Flask, request, jsonify
import hashlib
import json
import math
import os
import threading

app = Flask(__name__)

MAX_SAFE_INTEGER = 9007199254740991

DATA_DIR = os.environ.get("DATA_DIR", "data")
STATE_FILE = os.path.join(DATA_DIR, "freezes.json")

state_lock = threading.Lock()

UNSUPPORTED_CODES = {
    "INVALID_INPUT",
    "UNALLOWED_UNSUPPORTED_REASON",
    "NOT_LOADABLE",
    "CALIBRATION_MISMATCH",
    "TOKENIZER_MISMATCH",
}


# ============================================================
# STATE
# ============================================================

def load_state():
    os.makedirs(DATA_DIR, exist_ok=True)

    if not os.path.exists(STATE_FILE):
        return {}

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            value = json.load(f)

        return value if isinstance(value, dict) else {}

    except Exception:
        return {}


FREEZES = load_state()


def save_state():
    os.makedirs(DATA_DIR, exist_ok=True)

    temp = STATE_FILE + ".tmp"

    with open(
        temp,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            FREEZES,
            f,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    os.replace(temp, STATE_FILE)


# ============================================================
# JSON / STRING HELPERS
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
    return sha256_bytes(
        text.encode("utf-8")
    )


def sha256_json(value):
    return sha256_text(
        compact_json(value)
    )


def nonempty_string(value):
    return (
        isinstance(value, str)
        and len(value) > 0
    )


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def nonnegative_safe_integer(value):
    return safe_integer(value)


def finite_nonnegative(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def finite_fraction(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def unique_nonempty_strings(value):
    if not isinstance(value, list):
        return False

    seen = set()

    for item in value:
        if not nonempty_string(item):
            return False

        if item in seen:
            return False

        seen.add(item)

    return len(value) > 0


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=utf8_key,
    )


# ============================================================
# FILE INVENTORY
# ============================================================

def make_inventory(files):
    inventory = []

    for filename in sorted(
        files.keys(),
        key=utf8_key,
    ):
        content = files[filename]

        if not isinstance(content, str):
            return None

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        })

    return inventory


def package_digest(inventory):
    return sha256_json(inventory)


# ============================================================
# FREEZE INPUT VALIDATION
# ============================================================

def validate_freeze_input(body):
    required = [
        "phase",
        "freezeId",
        "calibrationDigest",
        "tokenizerDigest",
        "allowedUnsupportedReasons",
        "candidates",
    ]

    for key in required:
        if key not in body:
            return False

    if body["phase"] != "freeze":
        return False

    freeze_id = body["freezeId"]

    if (
        not nonempty_string(freeze_id)
        or len(freeze_id) > 128
    ):
        return False

    if not nonempty_string(
        body["calibrationDigest"]
    ):
        return False

    if not nonempty_string(
        body["tokenizerDigest"]
    ):
        return False

    if not unique_nonempty_strings(
        body["allowedUnsupportedReasons"]
    ):
        return False

    candidates = body["candidates"]

    if (
        not isinstance(candidates, list)
        or len(candidates) == 0
    ):
        return False

    names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        if "name" not in candidate:
            return False

        name = candidate["name"]

        if not nonempty_string(name):
            return False

        if name in names:
            return False

        names.add(name)

        if "files" not in candidate:
            return False

        files = candidate["files"]

        if (
            not isinstance(files, dict)
            or len(files) == 0
        ):
            return False

        for filename, content in files.items():

            if not isinstance(
                filename,
                str,
            ):
                return False

            if not isinstance(
                content,
                str,
            ):
                return False

        if "loadable" not in candidate:
            return False

        if not isinstance(
            candidate["loadable"],
            bool,
        ):
            return False

        if not nonempty_string(
            candidate.get(
                "calibrationDigest"
            )
        ):
            return False

        if not nonempty_string(
            candidate.get(
                "tokenizerDigest"
            )
        ):
            return False

        # unsupportedReason may be absent.
        if (
            "unsupportedReason" in candidate
            and candidate["unsupportedReason"]
            is not None
            and not nonempty_string(
                candidate["unsupportedReason"]
            )
        ):
            return False

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons,
):
    reasons = set()

    files = candidate["files"]

    inventory = make_inventory(files)

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

    total_bytes = sum(
        entry["bytes"]
        for entry in inventory
    )

    digest = package_digest(
        inventory
    )

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    if unsupported_reason is not None:

        if unsupported_reason not in allowed_reasons:
            reasons.add(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

        status = (
            "unsupported"
            if not reasons
            else "invalid"
        )

    else:

        if not candidate["loadable"]:
            reasons.add(
                "NOT_LOADABLE"
            )

        if (
            candidate["calibrationDigest"]
            != request_calibration
        ):
            reasons.add(
                "CALIBRATION_MISMATCH"
            )

        if (
            candidate["tokenizerDigest"]
            != request_tokenizer
        ):
            reasons.add(
                "TOKENIZER_MISMATCH"
            )

        status = (
            "frozen"
            if not reasons
            else "invalid"
        )

    return {
        "name": candidate["name"],
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": digest,
        "reasonCodes": sorted_codes(
            reasons
        ),
    }


# ============================================================
# FREEZE
# ============================================================

def process_freeze(body):
    if not validate_freeze_input(body):
        return (
            jsonify({
                "error": "INVALID_INPUT"
            }),
            400,
        )

    freeze_id = body["freezeId"]

    # Canonical representation of the complete freeze input.
    canonical_input = compact_json(body)

    input_digest = sha256_text(
        canonical_input
    )

    with state_lock:

        existing = FREEZES.get(
            freeze_id
        )

        if existing is not None:

            if (
                existing["inputDigest"]
                != input_digest
            ):

                return (
                    jsonify({
                        "error":
                            "FREEZE_ID_CONFLICT"
                    }),
                    409,
                )

            # Exact replay.
            return jsonify(
                existing["response"]
            ), 200

        result_candidates = []

        for candidate in body[
            "candidates"
        ]:

            result_candidates.append(
                freeze_candidate(
                    candidate,
                    body[
                        "calibrationDigest"
                    ],
                    body[
                        "tokenizerDigest"
                    ],
                    body[
                        "allowedUnsupportedReasons"
                    ],
                )
            )

        result_candidates.sort(
            key=lambda x: utf8_key(
                x["name"]
            )
        )

        response = {
            "freezeId": freeze_id,
            "candidates":
                result_candidates,
        }

        FREEZES[freeze_id] = {
            "inputDigest": input_digest,
            "response": response,
            "sourceCandidates":
                body["candidates"],
        }

        save_state()

        return jsonify(
            response
        ), 200


# ============================================================
# SELECT VALIDATION
# ============================================================

def validate_select_input(body):
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

    policy = body["policy"]

    if not nonnegative_safe_integer(
        policy.get("maxBytes")
    ):
        return False

    if not finite_fraction(
        policy.get("aggregateFloor")
    ):
        return False

    required_slices = policy.get(
        "requiredSlices"
    )

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

        if not finite_fraction(floor):
            return False

    if not finite_nonnegative(
        policy.get("maxLatencyMs")
    ):
        return False

    order = policy.get(
        "candidateOrder"
    )

    if not unique_nonempty_strings(
        order
    ):
        return False

    if not isinstance(
        body.get("latencies"),
        dict,
    ):
        return False

    for name, latency in (
        body["latencies"].items()
    ):

        if not finite_nonnegative(
            latency
        ):
            return False

    # Rows themselves must be arrays of objects.
    for row in body["rows"]:

        if not isinstance(row, dict):
            return False

        if "label" not in row:
            return False

        if "slice" not in row:
            return False

        if not nonempty_string(
            row["slice"]
        ):
            return False

        if not isinstance(
            row.get("predictions"),
            dict,
        ):
            return False

    return True


# ============================================================
# RECALCULATE CANDIDATE MANIFEST
# ============================================================

def recompute_manifest(candidate):
    files = candidate.get("files")

    if not isinstance(files, dict):
        return None

    inventory = make_inventory(
        files
    )

    if inventory is None:
        return None

    total = sum(
        item["bytes"]
        for item in inventory
    )

    digest = package_digest(
        inventory
    )

    return (
        inventory,
        total,
        digest,
    )


# ============================================================
# CANDIDATE ARRAY LINEAGE
# ============================================================

def candidates_equal(
    supplied,
    original,
):
    """
    The grader supplies frozen candidates.

    They must exactly match the stored candidate
    response.

    JSON structural equality is used.
    """

    return supplied == original


# ============================================================
# PREDICTIONS
# ============================================================

def calculate_metrics(
    candidate_name,
    rows,
    required_slices,
):
    """
    Returns:
        aggregate
        slices
        prediction_valid
    """

    if len(rows) == 0:
        return None, {
            name: None
            for name in required_slices
        }, False

    correct = 0

    slice_total = {
        name: 0
        for name in required_slices
    }

    slice_correct = {
        name: 0
        for name in required_slices
    }

    for row in rows:

        predictions = row[
            "predictions"
        ]

        if candidate_name not in predictions:
            return (
                None,
                {
                    name: None
                    for name in required_slices
                },
                False,
            )

        prediction = predictions[
            candidate_name
        ]

        label = row["label"]

        # Binary prediction.
        if prediction not in (0, 1):
            return (
                None,
                {
                    name: None
                    for name in required_slices
                },
                False,
            )

        if label not in (0, 1):
            return (
                None,
                {
                    name: None
                    for name in required_slices
                },
                False,
            )

        if prediction == label:
            correct += 1

        slice_name = row["slice"]

        if slice_name in slice_total:

            slice_total[
                slice_name
            ] += 1

            if prediction == label:
                slice_correct[
                    slice_name
                ] += 1

    aggregate = round(
        correct / len(rows),
        12,
    )

    slices = {}

    for name in required_slices:

        if slice_total[name] == 0:
            slices[name] = None
        else:
            slices[name] = round(
                slice_correct[name]
                / slice_total[name],
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

def process_select(body):
    if not validate_select_input(body):
        return (
            jsonify({
                "error": "INVALID_INPUT"
            }),
            400,
        )

    freeze_id = body[
        "freezeId"
    ]

    with state_lock:

        frozen = FREEZES.get(
            freeze_id
        )

        if frozen is None:

            # No frozen state.
            supplied = body[
                "candidates"
            ]

            results = []

            for candidate in supplied:

                name = (
                    candidate.get("name")
                    if isinstance(
                        candidate,
                        dict,
                    )
                    else ""
                )

                results.append({
                    "name": name,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": [
                        "NOT_FROZEN"
                    ],
                })

            results.sort(
                key=lambda x:
                    utf8_key(
                        x["name"]
                    )
            )

            return jsonify({
                "freezeId": freeze_id,
                "selected": None,
                "results": results,
                "packageManifest": None,
            }), 200

        # ----------------------------------------------------
        # Candidate lineage
        # ----------------------------------------------------

        stored_candidates = frozen[
            "response"
        ]["candidates"]

        supplied_candidates = body[
            "candidates"
        ]

        # Exact frozen response must match.
        if not candidates_equal(
            supplied_candidates,
            stored_candidates,
        ):

            results = []

            for candidate in supplied_candidates:

                name = (
                    candidate.get("name")
                    if isinstance(
                        candidate,
                        dict,
                    )
                    else ""
                )

                results.append({
                    "name": name,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": [
                        "INVALID_LINEAGE"
                    ],
                })

            results.sort(
                key=lambda x:
                    utf8_key(
                        x["name"]
                    )
            )

            return jsonify({
                "freezeId": freeze_id,
                "selected": None,
                "results": results,
                "packageManifest": None,
            }), 200

        policy = body["policy"]

        candidate_order = policy[
            "candidateOrder"
        ]

        required_slices = policy[
            "requiredSlices"
        ]

        # ----------------------------------------------------
        # Candidate names
        # ----------------------------------------------------

        candidate_names = [
            candidate["name"]
            for candidate in
            supplied_candidates
        ]

        if (
            len(candidate_names)
            != len(set(candidate_names))
            or set(candidate_names)
            != set(candidate_order)
        ):

            return jsonify({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }), 200

        order_index = {
            name: i
            for i, name
            in enumerate(candidate_order)
        }

        # ----------------------------------------------------
        # Results
        # ----------------------------------------------------

        results = []

        for candidate in supplied_candidates:

            name = candidate[
                "name"
            ]

            reasons = set()

            # Candidate must be frozen.
            if candidate[
                "status"
            ] != "frozen":

                reasons.add(
                    "INVALID_LINEAGE"
                )

            # Recompute inventory.
            manifest = (
                recompute_manifest(
                    candidate
                )
            )

            total_bytes = None

            if manifest is None:

                reasons.add(
                    "INVALID_MANIFEST"
                )

            else:

                inventory, total_bytes, digest = (
                    manifest
                )

                if (
                    inventory
                    != candidate.get(
                        "inventory"
                    )
                    or digest
                    != candidate.get(
                        "packageDigest"
                    )
                ):

                    reasons.add(
                        "INVALID_MANIFEST"
                    )

            # Latency.
            latencies = body[
                "latencies"
            ]

            latency_ms = None

            if name not in latencies:

                reasons.add(
                    "INVALID_MANIFEST"
                )

            else:

                latency = latencies[name]

                if not finite_nonnegative(
                    latency
                ):
                    reasons.add(
                        "INVALID_MANIFEST"
                    )
                else:
                    latency_ms = latency

            # Predictions.
            aggregate, slices, prediction_valid = (
                calculate_metrics(
                    name,
                    body["rows"],
                    required_slices,
                )
            )

            if not prediction_valid:

                reasons.add(
                    "INVALID_PREDICTIONS"
                )

            else:

                if (
                    aggregate
                    < policy[
                        "aggregateFloor"
                    ]
                ):

                    reasons.add(
                        "AGGREGATE_FLOOR"
                    )

                for slice_name, floor in (
                    required_slices.items()
                ):

                    if slices.get(
                        slice_name
                    ) is None:

                        reasons.add(
                            f"MISSING_SLICE:{slice_name}"
                        )

                    elif slices[
                        slice_name
                    ] < floor:

                        reasons.add(
                            f"SLICE_FLOOR:{slice_name}"
                        )

            # Size.
            if (
                total_bytes is not None
                and total_bytes
                > policy["maxBytes"]
            ):

                reasons.add(
                    "SIZE_LIMIT"
                )

            # Latency.
            if (
                latency_ms is not None
                and latency_ms
                > policy["maxLatencyMs"]
            ):

                reasons.add(
                    "LATENCY_LIMIT"
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
                "reasonCodes":
                    sorted_codes(
                        reasons
                    ),
            })

        # ----------------------------------------------------
        # Result order
        # ----------------------------------------------------

        results.sort(
            key=lambda result: (
                order_index.get(
                    result["name"],
                    10**9,
                ),
                utf8_key(
                    result["name"]
                ),
            )
        )

        # ----------------------------------------------------
        # Winner
        # ----------------------------------------------------

        admitted_results = [
            result
            for result in results
            if result["admitted"]
        ]

        winner = None

        if admitted_results:

            winner = min(
                admitted_results,
                key=lambda result: (
                    result["totalBytes"],
                    result["latencyMs"],
                    order_index.get(
                        result["name"],
                        10**9,
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

            package_manifest = next(
                candidate
                for candidate in
                supplied_candidates
                if candidate[
                    "name"
                ] == selected
            )

        return jsonify({
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest":
                package_manifest,
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
        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    try:
        body = request.get_json()
    except Exception:
        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    if not isinstance(
        body,
        dict,
    ):
        return jsonify({
            "error": "INVALID_INPUT"
        }), 400

    phase = body.get(
        "phase"
    )

    if phase == "freeze":
        return process_freeze(body)

    if phase == "select":
        return process_select(body)

    return jsonify({
        "error": "INVALID_INPUT"
    }), 400


@app.route("/")
def index():
    return "quantize API running", 200


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            8000,
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
    )
