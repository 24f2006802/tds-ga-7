"""
Release Gate policy endpoint.

This is a *pure* decision function: given a JSON payload describing a CI run,
it returns which safety rules were broken. "Pure" means: same input always
gives the same output, no randomness, no reading the clock, no network calls.
That's what "deterministic" means in the assignment.
"""

import re
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI()

# A third-party action ref must be exactly 40 lowercase hex characters (a full git commit SHA).
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# The only permission set that is allowed for a release run.
REQUIRED_PERMISSIONS = {"contents": "read", "packages": "write", "id-token": "none"}


class Action(BaseModel):
    owner: str
    name: str
    ref: str


class Workflow(BaseModel):
    trigger: str
    permissions: dict
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[Action] = []
    environmentApproval: Optional[bool] = None


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Workflow
    image: Image


@app.post("/release-gate")
def release_gate(req: ReleaseRequest):
    violations = []

    # ---- 1. Permissions must be EXACTLY least privilege, nothing more, nothing less ----
    if req.workflow.permissions != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # ---- 2. pull_request_target is never allowed as the actual trigger ----
    if req.workflow.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # ---- 3. Tests must pass, matrix must be complete, and fail-fast must be off ----
    if (
        not req.workflow.testsPassed
        or not req.workflow.matrixComplete
        or req.workflow.failFast is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---- 4. Every third-party action must be pinned to a full 40-char commit SHA ----
    #     (actions owned by "actions" are allowed to use a version tag like "v4")
    for action in req.workflow.actions:
        if action.owner == "actions":
            continue
        if not FULL_SHA_RE.match(action.ref):
            violations.append("MUTABLE_ACTION")
            break  # one code is enough even if several actions are bad

    # ---- 5. Image must be built in multiple stages (build stage thrown away) ----
    if not req.image.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    # ---- 6. Image must not run as root ----
    if req.image.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    # ---- 7. Secrets must never be baked into a layer ----
    if req.image.secretMode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # ---- 8. Zero critical CVEs allowed ----
    if req.image.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")

    # ---- 9. Image must be referenced by digest, not a floating tag ----
    if not req.image.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # ---- 10 & 11. Extra rules that ONLY apply when targeting production ----
    if req.target == "production":
        if not (req.event == "push" and req.ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if req.workflow.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"
    return {"decision": decision, "violations": violations}


@app.get("/")
def health():
    return {"status": "ok"}