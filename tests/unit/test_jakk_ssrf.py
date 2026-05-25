"""Tests for the cloud_metadata matcher (the SSRF success detector).

These pin the per-cloud response-shape detection. The matcher's whole job
is to be PRECISE — a `vulnerable` here means "we pulled an actual cloud
metadata document," which is directly reportable. So the negative cases
matter as much as the positives: normal API responses that happen to
mention tokens or keys must NOT fire.
"""
from __future__ import annotations

import pytest

from jakk.matchers import run_matcher


# ---------------------------------------------------------------------------
# Positive cases — real metadata-response shapes
# ---------------------------------------------------------------------------

AWS_IMDS_CREDS = """{
  "Code" : "Success",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAEXAMPLE1234567XY",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "IQoJb3JpZ2luX2VjEEXAMPLE...",
  "Expiration" : "2026-05-24T00:00:00Z"
}"""

AWS_IMDS_ROLE_LISTING = "s3-readonly-role"  # the listing path returns just the role name

GCP_TOKEN = '{"access_token":"ya29.c.EXAMPLE-gcp-token-value","expires_in":3599,"token_type":"Bearer"}'

AZURE_IMDS_TOKEN = '{"access_token":"eyJ0eXAiOiJKV1Q...","client_id":"11111111-2222-3333-4444-555555555555","expires_in":"86399"}'

AZURE_IMDS_COMPUTE = '{"compute":{"vmId":"abc","subscriptionId":"deadbeef-0000-1111-2222-333344445555","location":"eastus"}}'


@pytest.mark.parametrize(
    "label,response",
    [
        ("aws creds doc", AWS_IMDS_CREDS),
        ("gcp token", GCP_TOKEN),
        ("azure token", AZURE_IMDS_TOKEN),
        ("azure compute", AZURE_IMDS_COMPUTE),
    ],
)
def test_cloud_metadata_fires_on_metadata_responses(label, response):
    r = run_matcher("cloud_metadata", {}, response, {})
    assert r.fired, f"expected cloud_metadata to fire on {label}"
    assert r.outcome == "vulnerable"
    assert r.evidence  # carries a labeled snippet


def test_aws_access_key_id_alone_is_enough():
    r = run_matcher("cloud_metadata", {}, '{"AccessKeyId":"ASIAZZZZZZZZZZZZZZZZ"}', {})
    assert r.fired and r.outcome == "vulnerable"


def test_gcp_metadata_flavor_header_echo():
    r = run_matcher("cloud_metadata", {}, "Request received with Metadata-Flavor: Google", {})
    assert r.fired


# ---------------------------------------------------------------------------
# Negative cases — must NOT fire on ordinary responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,response",
    [
        ("github file listing", '{"name":"README.md","path":"README.md","type":"file"}'),
        ("normal error", "Access denied: URL not allowed"),
        ("benign access_token without GCP/Azure shape", '{"access_token":"plain-opaque-token"}'),
        ("mentions the word token in prose", "Your personal access token has expired."),
        ("empty", ""),
        ("AKIA long-lived key in unrelated text", "example key format is AKIAIOSFODNN7EXAMPLE"),
    ],
)
def test_cloud_metadata_does_not_fire_on_clean_responses(label, response):
    r = run_matcher("cloud_metadata", {}, response, {})
    assert not r.fired, f"cloud_metadata should NOT fire on {label}: {response!r}"
    assert r.outcome == "pass"


def test_bare_access_token_without_cloud_shape_is_pass():
    # A plain access_token (no ya29. prefix, no client_id pairing) is a
    # normal OAuth response, NOT a cloud metadata leak. Must not fire.
    r = run_matcher("cloud_metadata", {}, '{"access_token":"abc123","token_type":"Bearer"}', {})
    assert not r.fired


# ---------------------------------------------------------------------------
# Operator-supplied extra patterns
# ---------------------------------------------------------------------------


def test_cloud_metadata_accepts_custom_patterns():
    r = run_matcher(
        "cloud_metadata",
        {"patterns": [r"INTERNAL-IMDS-[A-Z]{4}"]},
        "leaked: INTERNAL-IMDS-WXYZ",
        {},
    )
    assert r.fired and r.outcome == "vulnerable"
