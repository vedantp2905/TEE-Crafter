"""The quota hint must report the limit Azure actually stated, or admit it can't.

``REAL_QUOTA_STDERR`` below is not a hand-written fixture.  It was captured on
2026-08-22 by deliberately asking for a ``Standard_DC16as_v5`` in ``westus``,
where ``standardDCASv5Family`` has a limit of 8 — and read out of
``az vm create --debug`` rather than stderr, because azure-cli 2.89.1 on
Python 3.14 consumes the response body itself and reports only
``The content for this response was already consumed``.

Two failure modes are pinned here:

* **Wrong attribution.**  The subject of the sentence is the phrase after
  "exceeding approved", and it is not always a VM family — "Total Regional
  Cores" produces the same sentence with the same ``Current Limit:`` field.
  Reading the family out of the portal URL instead attaches a regional limit
  to a family name, which is how a family whose real limit is 8 was once
  reported as ``limit=48``.
* **Invented values.**  Every field used to fall back to a plausible default
  (``standardDCASv5Family`` / ``westus`` / ``0``).  Since the SDK bug above
  routinely replaces the message with a traceback, the operator was shown a
  complete-looking hint that had been made up, in which ``limit=0`` read as a
  real quota of zero.
"""
from __future__ import annotations

import pytest

from tee_crafter.cli.commands.baking.common.azure_cvm import (
    _extract_quota_details,
    _quota_message,
)

REAL_QUOTA_STDERR = (
    "ERROR: (QuotaExceeded) Operation could not be completed as it results in "
    "exceeding approved standardDCASv5Family Cores quota. Additional details - "
    "Deployment Model: Resource Manager, Location: westus, Current Limit: 8, "
    "Current Usage: 0, Additional Required: 16, (Minimum) New Limit Required: "
    "16. Setup Alerts when Quota reaches threshold. Learn more at "
    "https://aka.ms/quotamonitoringalerting . Submit a request for Quota "
    "increase at https://aka.ms/ProdportalCRP/#blade/"
    "Microsoft_Azure_Capacity/UsageAndQuota.ReactView/Parameters/"
    "%7B%22subscriptionId%22:%22060b9553-c6f3-43f4-a6bd-00943d41d0d7%22,"
    "%22command%22:%22openQuotaApprovalBlade%22,%22quotas%22:"
    "[%7B%22location%22:%22westus%22,%22providerId%22:%22Microsoft.Compute%22,"
    "%22resourceName%22:%22standardDCASv5Family%22,%22quotaRequest%22:"
    "%7B%22properties%22:%7B%22limit%22:16,%22unit%22:%22Count%22,"
    "%22name%22:%7B%22value%22:%22standardDCASv5Family%22%7D%7D%7D%7D]%7D "
    "by specifying parameters listed in the 'Details' section for deployment "
    "to succeed."
)

# Same sentence, different subject: the constraint is the region's total core
# allowance, and no VM family is named anywhere in it.
REGIONAL_QUOTA_STDERR = (
    "ERROR: (QuotaExceeded) Operation could not be completed as it results in "
    "exceeding approved Total Regional Cores quota. Additional details - "
    "Deployment Model: Resource Manager, Location: eastus2, Current Limit: 48, "
    "Current Usage: 40, Additional Required: 16, (Minimum) New Limit "
    "Required: 56."
)

# What the operator actually gets when the azure-cli response bug fires.
SDK_BUG_STDERR = (
    "ERROR: The command failed with an unexpected error. Here is the "
    "traceback:\nERROR: The content for this response was already consumed\n"
    "Traceback (most recent call last):\n  File \"/opt/homebrew/Cellar/"
    "azure-cli/2.89.1/libexec/lib/python3.14/site-packages/azure/cli/core/"
    "commands/__init__.py\", line 789, in _run_job\n    result = "
    "cmd_copy(params)\n"
)


class TestTheRealMessage:
    def test_the_limit_is_the_one_azure_stated(self):
        assert _extract_quota_details(REAL_QUOTA_STDERR)["limit"] == 8

    def test_the_requested_new_limit_is_not_mistaken_for_the_ceiling(self):
        """``(Minimum) New Limit Required: 16`` is an ask, not a ceiling."""
        d = _extract_quota_details(REAL_QUOTA_STDERR)
        assert d["limit"] == 8 and d["required"] == 16

    def test_the_url_encoded_limit_is_not_picked_up(self):
        """The portal link carries ``%22limit%22:16`` — also not the ceiling."""
        assert _extract_quota_details(REAL_QUOTA_STDERR)["limit"] != 16

    def test_usage_is_read(self):
        assert _extract_quota_details(REAL_QUOTA_STDERR)["usage"] == 0

    def test_family_location_and_subscription(self):
        d = _extract_quota_details(REAL_QUOTA_STDERR)
        assert d["family"] == "standardDCASv5Family"
        assert d["location"] == "westus"
        assert d["sub_id"] == "060b9553-c6f3-43f4-a6bd-00943d41d0d7"

    def test_the_subject_comes_from_the_sentence(self):
        d = _extract_quota_details(REAL_QUOTA_STDERR)
        assert d["subject"] == "standardDCASv5Family Cores"

    def test_the_rendered_message_states_all_three_numbers(self):
        msg = _quota_message(_extract_quota_details(REAL_QUOTA_STDERR), "snp-azure")
        assert "limit=8" in msg
        assert "in use=0" in msg
        assert "needs 16" in msg
        assert "westus" in msg


class TestRegionalCoresIsNotBlamedOnAFamily:
    def test_the_subject_is_reported_verbatim(self):
        d = _extract_quota_details(REGIONAL_QUOTA_STDERR)
        assert d["subject"] == "Total Regional Cores"

    def test_no_family_is_invented(self):
        """This is the limit=48-on-DCASv5 bug: there is no family to name."""
        assert _extract_quota_details(REGIONAL_QUOTA_STDERR)["family"] is None

    def test_the_message_names_the_regional_quota_not_a_family(self):
        msg = _quota_message(
            _extract_quota_details(REGIONAL_QUOTA_STDERR), "tdx-azure")
        assert "Total Regional Cores" in msg
        assert "standardDCASv5Family" not in msg
        assert "limit=48" in msg


#: A refusal that states only what it wants, with no ``Current Limit:`` at all.
#: The number present is the *ask*; reporting it as the ceiling would tell the
#: operator their quota is 56 when it might be 8.
REQUIRED_ONLY_STDERR = (
    "ERROR: (QuotaExceeded) Operation could not be completed as it results in "
    "exceeding approved standardDCSv3Family Cores quota. "
    "(Minimum) New Limit Required: 56."
)


class TestOnlyTheCurrentLimitCounts:
    def test_a_new_limit_required_is_not_read_as_the_limit(self):
        d = _extract_quota_details(REQUIRED_ONLY_STDERR)
        assert d["limit"] is None, (
            "a loose match on 'Limit' picks up the requested increase and "
            "reports it as the ceiling")
        assert d["required"] is None  # the label is different, deliberately

    def test_the_message_admits_it_does_not_know(self):
        msg = _quota_message(
            _extract_quota_details(REQUIRED_ONLY_STDERR), "sgx-azure")
        assert "did not report a limit" in msg
        assert "limit=56" not in msg
        assert "standardDCSv3Family" in msg


class TestNothingIsInvented:
    @pytest.mark.parametrize("field", ["limit", "usage", "required",
                                       "location", "family", "subject"])
    def test_unparsed_fields_are_none(self, field):
        assert _extract_quota_details(SDK_BUG_STDERR)[field] is None

    def test_a_missing_limit_is_not_reported_as_zero(self):
        msg = _quota_message(_extract_quota_details(SDK_BUG_STDERR), "snp-azure")
        assert "limit=0" not in msg
        assert "did not report a limit" in msg

    def test_the_help_text_still_renders(self):
        """A hint with no parsed fields must still be a usable hint."""
        msg = _quota_message(_extract_quota_details(SDK_BUG_STDERR), "snp-azure")
        assert "Request a quota increase" in msg
        assert "--tee-platform snp-azure" in msg
        assert "the requested VM family" in msg

    def test_an_empty_string_does_not_raise(self):
        assert _quota_message(_extract_quota_details(""), "sgx-azure")


class TestBothCallSitesUseTheSameRenderer:
    def test_neither_formats_the_message_inline(self):
        import inspect
        from tee_crafter.cli.commands.baking.common import azure_cvm
        src = inspect.getsource(azure_cvm)
        assert src.count("_quota_message(") == 3  # 1 definition + 2 call sites
        assert "(limit={details['limit']})" not in src
