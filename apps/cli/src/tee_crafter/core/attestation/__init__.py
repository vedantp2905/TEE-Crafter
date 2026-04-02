"""Attestation collateral: builder-side fetch/verify of Intel PCS documents.

The modules here run on the *build* host.  They produce signature-verified
artifacts that get staged next to the generated client so the client can
re-verify everything offline, with no network access at connect time.
"""
