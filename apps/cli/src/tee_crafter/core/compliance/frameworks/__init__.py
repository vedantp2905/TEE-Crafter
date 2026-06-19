"""All built-in compliance framework definitions.

Four frameworks were removed rather than shipped with fabricated control
identifiers, because a wrong identifier is worse for an auditor than a missing
framework:

* ``cmmc_2`` — every practice id was the placeholder ``*.L2-b.1.D``.
* ``dora`` — every id (``ICT-RM-1``, ``TPRM-1``, ``RES-1``) was invented; none
  came from Regulation (EU) 2022/2554.
* ``iso_42001`` — ids were wrong, and ``A.11.2`` does not exist (ISO/IEC
  42001:2023 Annex A ends at A.10).
* ``fedramp`` — the ``"FedRAMP SC-8"`` prefix was invented. FedRAMP baselines
  *are* NIST 800-53 Rev 5 controls, so ``nist_800_53`` already covers them.

Reinstating any of these needs the real control catalogue in hand, not a
reconstruction from memory.
"""
from tee_crafter.core.compliance.frameworks.hipaa import FRAMEWORK as _hipaa
from tee_crafter.core.compliance.frameworks.soc2 import FRAMEWORK as _soc2
from tee_crafter.core.compliance.frameworks.pci_dss import FRAMEWORK as _pci_dss
from tee_crafter.core.compliance.frameworks.gdpr import FRAMEWORK as _gdpr
from tee_crafter.core.compliance.frameworks.ccpa import FRAMEWORK as _ccpa
from tee_crafter.core.compliance.frameworks.nist_800_53 import FRAMEWORK as _nist_800_53
from tee_crafter.core.compliance.frameworks.nist_csf import FRAMEWORK as _nist_csf
from tee_crafter.core.compliance.frameworks.iso_27001 import FRAMEWORK as _iso_27001
from tee_crafter.core.compliance.frameworks.iso_27701 import FRAMEWORK as _iso_27701
from tee_crafter.core.compliance.frameworks.hitrust import FRAMEWORK as _hitrust
from tee_crafter.core.compliance.frameworks.csa_ccm import FRAMEWORK as _csa_ccm
from tee_crafter.core.compliance.frameworks.glba import FRAMEWORK as _glba
from tee_crafter.core.compliance.frameworks.nis2 import FRAMEWORK as _nis2
from tee_crafter.core.compliance.frameworks.eu_ai_act import FRAMEWORK as _eu_ai_act

ALL_FRAMEWORKS = [
    _hipaa, _soc2, _pci_dss, _gdpr, _ccpa,
    _nist_800_53, _nist_csf, _iso_27001, _iso_27701,
    _hitrust, _csa_ccm, _glba,
    _nis2, _eu_ai_act,
]
