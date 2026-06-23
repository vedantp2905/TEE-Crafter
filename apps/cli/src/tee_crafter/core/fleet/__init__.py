"""Mixed on-demand + spot fleet management with cost preflight,
health-checked failover, and scale-to-zero schedules.

Public API exports the small surface most callers need; the deeper
classes (priority lists, schedulers) live in their submodules.
"""
from tee_crafter.core.fleet.spec import (  # noqa: F401
    FleetSpec, FleetMix, InstanceCandidate, HealthCheck, ScaleSchedule,
    FleetSpecError,
)
from tee_crafter.core.fleet.cost import (  # noqa: F401
    PriceQuote, CostEstimate, CostPreflight, PriceFeed, StaticPriceFeed,
    estimate_cost,
)
from tee_crafter.core.fleet.health import (  # noqa: F401
    HealthState, HealthChecker, HealthEvent,
)
from tee_crafter.core.fleet.scheduler import (  # noqa: F401
    FleetPlan, FleetScheduler, FailoverDecision,
)
