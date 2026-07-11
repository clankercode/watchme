//! Capability-probed planner routing with same-family exclusion.

use std::path::PathBuf;

use crate::config::PlanningConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannerCapability {
    pub id: String,
    pub executable: PathBuf,
    pub configured_family: String,
    pub resolved_family: String,
    pub available: bool,
    pub unsafe_mode: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPlanner {
    pub id: String,
    pub executable: PathBuf,
    pub provider_family: String,
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouterOutcome {
    pub eligible: Vec<ResolvedPlanner>,
    pub human_required: bool,
}

#[derive(Clone, Debug)]
pub struct PlannerRouter {
    planning: PlanningConfig,
}

impl PlannerRouter {
    pub fn new(planning: PlanningConfig) -> Self {
        Self { planning }
    }

    pub fn select(&self, failed_family: &str, candidates: &[PlannerCapability]) -> RouterOutcome {
        let eligible = resolve_eligible_planners(&self.planning, failed_family, candidates);
        RouterOutcome {
            human_required: eligible.is_empty(),
            eligible,
        }
    }

    pub fn resolve_from_probes(
        &self,
        failed_family: &str,
        probes: &[PlannerCapability],
    ) -> RouterOutcome {
        self.select(failed_family, probes)
    }
}

/// Resolve eligible planners using actual probed provider families.
pub fn resolve_eligible_planners(
    planning: &PlanningConfig,
    failed_family: &str,
    candidates: &[PlannerCapability],
) -> Vec<ResolvedPlanner> {
    if !planning.enabled {
        return Vec::new();
    }
    let mut by_id: std::collections::BTreeMap<&str, &PlannerCapability> = candidates
        .iter()
        .map(|candidate| (candidate.id.as_str(), candidate))
        .collect();

    let mut eligible = Vec::new();
    for id in &planning.planner_priority {
        let Some(candidate) = by_id.remove(id.as_str()) else {
            continue;
        };
        if !candidate.available || candidate.unsafe_mode {
            continue;
        }
        if let Some(config) = planning.planners.get(id)
            && !config.enabled
        {
            continue;
        }
        let family = normalize_family(&candidate.resolved_family);
        if family == "unknown" && !planning.allow_unknown_provider_family {
            continue;
        }
        if family == normalize_family(failed_family) {
            continue;
        }
        eligible.push(ResolvedPlanner {
            id: candidate.id.clone(),
            executable: candidate.executable.clone(),
            provider_family: family,
            args: Vec::new(),
        });
    }
    eligible
}

fn normalize_family(family: &str) -> String {
    family.trim().to_ascii_lowercase()
}
