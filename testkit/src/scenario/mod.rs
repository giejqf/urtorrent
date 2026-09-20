// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Scenario registry and runner. A scenario is a function over a [`Ctx`] that
//! builds actors in a fresh lab, drives them, asserts, and optionally records
//! artifacts (tap logs) that `xtask capture` promotes to golden files.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::lab::{Actor, Lab, Shape};
use crate::oracle::{Oracle, OracleConfig};

pub mod m0;
pub mod m2;
pub mod m3;
pub mod m4;
pub mod m5;
pub mod m6;
pub mod m8;

/// Which command a scenario belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    /// `xtask it`: an integration assertion.
    It,
    /// `xtask capture`: produces golden captures from the oracle.
    Capture,
    /// `xtask diff`: differential oracle-vs-us run.
    Diff,
}

/// A registered scenario.
pub struct ScenarioDef {
    pub name: &'static str,
    pub shapes: &'static [Shape],
    pub tags: &'static [Tag],
    pub run: fn(&mut Ctx) -> Result<()>,
}

/// Runtime context handed to a scenario.
pub struct Ctx {
    pub lab: Lab,
    pub shape: Shape,
    pub run_dir: PathBuf,
    pub artifacts: Vec<(String, PathBuf)>,
    pub notes: Vec<String>,
    started: Instant,
}

impl Ctx {
    pub fn whitelist(&self) -> Vec<String> {
        vec![self.lab.v4_subnet(), self.lab.v6_subnet()]
    }

    /// The harness's address on the bridge, in the family the shape wants.
    pub fn host_addr(&self) -> IpAddr {
        self.lab.host_addr(self.shape)
    }

    /// Every harness address usable by actors of this shape.
    pub fn host_addrs(&self) -> Vec<IpAddr> {
        let mut v = Vec::new();
        if self.shape.has_v4() {
            v.push(IpAddr::V4(self.lab.host_v4()));
        }
        if self.shape.has_v6() {
            v.push(IpAddr::V6(self.lab.host_v6()));
        }
        v
    }

    /// A distinct harness-side address (index 2..9) in the shape's family.
    pub fn host_alias(&self, n: u8) -> Result<IpAddr> {
        let (v4, v6) = self.lab.host_alias(n)?;
        Ok(if self.shape.has_v4() {
            IpAddr::V4(v4)
        } else {
            IpAddr::V6(v6)
        })
    }

    pub fn actor(&mut self, name: &str) -> Result<Actor> {
        self.lab.actor_with_shape(name, self.shape)
    }

    pub fn oracle(&mut self, name: &str, config: OracleConfig) -> Result<Oracle> {
        let actor = self.actor(name)?;
        let wl = self.whitelist();
        Oracle::launch(&actor, config, &wl).with_context(|| format!("launching oracle {name}"))
    }

    /// Launch the library under test (`urt-client`) as an actor.
    pub fn client(
        &mut self,
        name: &str,
        config: crate::client::ClientConfig,
        torrent: &Path,
    ) -> Result<crate::client::UrtClient> {
        let actor = self.actor(name)?;
        crate::client::UrtClient::launch(&actor, config, torrent)
            .with_context(|| format!("launching client {name}"))
    }

    /// Register a file produced by the scenario as an artifact (golden candidate).
    pub fn artifact(&mut self, name: &str, path: &Path) {
        self.artifacts.push((name.to_string(), path.to_path_buf()));
    }

    pub fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        tracing::info!("{s}");
        self.notes.push(s);
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.run_dir.join(name)
    }
}

/// All registered scenarios.
pub fn all() -> Vec<ScenarioDef> {
    let mut v = Vec::new();
    v.extend(m0::scenarios());
    v.extend(m2::scenarios());
    v.extend(m3::scenarios());
    v.extend(m4::scenarios());
    v.extend(m5::scenarios());
    v.extend(m6::scenarios());
    v.extend(m8::scenarios());
    v
}

pub fn find(name: &str) -> Option<ScenarioDef> {
    all().into_iter().find(|s| s.name == name)
}

/// Root for run artifacts.
pub fn runs_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("runs")
}

/// Root for golden captures.
pub fn golden_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("golden")
}

/// Outcome of one scenario run.
pub struct Outcome {
    pub name: String,
    pub shape: Shape,
    pub run_dir: PathBuf,
    pub artifacts: Vec<(String, PathBuf)>,
    pub notes: Vec<String>,
    pub elapsed: Duration,
    pub result: Result<()>,
}

/// Run one scenario in one shape.
pub fn run_one(def: &ScenarioDef, shape: Shape, keep_lab: bool) -> Outcome {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let run_dir = runs_root().join(format!("{stamp}-{}-{}", def.name, shape.name()));
    let started = Instant::now();
    let lab = match Lab::create(&run_dir) {
        Ok(l) => l,
        Err(e) => {
            return Outcome {
                name: def.name.into(),
                shape,
                run_dir,
                artifacts: Vec::new(),
                notes: Vec::new(),
                elapsed: started.elapsed(),
                result: Err(e),
            };
        }
    };
    let mut ctx = Ctx {
        lab,
        shape,
        run_dir: run_dir.clone(),
        artifacts: Vec::new(),
        notes: Vec::new(),
        started,
    };
    if keep_lab {
        ctx.lab.keep();
    }
    let result = (def.run)(&mut ctx);
    let elapsed = ctx.elapsed();
    let Ctx {
        artifacts, notes, ..
    } = ctx;
    Outcome {
        name: def.name.into(),
        shape,
        run_dir,
        artifacts,
        notes,
        elapsed,
        result,
    }
}

/// Copy a run's artifacts into the golden tree.
pub fn promote_golden(outcome: &Outcome) -> Result<Vec<PathBuf>> {
    if outcome.result.is_err() {
        bail!("not promoting a failed run");
    }
    let dir = golden_root().join(&outcome.name).join(outcome.shape.name());
    std::fs::create_dir_all(&dir)?;
    let mut out = Vec::new();
    for (name, path) in &outcome.artifacts {
        let dst = dir.join(name);
        std::fs::copy(path, &dst)
            .with_context(|| format!("copy {} -> {}", path.display(), dst.display()))?;
        out.push(dst);
    }
    Ok(out)
}

/// Golden path for an artifact of a scenario/shape, if it exists.
pub fn golden_file(scenario: &str, shape: Shape, name: &str) -> Option<PathBuf> {
    let p = golden_root().join(scenario).join(shape.name()).join(name);
    p.exists().then_some(p)
}
