// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `testkit` CLI: run scenarios, regenerate golden captures, manage the lab.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs
)]

use std::process::ExitCode;

use anyhow::{Result, bail};
use testkit::lab::Shape;
use testkit::scenario::{self, Tag};

fn usage() -> ExitCode {
    eprintln!(
        "usage:
  testkit list
  testkit it [--shape v4|v6|dual] [--keep] [scenario ...]       run integration scenarios
  testkit capture [--shape ...] [scenario ...]                  run capture scenarios and promote goldens
  testkit run <scenario> [--shape ...] [--keep]                 run one scenario (any tag), no promotion
  testkit lab clean                                             remove stale lab bridges/namespaces
  testkit oracle ensure                                         download + verify pinned oracle binaries"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    testkit::init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return usage();
    };
    let rest = &args[1..];
    let r = match cmd.as_str() {
        "list" => {
            for s in scenario::all() {
                println!(
                    "{:<28} shapes={:?} tags={:?}",
                    s.name,
                    s.shapes.iter().map(|s| s.name()).collect::<Vec<_>>(),
                    s.tags
                );
            }
            Ok(true)
        }
        "it" => run_tagged(rest, Some(Tag::It), false),
        "capture" => run_tagged(rest, Some(Tag::Capture), true),
        "run" => run_tagged(rest, None, false),
        "lab" => match rest.first().map(String::as_str) {
            Some("clean") => testkit::lab::clean_all().map(|r| {
                println!("removed: {r:?}");
                true
            }),
            _ => return usage(),
        },
        "oracle" => match rest.first().map(String::as_str) {
            Some("ensure") => (|| {
                for line in [testkit::oracle::LtLine::Lt2, testkit::oracle::LtLine::Lt1] {
                    let p = testkit::oracle::ensure_binary(line)?;
                    println!("{}: {}", line.name(), p.display());
                }
                Ok(true)
            })(),
            _ => return usage(),
        },
        _ => return usage(),
    };
    match r {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_tagged(args: &[String], tag: Option<Tag>, promote: bool) -> Result<bool> {
    let mut shape_filter: Option<Shape> = None;
    let mut keep = false;
    let mut names: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--shape" => {
                i += 1;
                shape_filter = Some(
                    Shape::parse(args.get(i).map(String::as_str).unwrap_or(""))
                        .ok_or_else(|| anyhow::anyhow!("bad --shape"))?,
                );
            }
            "--keep" => keep = true,
            s if s.starts_with("--") => bail!("unknown flag {s}"),
            s => names.push(s.to_string()),
        }
        i += 1;
    }
    let defs: Vec<_> = scenario::all()
        .into_iter()
        .filter(|d| tag.is_none_or(|t| d.tags.contains(&t)))
        .filter(|d| names.is_empty() || names.iter().any(|n| n == d.name))
        .collect();
    if defs.is_empty() {
        bail!("no matching scenarios");
    }
    for n in &names {
        if !defs.iter().any(|d| d.name == n) {
            bail!("unknown scenario {n}");
        }
    }
    let mut failed = 0;
    let mut total = 0;
    for def in &defs {
        for &shape in def.shapes {
            if shape_filter.is_some_and(|s| s != shape) {
                continue;
            }
            total += 1;
            println!("=== {} [{}] ===", def.name, shape.name());
            let out = scenario::run_one(def, shape, keep);
            match &out.result {
                Ok(()) => {
                    println!(
                        "PASS {} [{}] in {:.1}s ({})",
                        def.name,
                        shape.name(),
                        out.elapsed.as_secs_f64(),
                        out.run_dir.display()
                    );
                    if promote {
                        let files = scenario::promote_golden(&out)?;
                        for f in files {
                            println!("  golden: {}", f.display());
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    println!(
                        "FAIL {} [{}] in {:.1}s: {e:#}\n  artifacts: {}",
                        def.name,
                        shape.name(),
                        out.elapsed.as_secs_f64(),
                        out.run_dir.display()
                    );
                }
            }
        }
    }
    println!("{} scenario runs, {failed} failed", total);
    Ok(failed == 0)
}
