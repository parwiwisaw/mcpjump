//! `ProcessEnv` and `MapEnv` obey the same `Env` contract.

use mcpjump::sys::env::{Env, ProcessEnv};

use crate::support::fakes::env::MapEnv;

const UNSET: &str = "MCPJUMP_TEST_SURELY_UNSET_VARIABLE";

fn check_contract(env: &dyn Env, path: &str) {
    assert_eq!(env.var("PATH").as_deref(), Some(path));
    assert_eq!(env.var(UNSET), None);
}

#[test]
fn process_env_and_map_env_agree() {
    let path = std::env::var("PATH").unwrap();
    check_contract(&ProcessEnv, &path);
    check_contract(&MapEnv::default().with("PATH", &path), &path);
}
