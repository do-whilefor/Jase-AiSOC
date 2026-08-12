use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aisoc_contracts::{
    AdapterExecutionResult, AdapterRollbackResult, ApprovalDecision, ExecutionResultStatus,
    ResponseActionDetail, ResponseActionStatus, ResponseExecutionRead, ResponseRollbackRead,
    ResponseTarget, RollbackResultStatus, TargetObservation,
};
use aisoc_core::{sha256_file, sha256_hex};
use aisoc_storage::{AppendOnlyJsonl, StorageError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    prepare_operation, revalidate_account_target, revalidate_file_target, revalidate_ip_target,
    RegisteredOperation, ResponseError,
};

const MAX_ACTION_JOURNAL_RECORDS: usize = 1_000_000;
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerIdentity {
    pub host_id: String,
    pub agent_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseRunnerConfig {
    pub enabled: bool,
    pub quarantine_directory: PathBuf,
    pub nft_binary: PathBuf,
    pub nft_family: String,
    pub nft_table: String,
    pub nft_set: String,
    pub usermod_binary: PathBuf,
}

impl Default for ResponseRunnerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            quarantine_directory: PathBuf::from("/var/lib/aisoc-agent/quarantine"),
            nft_binary: PathBuf::from("/usr/sbin/nft"),
            nft_family: "inet".to_owned(),
            nft_table: "aisoc".to_owned(),
            nft_set: "blocked_ipv4".to_owned(),
            usermod_binary: PathBuf::from("/usr/sbin/usermod"),
        }
    }
}

impl ResponseRunnerConfig {
    pub fn validate(&self) -> Result<(), RunnerError> {
        if !self.quarantine_directory.is_absolute()
            || !self.nft_binary.is_absolute()
            || !self.usermod_binary.is_absolute()
            || !matches!(self.nft_family.as_str(), "inet" | "ip" | "ip6")
            || !safe_nft_identifier(&self.nft_table)
            || !safe_nft_identifier(&self.nft_set)
        {
            return Err(RunnerError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RollbackToken {
    TemporaryIpBlock {
        ip_address: String,
    },
    FileQuarantine {
        original_path: String,
        quarantine_path: String,
        sha256: String,
    },
    AccountLock {
        username: String,
        uid: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case", deny_unknown_fields)]
enum RunnerJournalRecord {
    Execution {
        idempotency_key: String,
        action_id: String,
        execution: ResponseExecutionRead,
        rollback_token: RollbackToken,
    },
    Rollback {
        idempotency_key: String,
        action_id: String,
        execution_id: String,
        rollback: ResponseRollbackRead,
    },
}

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("response runner is disabled")]
    Disabled,
    #[error("response runner configuration is invalid")]
    InvalidConfiguration,
    #[error("response action detail is invalid")]
    InvalidAction,
    #[error("response action is not authorized for this Agent identity")]
    IdentityMismatch,
    #[error("response action approval facts do not satisfy the policy")]
    ApprovalMismatch,
    #[error("response action expired before execution")]
    Expired,
    #[error("response operation is not supported by this runner")]
    UnsupportedOperation,
    #[error("idempotency key conflicts with another response action")]
    IdempotencyConflict,
    #[error("response execution has no rollback state")]
    MissingRollbackState,
    #[error("response target changed before or during execution")]
    TargetChanged,
    #[error("fixed response adapter failed: {0}")]
    Adapter(String),
    #[error("response runner I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("response runner JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("response runner storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("response validation failed: {0}")]
    Response(#[from] ResponseError),
    #[error("response runner journal is inconsistent")]
    InvalidJournal,
}

#[derive(Debug)]
pub struct ResponseRunner {
    identity: RunnerIdentity,
    config: ResponseRunnerConfig,
    journal: AppendOnlyJsonl<RunnerJournalRecord>,
    executions_by_key: BTreeMap<String, (String, ResponseExecutionRead, RollbackToken)>,
    executions_by_id: BTreeMap<String, (String, ResponseExecutionRead, RollbackToken)>,
    rollbacks_by_key: BTreeMap<String, (String, ResponseRollbackRead)>,
}

impl ResponseRunner {
    pub fn open(
        path: impl AsRef<Path>,
        identity: RunnerIdentity,
        config: ResponseRunnerConfig,
    ) -> Result<Self, RunnerError> {
        config.validate()?;
        validate_runner_identity(&identity)?;
        let journal = AppendOnlyJsonl::<RunnerJournalRecord>::open(path)?;
        let records = journal.read_all()?;
        if records.len() > MAX_ACTION_JOURNAL_RECORDS {
            return Err(RunnerError::InvalidJournal);
        }
        let mut runner = Self {
            identity,
            config,
            journal,
            executions_by_key: BTreeMap::new(),
            executions_by_id: BTreeMap::new(),
            rollbacks_by_key: BTreeMap::new(),
        };
        for record in records {
            runner.restore_record(record)?;
        }
        Ok(runner)
    }

    pub fn execute(
        &mut self,
        detail: &ResponseActionDetail,
        idempotency_key: &str,
    ) -> Result<ResponseExecutionRead, RunnerError> {
        self.preflight(detail, idempotency_key)?;
        if let Some((action_id, execution, _)) = self.executions_by_key.get(idempotency_key) {
            if action_id == &detail.plan.action_id {
                return Ok(execution.clone());
            }
            return Err(RunnerError::IdempotencyConflict);
        }

        let started_at = now();
        let operation = prepare_operation(&detail.plan)?;
        let (result, rollback_token) = match operation {
            RegisteredOperation::TemporaryIpBlock {
                ip,
                ttl_seconds,
                ..
            } => self.execute_ip_block(detail, &ip, ttl_seconds)?,
            RegisteredOperation::QuarantineFile { target } => {
                self.execute_file_quarantine(detail, &target)?
            }
            RegisteredOperation::DisableAccount { target } => {
                self.execute_account_lock(detail, &target)?
            }
            RegisteredOperation::CollectEvidence { .. }
            | RegisteredOperation::TerminateProcess { .. }
            | RegisteredOperation::IsolateHost { .. } => {
                return Err(RunnerError::UnsupportedOperation)
            }
        };
        let completed_at = now();
        let execution = ResponseExecutionRead {
            execution_id: format!("rex_{}", Uuid::new_v4().simple()),
            action_id: detail.plan.action_id.clone(),
            attempt: next_attempt(&self.executions_by_id, &detail.plan.action_id),
            idempotency_key: idempotency_key.to_owned(),
            status: result.status,
            result,
            started_at,
            completed_at,
        };
        if !execution.is_valid() {
            return Err(RunnerError::InvalidAction);
        }
        let record = RunnerJournalRecord::Execution {
            idempotency_key: idempotency_key.to_owned(),
            action_id: detail.plan.action_id.clone(),
            execution: execution.clone(),
            rollback_token: rollback_token.clone(),
        };
        self.journal.append(record)?;
        self.executions_by_key.insert(
            idempotency_key.to_owned(),
            (
                detail.plan.action_id.clone(),
                execution.clone(),
                rollback_token.clone(),
            ),
        );
        self.executions_by_id.insert(
            execution.execution_id.clone(),
            (detail.plan.action_id.clone(), execution.clone(), rollback_token),
        );
        Ok(execution)
    }

    pub fn rollback(
        &mut self,
        detail: &ResponseActionDetail,
        execution_id: &str,
        idempotency_key: &str,
        requested_by: &str,
        reason: &str,
    ) -> Result<ResponseRollbackRead, RunnerError> {
        self.preflight_common(detail, idempotency_key)?;
        if !bounded_text(requested_by, 1, 256) || !bounded_text(reason, 1, 512) {
            return Err(RunnerError::InvalidAction);
        }
        if let Some((action_id, rollback)) = self.rollbacks_by_key.get(idempotency_key) {
            if action_id == &detail.plan.action_id && rollback.execution_id == execution_id {
                return Ok(rollback.clone());
            }
            return Err(RunnerError::IdempotencyConflict);
        }
        let Some((action_id, execution, token)) = self.executions_by_id.get(execution_id).cloned()
        else {
            return Err(RunnerError::MissingRollbackState);
        };
        if action_id != detail.plan.action_id || execution.status != ExecutionResultStatus::Succeeded {
            return Err(RunnerError::MissingRollbackState);
        }

        let started_at = now();
        let result = match token {
            RollbackToken::TemporaryIpBlock { ip_address } => {
                self.rollback_ip_block(detail, &ip_address)?
            }
            RollbackToken::FileQuarantine {
                original_path,
                quarantine_path,
                sha256,
            } => self.rollback_file_quarantine(
                detail,
                &original_path,
                &quarantine_path,
                &sha256,
            )?,
            RollbackToken::AccountLock { username, uid } => {
                self.rollback_account_lock(detail, &username, uid)?
            }
        };
        let rollback = ResponseRollbackRead {
            rollback_id: format!("rrb_{}", Uuid::new_v4().simple()),
            action_id: detail.plan.action_id.clone(),
            execution_id: execution_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            reason: reason.to_owned(),
            requested_by: requested_by.to_owned(),
            status: result.status,
            result,
            started_at,
            completed_at: now(),
        };
        if !rollback.is_valid() {
            return Err(RunnerError::InvalidAction);
        }
        let record = RunnerJournalRecord::Rollback {
            idempotency_key: idempotency_key.to_owned(),
            action_id: detail.plan.action_id.clone(),
            execution_id: execution_id.to_owned(),
            rollback: rollback.clone(),
        };
        self.journal.append(record)?;
        self.rollbacks_by_key.insert(
            idempotency_key.to_owned(),
            (detail.plan.action_id.clone(), rollback.clone()),
        );
        Ok(rollback)
    }

    fn preflight(
        &self,
        detail: &ResponseActionDetail,
        idempotency_key: &str,
    ) -> Result<(), RunnerError> {
        self.preflight_common(detail, idempotency_key)?;
        if !matches!(
            detail.plan.status,
            ResponseActionStatus::Approved | ResponseActionStatus::Queued
        ) {
            return Err(RunnerError::InvalidAction);
        }
        if let Some(expires_at) = detail.plan.expires_at.as_deref() {
            let expires = DateTime::parse_from_rfc3339(expires_at)
                .map_err(|_| RunnerError::InvalidAction)?;
            if Utc::now() >= expires {
                return Err(RunnerError::Expired);
            }
        }
        verify_approvals(detail)?;
        Ok(())
    }

    fn preflight_common(
        &self,
        detail: &ResponseActionDetail,
        idempotency_key: &str,
    ) -> Result<(), RunnerError> {
        if !self.config.enabled {
            return Err(RunnerError::Disabled);
        }
        if !detail.is_valid() || !valid_idempotency_key(idempotency_key) {
            return Err(RunnerError::InvalidAction);
        }
        if detail.plan.target.host_id() != self.identity.host_id
            || expected_agent_id(&detail.plan.target) != self.identity.agent_id
        {
            return Err(RunnerError::IdentityMismatch);
        }
        Ok(())
    }

    fn execute_ip_block(
        &self,
        detail: &ResponseActionDetail,
        ip: &str,
        ttl_seconds: u32,
    ) -> Result<(AdapterExecutionResult, RollbackToken), RunnerError> {
        let ResponseTarget::Ip(target) = &detail.plan.target else {
            return Err(RunnerError::InvalidAction);
        };
        revalidate_ip_target(target)?;
        validate_fixed_executable(&self.config.nft_binary)?;
        let before_blocked = self.nft_contains(ip)?;
        if before_blocked {
            return Err(RunnerError::TargetChanged);
        }
        let before = observation(
            detail.plan.target.clone(),
            json!({"blocked": false, "ip_address": ip}),
        )?;
        let timeout = format!("{ttl_seconds}s");
        self.run_fixed(
            &self.config.nft_binary,
            &[
                "add",
                "element",
                &self.config.nft_family,
                &self.config.nft_table,
                &self.config.nft_set,
                "{",
                ip,
                "timeout",
                &timeout,
                "}",
            ],
        )?;
        if !self.nft_contains(ip)? {
            return Err(RunnerError::Adapter("nft_postcondition_failed".to_owned()));
        }
        let after = observation(
            detail.plan.target.clone(),
            json!({"blocked": true, "ip_address": ip, "ttl_seconds": ttl_seconds}),
        )?;
        Ok((
            successful_execution("nftables", operation_ref(&detail.plan.action_id), before, after),
            RollbackToken::TemporaryIpBlock {
                ip_address: ip.to_owned(),
            },
        ))
    }

    fn rollback_ip_block(
        &self,
        detail: &ResponseActionDetail,
        ip: &str,
    ) -> Result<AdapterRollbackResult, RunnerError> {
        let ResponseTarget::Ip(target) = &detail.plan.target else {
            return Err(RunnerError::InvalidAction);
        };
        if target.ip_address != ip {
            return Err(RunnerError::TargetChanged);
        }
        validate_fixed_executable(&self.config.nft_binary)?;
        if !self.nft_contains(ip)? {
            return Err(RunnerError::TargetChanged);
        }
        let before = observation(
            detail.plan.target.clone(),
            json!({"blocked": true, "ip_address": ip}),
        )?;
        self.run_fixed(
            &self.config.nft_binary,
            &[
                "delete",
                "element",
                &self.config.nft_family,
                &self.config.nft_table,
                &self.config.nft_set,
                "{",
                ip,
                "}",
            ],
        )?;
        if self.nft_contains(ip)? {
            return Err(RunnerError::Adapter("nft_rollback_postcondition_failed".to_owned()));
        }
        let after = observation(
            detail.plan.target.clone(),
            json!({"blocked": false, "ip_address": ip}),
        )?;
        Ok(successful_rollback(
            "nftables",
            operation_ref(&detail.plan.action_id),
            before,
            after,
        ))
    }

    fn execute_file_quarantine(
        &self,
        detail: &ResponseActionDetail,
        target: &aisoc_contracts::FileResponseTarget,
    ) -> Result<(AdapterExecutionResult, RollbackToken), RunnerError> {
        revalidate_file_target(target)?;
        prepare_private_directory(&self.config.quarantine_directory)?;
        let source = Path::new(&target.path);
        let destination = self.config.quarantine_directory.join(format!(
            "{}-{}",
            detail.plan.action_id, target.sha256
        ));
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(RunnerError::TargetChanged);
        }
        let before = file_observation(detail.plan.target.clone(), source, false)?;
        fs::rename(source, &destination)?;
        let rollback_on_failure = || -> Result<(), std::io::Error> {
            if fs::symlink_metadata(source).is_err() && fs::symlink_metadata(&destination).is_ok() {
                fs::rename(&destination, source)?;
            }
            Ok(())
        };
        let verification = (|| -> Result<TargetObservation, RunnerError> {
            if fs::symlink_metadata(source).is_ok() {
                return Err(RunnerError::TargetChanged);
            }
            let (actual_sha256, _) = sha256_file(&destination, 512 * 1024 * 1024)?;
            if actual_sha256 != target.sha256 {
                return Err(RunnerError::TargetChanged);
            }
            file_observation(detail.plan.target.clone(), &destination, true)
        })();
        let after = match verification {
            Ok(value) => value,
            Err(error) => {
                let _ = rollback_on_failure();
                return Err(error);
            }
        };
        Ok((
            successful_execution(
                "native_file",
                operation_ref(&detail.plan.action_id),
                before,
                after,
            ),
            RollbackToken::FileQuarantine {
                original_path: target.path.clone(),
                quarantine_path: destination.to_string_lossy().into_owned(),
                sha256: target.sha256.clone(),
            },
        ))
    }

    fn rollback_file_quarantine(
        &self,
        detail: &ResponseActionDetail,
        original_path: &str,
        quarantine_path: &str,
        expected_sha256: &str,
    ) -> Result<AdapterRollbackResult, RunnerError> {
        let ResponseTarget::File(target) = &detail.plan.target else {
            return Err(RunnerError::InvalidAction);
        };
        if target.path != original_path || target.sha256 != expected_sha256 {
            return Err(RunnerError::TargetChanged);
        }
        let original = Path::new(original_path);
        let quarantined = Path::new(quarantine_path);
        if fs::symlink_metadata(original).is_ok() {
            return Err(RunnerError::TargetChanged);
        }
        let metadata = fs::symlink_metadata(quarantined)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RunnerError::TargetChanged);
        }
        let (sha, _) = sha256_file(quarantined, 512 * 1024 * 1024)?;
        if sha != expected_sha256 {
            return Err(RunnerError::TargetChanged);
        }
        let before = file_observation(detail.plan.target.clone(), quarantined, true)?;
        fs::rename(quarantined, original)?;
        revalidate_file_target(target)?;
        let after = file_observation(detail.plan.target.clone(), original, false)?;
        Ok(successful_rollback(
            "native_file",
            operation_ref(&detail.plan.action_id),
            before,
            after,
        ))
    }

    fn execute_account_lock(
        &self,
        detail: &ResponseActionDetail,
        target: &aisoc_contracts::AccountResponseTarget,
    ) -> Result<(AdapterExecutionResult, RollbackToken), RunnerError> {
        revalidate_account_target(target)?;
        if target.locked {
            return Err(RunnerError::TargetChanged);
        }
        validate_fixed_executable(&self.config.usermod_binary)?;
        let current = inspect_account(&target.username)?;
        if current.uid != target.uid || current.shell != target.shell || current.locked != target.locked {
            return Err(RunnerError::TargetChanged);
        }
        let before = account_observation(detail.plan.target.clone(), &current)?;
        self.run_fixed(
            &self.config.usermod_binary,
            &["-L", "--", &target.username],
        )?;
        let after_state = inspect_account(&target.username)?;
        if after_state.uid != target.uid || !after_state.locked {
            return Err(RunnerError::Adapter("account_lock_postcondition_failed".to_owned()));
        }
        let after = account_observation(detail.plan.target.clone(), &after_state)?;
        Ok((
            successful_execution(
                "shadow_usermod",
                operation_ref(&detail.plan.action_id),
                before,
                after,
            ),
            RollbackToken::AccountLock {
                username: target.username.clone(),
                uid: target.uid,
            },
        ))
    }

    fn rollback_account_lock(
        &self,
        detail: &ResponseActionDetail,
        username: &str,
        uid: u32,
    ) -> Result<AdapterRollbackResult, RunnerError> {
        let ResponseTarget::Account(target) = &detail.plan.target else {
            return Err(RunnerError::InvalidAction);
        };
        if target.username != username || target.uid != uid || target.locked {
            return Err(RunnerError::TargetChanged);
        }
        validate_fixed_executable(&self.config.usermod_binary)?;
        let current = inspect_account(username)?;
        if current.uid != uid || !current.locked {
            return Err(RunnerError::TargetChanged);
        }
        let before = account_observation(detail.plan.target.clone(), &current)?;
        self.run_fixed(&self.config.usermod_binary, &["-U", "--", username])?;
        let after_state = inspect_account(username)?;
        if after_state.uid != uid || after_state.locked {
            return Err(RunnerError::Adapter("account_unlock_postcondition_failed".to_owned()));
        }
        let after = account_observation(detail.plan.target.clone(), &after_state)?;
        Ok(successful_rollback(
            "shadow_usermod",
            operation_ref(&detail.plan.action_id),
            before,
            after,
        ))
    }

    fn nft_contains(&self, ip: &str) -> Result<bool, RunnerError> {
        let output = self.run_fixed_allow_status(
            &self.config.nft_binary,
            &[
                "get",
                "element",
                &self.config.nft_family,
                &self.config.nft_table,
                &self.config.nft_set,
                "{",
                ip,
                "}",
            ],
        )?;
        if output.status.success() {
            Ok(true)
        } else if output.status.code() == Some(1) {
            Ok(false)
        } else {
            Err(command_failure("nft_query_failed", &output))
        }
    }

    fn run_fixed(&self, executable: &Path, args: &[&str]) -> Result<Output, RunnerError> {
        let output = self.run_fixed_allow_status(executable, args)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(command_failure("fixed_adapter_failed", &output))
        }
    }

    fn run_fixed_allow_status(
        &self,
        executable: &Path,
        args: &[&str],
    ) -> Result<Output, RunnerError> {
        if args.iter().any(|arg| {
            arg.is_empty()
                || arg.len() > 4096
                || arg.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
        }) {
            return Err(RunnerError::InvalidAction);
        }
        let output = Command::new(executable)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output()?;
        if output.stdout.len() > MAX_COMMAND_OUTPUT || output.stderr.len() > MAX_COMMAND_OUTPUT {
            return Err(RunnerError::Adapter("adapter_output_too_large".to_owned()));
        }
        Ok(output)
    }

    fn restore_record(&mut self, record: RunnerJournalRecord) -> Result<(), RunnerError> {
        match record {
            RunnerJournalRecord::Execution {
                idempotency_key,
                action_id,
                execution,
                rollback_token,
            } => {
                if !valid_idempotency_key(&idempotency_key)
                    || !execution.is_valid()
                    || execution.idempotency_key != idempotency_key
                    || execution.action_id != action_id
                    || self.executions_by_key.contains_key(&idempotency_key)
                    || self.executions_by_id.contains_key(&execution.execution_id)
                {
                    return Err(RunnerError::InvalidJournal);
                }
                self.executions_by_key.insert(
                    idempotency_key,
                    (action_id.clone(), execution.clone(), rollback_token.clone()),
                );
                self.executions_by_id.insert(
                    execution.execution_id.clone(),
                    (action_id, execution, rollback_token),
                );
            }
            RunnerJournalRecord::Rollback {
                idempotency_key,
                action_id,
                execution_id,
                rollback,
            } => {
                let Some((stored_action, _, _)) = self.executions_by_id.get(&execution_id) else {
                    return Err(RunnerError::InvalidJournal);
                };
                if !valid_idempotency_key(&idempotency_key)
                    || !rollback.is_valid()
                    || rollback.idempotency_key != idempotency_key
                    || rollback.action_id != action_id
                    || rollback.execution_id != execution_id
                    || stored_action != &action_id
                    || self.rollbacks_by_key.contains_key(&idempotency_key)
                {
                    return Err(RunnerError::InvalidJournal);
                }
                self.rollbacks_by_key
                    .insert(idempotency_key, (action_id, rollback));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AccountState {
    username: String,
    uid: u32,
    shell: String,
    locked: bool,
}

fn inspect_account(username: &str) -> Result<AccountState, RunnerError> {
    let passwd = read_bounded_regular(Path::new("/etc/passwd"), 16 * 1024 * 1024)?;
    let passwd_text = std::str::from_utf8(&passwd)
        .map_err(|_| RunnerError::Adapter("passwd_not_utf8".to_owned()))?;
    let mut uid = None;
    let mut shell = None;
    for line in passwd_text.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() == 7 && fields[0] == username {
            uid = fields[2].parse::<u32>().ok();
            shell = Some(fields[6].to_owned());
            break;
        }
    }
    let (Some(uid), Some(shell)) = (uid, shell) else {
        return Err(RunnerError::TargetChanged);
    };
    let shadow = read_bounded_regular(Path::new("/etc/shadow"), 16 * 1024 * 1024)?;
    let shadow_text = std::str::from_utf8(&shadow)
        .map_err(|_| RunnerError::Adapter("shadow_not_utf8".to_owned()))?;
    let mut locked = None;
    for line in shadow_text.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(username) {
            let password = fields.next().ok_or(RunnerError::TargetChanged)?;
            locked = Some(password.starts_with('!') || password.starts_with('*'));
            break;
        }
    }
    Ok(AccountState {
        username: username.to_owned(),
        uid,
        shell,
        locked: locked.ok_or(RunnerError::TargetChanged)?,
    })
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, RunnerError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > maximum {
        return Err(RunnerError::TargetChanged);
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(RunnerError::TargetChanged);
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    use std::io::Read;
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(RunnerError::TargetChanged);
    }
    Ok(bytes)
}

fn prepare_private_directory(path: &Path) -> Result<(), RunnerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(RunnerError::InvalidConfiguration)
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn validate_fixed_executable(path: &Path) -> Result<(), RunnerError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RunnerError::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(RunnerError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn verify_approvals(detail: &ResponseActionDetail) -> Result<(), RunnerError> {
    if detail
        .approvals
        .iter()
        .any(|approval| approval.decision == ApprovalDecision::Reject)
    {
        return Err(RunnerError::ApprovalMismatch);
    }
    let approvals = detail
        .approvals
        .iter()
        .filter(|approval| approval.decision == ApprovalDecision::Approve)
        .collect::<Vec<_>>();
    let unique = approvals
        .iter()
        .map(|approval| approval.approver.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() != approvals.len()
        || approvals.len() < detail.plan.policy.required_approvals as usize
        || detail.plan.approval_count != approvals.len() as u8
        || (detail.plan.policy.business_confirmation_required
            && !approvals.iter().any(|approval| approval.business_confirmation))
    {
        return Err(RunnerError::ApprovalMismatch);
    }
    Ok(())
}

fn expected_agent_id(target: &ResponseTarget) -> &str {
    match target {
        ResponseTarget::Ip(target) => &target.expected_agent_id,
        ResponseTarget::Process(target) => &target.expected_agent_id,
        ResponseTarget::File(target) => &target.expected_agent_id,
        ResponseTarget::Account(target) => &target.expected_agent_id,
        ResponseTarget::Host(target) => &target.expected_agent_id,
        ResponseTarget::EvidenceCollection(target) => &target.expected_agent_id,
    }
}

fn validate_runner_identity(identity: &RunnerIdentity) -> Result<(), RunnerError> {
    if !identity.host_id.starts_with("host_")
        || identity.host_id.len() < 13
        || !identity.agent_id.starts_with("agent_")
        || identity.agent_id.len() < 14
    {
        return Err(RunnerError::InvalidConfiguration);
    }
    Ok(())
}

fn observation(target: ResponseTarget, state: Value) -> Result<TargetObservation, RunnerError> {
    let state_sha256 = sha256_hex(&serde_json::to_vec(&state)?);
    let mut fields = BTreeMap::new();
    let Value::Object(values) = state else {
        return Err(RunnerError::InvalidAction);
    };
    for (key, value) in values {
        fields.insert(key, value);
    }
    let observation = TargetObservation {
        target,
        observed_at: now(),
        state_sha256,
        state: fields,
    };
    if observation.is_valid() {
        Ok(observation)
    } else {
        Err(RunnerError::InvalidAction)
    }
}

fn file_observation(
    target: ResponseTarget,
    path: &Path,
    quarantined: bool,
) -> Result<TargetObservation, RunnerError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RunnerError::TargetChanged);
    }
    let (sha256, size) = sha256_file(path, 512 * 1024 * 1024)?;
    observation(
        target,
        json!({
            "path": path.to_string_lossy(),
            "sha256": sha256,
            "size": size,
            "quarantined": quarantined,
        }),
    )
}

fn account_observation(
    target: ResponseTarget,
    state: &AccountState,
) -> Result<TargetObservation, RunnerError> {
    observation(
        target,
        json!({
            "username": state.username,
            "uid": state.uid,
            "shell": state.shell,
            "locked": state.locked,
        }),
    )
}

fn successful_execution(
    adapter: &str,
    operation_reference: String,
    before: TargetObservation,
    after: TargetObservation,
) -> AdapterExecutionResult {
    AdapterExecutionResult {
        status: ExecutionResultStatus::Succeeded,
        adapter: adapter.to_owned(),
        operation_reference,
        before,
        after: Some(after),
        verification_passed: true,
        error_code: None,
    }
}

fn successful_rollback(
    adapter: &str,
    operation_reference: String,
    before: TargetObservation,
    after: TargetObservation,
) -> AdapterRollbackResult {
    AdapterRollbackResult {
        status: RollbackResultStatus::Succeeded,
        adapter: adapter.to_owned(),
        operation_reference,
        before,
        after: Some(after),
        verification_passed: true,
        error_code: None,
    }
}

fn next_attempt(
    executions: &BTreeMap<String, (String, ResponseExecutionRead, RollbackToken)>,
    action_id: &str,
) -> u64 {
    executions
        .values()
        .filter(|(stored_action, _, _)| stored_action == action_id)
        .count() as u64
        + 1
}

fn operation_ref(action_id: &str) -> String {
    format!("agent:{action_id}")
}

fn valid_idempotency_key(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn safe_nft_identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn bounded_text(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && !value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
}

fn command_failure(code: &str, output: &Output) -> RunnerError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    if detail.is_empty() {
        RunnerError::Adapter(code.to_owned())
    } else {
        RunnerError::Adapter(format!("{code}: {}", truncate(detail, 512)))
    }
}

fn truncate(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    &value[..end]
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use aisoc_contracts::{
        FileResponseTarget, ResponseActionKind, ResponseActionPlan, ResponseActionStatus,
        ResponseActionEvent, ResponseOperation, ResponsePolicyDecision, ResponseTier,
        RESPONSE_ACTION_SCHEMA_VERSION, RESPONSE_POLICY_VERSION,
    };

    use super::*;

    fn temp_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aisoc-response-runner-{}-{nonce}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn file_detail(path: &Path) -> ResponseActionDetail {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).expect("metadata");
        let (sha256, _) = sha256_file(path, 1024 * 1024).expect("hash");
        let action_id = format!("rsa_{}", "a".repeat(32));
        ResponseActionDetail {
            plan: ResponseActionPlan {
                schema_version: RESPONSE_ACTION_SCHEMA_VERSION.to_owned(),
                action_id: action_id.clone(),
                tenant_id: "ten_12345678".to_owned(),
                incident_id: "inc_12345678".to_owned(),
                incident_revision: 1,
                action: ResponseActionKind::IsolateFile,
                tier: ResponseTier::R2ReversibleContainment,
                status: ResponseActionStatus::Queued,
                target: ResponseTarget::File(FileResponseTarget {
                    target_type: "file".to_owned(),
                    host_id: "host_12345678".to_owned(),
                    expected_agent_id: "agent_12345678".to_owned(),
                    path: path.to_string_lossy().into_owned(),
                    sha256,
                    inode: metadata.ino(),
                    device: metadata.dev(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    mode: (metadata.mode() & 0o7777) as u16,
                }),
                target_identity_sha256: "b".repeat(64),
                evidence_ids: vec!["evi_1234567890abcdef12345678".to_owned()],
                reason: "quarantine verified sample".to_owned(),
                operation: ResponseOperation::FileQuarantine,
                adapter: "native_file".to_owned(),
                policy: ResponsePolicyDecision {
                    policy_version: RESPONSE_POLICY_VERSION.to_owned(),
                    allowed: true,
                    tier: ResponseTier::R2ReversibleContainment,
                    required_approvals: 0,
                    rollback_required: true,
                    rollback_supported: true,
                    target_revalidation_required: true,
                    execution_verification_required: true,
                    business_confirmation_required: false,
                    reasons: vec!["verified_file_identity".to_owned()],
                },
                requested_by: "operator:test".to_owned(),
                approval_count: 0,
                ttl_seconds: None,
                created_at: "2026-08-11T00:00:00Z".to_owned(),
                expires_at: None,
                queued_at: Some("2026-08-11T00:00:01Z".to_owned()),
                completed_at: None,
            },
            approvals: Vec::new(),
            executions: Vec::new(),
            rollbacks: Vec::new(),
            events: vec![ResponseActionEvent {
                sequence: 1,
                action_id,
                from_status: None,
                to_status: ResponseActionStatus::Queued,
                actor: "system".to_owned(),
                reason: "queued".to_owned(),
                created_at: "2026-08-11T00:00:01Z".to_owned(),
            }],
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_quarantine_has_verified_real_rollback_and_restart_idempotency() {
        let root = temp_root();
        fs::create_dir_all(&root).expect("root");
        let original = root.join("sample.bin");
        fs::write(&original, b"sample-payload").expect("sample");
        let detail = file_detail(&original);
        let journal = root.join("runner.jsonl");
        let config = ResponseRunnerConfig {
            enabled: true,
            quarantine_directory: root.join("quarantine"),
            ..ResponseRunnerConfig::default()
        };
        let identity = RunnerIdentity {
            host_id: "host_12345678".to_owned(),
            agent_id: "agent_12345678".to_owned(),
        };
        let execution_id;
        {
            let mut runner = ResponseRunner::open(&journal, identity.clone(), config.clone())
                .expect("open");
            let execution = runner
                .execute(&detail, "execute-file-0001")
                .expect("execute");
            execution_id = execution.execution_id.clone();
            assert!(!original.exists());
            let replay = runner
                .execute(&detail, "execute-file-0001")
                .expect("idempotent replay");
            assert_eq!(execution.execution_id, replay.execution_id);
        }
        let mut reopened = ResponseRunner::open(&journal, identity, config).expect("reopen");
        let rollback = reopened
            .rollback(
                &detail,
                &execution_id,
                "rollback-file-0001",
                "operator:test",
                "restore after containment window",
            )
            .expect("rollback");
        assert_eq!(rollback.status, RollbackResultStatus::Succeeded);
        assert_eq!(fs::read(&original).expect("restored"), b"sample-payload");
        fs::remove_dir_all(root).expect("cleanup");
    }
}
