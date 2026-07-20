use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
#[cfg(any(not(feature = "external-blob-store"), test))]
use mdbx_core::model::attachment::StorageMode;
use mdbx_core::model::{ChangeScope, Commit, CommitKind, EntryType};
use mdbx_core::tiga::{DeviceAssurance, DeviceContext, TigaMode};
use mdbx_storage::backup::BackupService;
#[cfg(feature = "benchmark")]
use mdbx_storage::benchmark::BenchmarkRunner;
#[cfg(feature = "external-blob-store")]
use mdbx_storage::blob_lifecycle::{BlobAuditOptions, BlobLifecycleLimits, BlobLifecycleService};
#[cfg(feature = "external-blob-store")]
use mdbx_storage::blob_store::FileSystemBlobStore;
use mdbx_storage::connection::{PendingVaultCreation, VaultConnection};
#[cfg(any(feature = "kdbx-import", feature = "kdbx-export"))]
use mdbx_storage::import::KdbxEntry;
#[cfg(feature = "kdbx-export")]
use mdbx_storage::import::KdbxExporter;
#[cfg(feature = "kdbx-import")]
use mdbx_storage::import::KdbxImporter;
use mdbx_storage::init::{initialize_vault, VaultInitParams};
use mdbx_storage::recovery::{IssueSeverity, RecoveryVerifier};
use mdbx_storage::repo::{
    AttachmentPlaintextPurpose, AttachmentRepo, AttachmentWriteOptions, EntryRepo,
    ObjectSummaryRepo, ProjectRepo, SnapshotRepo,
};
use mdbx_storage::repo::{CommitContext, CommitOperation, OperationExecution};
#[cfg(feature = "search")]
use mdbx_storage::search::SearchService;
use mdbx_storage::sync_apply::{ApplyBatchResult, SyncApplyRepo};
use mdbx_storage::sync_state::collect_sync_state_payload as collect_core_sync_state_payload;
use mdbx_storage::tiga_policy::TigaAuthorizationContext;
use mdbx_storage::unlock::UnlockService;
use mdbx_sync::{
    build_bundle, read_bundle_with_limits, write_bundle, BundleReadLimits, CommitBatch,
    CommitOperationMetadata, SerializedCommit, TombstoneRecord,
};
use rusqlite::{params, OptionalExtension};

fn prompt(prompt_text: &str) -> String {
    eprint!("{}", prompt_text);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn prompt_password(prompt_text: &str) -> String {
    rpassword::prompt_password(prompt_text).unwrap()
}

/// Monica DataBase eXchange — 离线优先密码管理器 CLI
#[derive(Parser)]
#[command(name = "mdbx", version, about)]
struct Cli {
    /// vault 文件路径（默认 ./vault.mdbx）
    #[arg(short, long, default_value = "vault.mdbx")]
    vault: PathBuf,

    /// 非交互解锁密码（用于脚本和自动化测试）
    #[arg(long, global = true)]
    unlock_password: Option<String>,

    /// 非交互解锁 PIN（用于脚本和自动化测试）
    #[arg(long, global = true)]
    unlock_pin: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 创建新 vault 并设置解锁凭据
    Init {
        /// Tiga 安全模式: power, multi (默认), sky
        #[arg(short, long, default_value = "multi")]
        tiga: String,
        /// 非交互设置密码
        #[arg(long)]
        password: Option<String>,
        /// 非交互设置 PIN
        #[arg(long)]
        pin: Option<String>,
    },
    /// 解锁 vault（输入凭据以启用加密）
    Unlock,
    /// 管理项目分组
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// 管理密码条目
    Entry {
        #[command(subcommand)]
        action: EntryAction,
    },
    /// 管理附件
    Attach {
        #[command(subcommand)]
        action: AttachAction,
    },
    /// 审计和维护外部加密 Blob Provider
    Blob {
        #[command(subcommand)]
        action: BlobAction,
    },
    /// 快照备份与恢复
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// 全文搜索
    #[cfg(feature = "search")]
    Search {
        /// 搜索关键词
        query: Option<String>,
        /// 按标签筛选
        #[arg(short, long)]
        tag: Option<String>,
        /// 按条目类型筛选
        #[arg(short, long)]
        entry_type: Option<String>,
    },
    /// 同步（预留）
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },
    /// 运行 vault 健康检查
    Health,
    /// 创建经过验证的单文件 vault 备份
    Backup {
        /// 输出 `.mdbx` 文件路径；已有文件不会被替换
        output: PathBuf,
    },
    /// 运行本地 benchmark harness
    #[cfg(feature = "benchmark")]
    Benchmark {
        /// 每个 benchmark 的迭代次数
        #[arg(short, long, default_value_t = 20)]
        iterations: u32,
    },
    /// 从 KDBX JSON 互操作文件导入
    #[cfg(feature = "kdbx-import")]
    ImportKdbxJson {
        /// 输入 JSON 文件，内容为 KdbxEntry 数组
        file: PathBuf,
    },
    /// 导出为 KDBX JSON 互操作文件
    #[cfg(feature = "kdbx-export")]
    ExportKdbxJson {
        /// 输出 JSON 文件
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// 列出所有项目
    List,
    /// 列出已软删除项目
    Deleted,
    /// 创建新项目
    Create {
        /// 项目标题
        title: String,
        /// 分组 ID（可选）
        #[arg(short, long)]
        group: Option<String>,
    },
    /// 查看项目详情
    Get { project_id: String },
    /// 编辑项目
    Edit {
        project_id: String,
        /// 新标题
        #[arg(short, long)]
        title: Option<String>,
        /// 切换收藏
        #[arg(short, long)]
        favorite: Option<bool>,
    },
    /// 删除项目（软删除）
    Delete { project_id: String },
}

#[derive(Subcommand)]
enum EntryAction {
    /// 列出项目中的所有条目
    List {
        project_id: String,
        /// 按类型筛选
        #[arg(short, long)]
        entry_type: Option<String>,
    },
    /// 创建新条目
    Create {
        project_id: String,
        /// 条目类型（login/note/card/identity/totp/passkey/ssh_key/api_token/document_ref）
        #[arg(short, long, default_value = "login")]
        entry_type: String,
        /// 条目标题
        #[arg(short, long)]
        title: Option<String>,
        /// 用户名
        #[arg(short, long)]
        username: Option<String>,
        /// 密码（不提供则交互输入）
        #[arg(short, long)]
        password: Option<String>,
        /// URL
        #[arg(short, long)]
        url: Option<String>,
        /// 备注
        #[arg(short, long)]
        notes: Option<String>,
    },
    /// 查看条目详情
    Get { entry_id: String },
    /// 编辑条目
    Edit {
        entry_id: String,
        /// 新标题
        #[arg(short, long)]
        title: Option<String>,
        /// 用户名
        #[arg(short, long)]
        username: Option<String>,
        /// 密码
        #[arg(short, long)]
        password: Option<String>,
        /// URL
        #[arg(short, long)]
        url: Option<String>,
        /// 备注
        #[arg(short, long)]
        notes: Option<String>,
    },
    /// 列出已软删除条目
    Deleted,
    /// 移动条目到另一个项目
    Move {
        entry_id: String,
        target_project_id: String,
    },
    /// 复制条目到另一个项目
    Copy {
        entry_id: String,
        target_project_id: String,
    },
    /// 删除条目（软删除）
    Delete { entry_id: String },
}

#[derive(Subcommand)]
enum AttachAction {
    /// 列出项目的附件
    List {
        /// 按项目 ID 列出
        #[arg(short, long)]
        project_id: Option<String>,
        /// 按条目 ID 列出
        #[arg(short, long)]
        entry_id: Option<String>,
    },
    /// 添加附件（从文件导入）
    Add {
        /// 所属项目 ID
        project_id: String,
        /// 所属条目 ID（可选）
        #[arg(short, long)]
        entry_id: Option<String>,
        /// 附件文件路径
        file: PathBuf,
        /// 将加密分块保存到 `<vault>.blobs` 内容寻址目录
        #[arg(long)]
        external: bool,
    },
    /// 导出附件内容
    Get {
        attachment_id: String,
        /// 输出文件路径（默认 stdout）
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// 查看附件元数据
    Info { attachment_id: String },
    /// 重命名附件元数据（不重写内容）
    Rename {
        attachment_id: String,
        file_name: String,
        /// 新 media type（可选）
        #[arg(short, long)]
        media_type: Option<String>,
    },
    /// 校验附件内容完整性
    Verify { attachment_id: String },
    /// 删除附件（软删除）
    Delete { attachment_id: String },
    /// 列出已软删除附件
    Deleted,
}

#[derive(Subcommand)]
enum BlobAction {
    /// 审计引用、缺失、损坏和未引用 Blob
    Audit {
        /// 未引用 Blob 的保护时长，单位小时
        #[arg(long, default_value_t = 168)]
        grace_hours: u64,
        /// 跳过密文内容读取，仅检查引用与 Provider 清单
        #[arg(long)]
        skip_content_verification: bool,
    },
    /// 生成垃圾回收计划凭证
    GcPlan {
        /// 未引用 Blob 的保护时长，单位小时
        #[arg(long, default_value_t = 168)]
        grace_hours: u64,
    },
    /// 使用计划凭证执行垃圾回收
    GcApply {
        plan_token: String,
        /// `gc-plan` 返回的固定清理时间边界
        #[arg(long)]
        cutoff_unix_secs: i64,
    },
}

#[derive(Subcommand)]
enum SnapshotAction {
    /// 创建快照
    Create,
    /// 列出所有快照
    List,
    /// 从快照恢复
    Restore { snapshot_id: String },
}

#[derive(Subcommand)]
enum SyncAction {
    /// 导出同步包
    Bundle {
        /// 输出文件路径
        #[arg(short, long, default_value = "sync-bundle.mdbx-sync")]
        output: PathBuf,
    },
    /// 导入同步包
    Apply {
        /// 输入文件路径
        file: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// MAIN
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let unlock = UnlockArgs {
        password: cli.unlock_password.as_deref(),
        pin: cli.unlock_pin.as_deref(),
    };

    match cli.command {
        Commands::Init {
            tiga,
            password,
            pin,
        } => cmd_init(&cli.vault, &tiga, password.as_deref(), pin.as_deref()),
        Commands::Unlock => cmd_unlock(&cli.vault, unlock),
        Commands::Project { action } => {
            let mut conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_project(&mut conn, action)
        }
        Commands::Entry { action } => {
            let mut conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_entry(&mut conn, action)
        }
        Commands::Attach { action } => {
            let mut conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_attach(&mut conn, &cli.vault, action)
        }
        Commands::Blob { action } => {
            let conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_blob(&conn, &cli.vault, action)
        }
        Commands::Snapshot { action } => {
            let mut conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_snapshot(&mut conn, action)
        }
        #[cfg(feature = "search")]
        Commands::Search {
            query,
            tag,
            entry_type,
        } => {
            let mut conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_search(&mut conn, query, tag, entry_type)
        }
        Commands::Sync { action } => {
            let mut conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_sync(&mut conn, action)
        }
        Commands::Health => {
            let conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_health(&conn)
        }
        Commands::Backup { output } => cmd_backup(&cli.vault, output),
        #[cfg(feature = "benchmark")]
        Commands::Benchmark { iterations } => cmd_benchmark(iterations),
        #[cfg(feature = "kdbx-import")]
        Commands::ImportKdbxJson { file } => {
            let mut conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_import_kdbx_json(&mut conn, file)
        }
        #[cfg(feature = "kdbx-export")]
        Commands::ExportKdbxJson { output } => {
            let conn = open_or_create_vault(&cli.vault, unlock)?;
            cmd_export_kdbx_json(&conn, output)
        }
    }
}

#[derive(Clone, Copy)]
struct UnlockArgs<'a> {
    password: Option<&'a str>,
    pin: Option<&'a str>,
}

fn open_or_create_vault(
    path: &std::path::Path,
    unlock: UnlockArgs<'_>,
) -> Result<VaultConnection, String> {
    if path.exists() {
        let mut conn =
            VaultConnection::open(path).map_err(|e| format!("failed to open vault: {}", e))?;
        apply_unlock_args(&mut conn, unlock)?;
        require_unlock_if_configured(&conn)?;
        Ok(conn)
    } else {
        Err(format!(
            "vault not found at '{}'. Run 'mdbx init' to create one.",
            path.display()
        ))
    }
}

fn ctx() -> CommitContext {
    CommitContext::new("cli-device".to_string())
}

const ATTACHMENT_STREAM_CHUNK_SIZE: usize = 1024 * 1024;

fn export_attachment_to_path(
    conn: &mut VaultConnection,
    attachment_id: &str,
    vault_path: &Path,
    output: &Path,
) -> Result<u64, String> {
    let device = cli_device_context();
    AttachmentRepo::authorize_plaintext_access_with_active_session(
        conn,
        attachment_id,
        AttachmentPlaintextPurpose::Export,
        &device,
        chrono::Utc::now().timestamp(),
    )
    .map_err(|error| error.to_string())?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".mdbx-attachment-")
        .tempfile_in(parent)
        .map_err(|error| format!("cannot create temporary output file: {error}"))?;
    let written =
        read_attachment_to_writer(conn, attachment_id, vault_path, temporary.as_file_mut())?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("cannot synchronize temporary output file: {error}"))?;
    temporary
        .persist(output)
        .map_err(|error| format!("cannot replace output file: {}", error.error))?;
    Ok(written)
}

fn default_blob_store_path(vault_path: &Path) -> PathBuf {
    let mut path = vault_path.as_os_str().to_os_string();
    path.push(".blobs");
    PathBuf::from(path)
}

fn read_attachment_to_writer(
    conn: &VaultConnection,
    attachment_id: &str,
    _vault_path: &Path,
    writer: &mut dyn std::io::Write,
) -> Result<u64, String> {
    #[cfg(feature = "external-blob-store")]
    {
        let store = FileSystemBlobStore::new(default_blob_store_path(_vault_path));
        AttachmentRepo::read_content_to_writer_with_blob_store(conn, attachment_id, &store, writer)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "external-blob-store"))]
    {
        let attachment = AttachmentRepo::get_by_id(conn, attachment_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("attachment {attachment_id} not found"))?;
        if attachment.storage_mode == StorageMode::ExternalHashRef {
            return Err(
                "this MDBX build does not include the filesystem encrypted Blob Provider"
                    .to_string(),
            );
        }
        AttachmentRepo::read_content_to_writer(conn, attachment_id, writer)
            .map_err(|error| error.to_string())
    }
}

fn read_attachment_content(
    conn: &VaultConnection,
    attachment_id: &str,
    _vault_path: &Path,
) -> Result<Vec<u8>, String> {
    #[cfg(feature = "external-blob-store")]
    {
        let store = FileSystemBlobStore::new(default_blob_store_path(_vault_path));
        AttachmentRepo::read_content_with_blob_store(conn, attachment_id, &store)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "external-blob-store"))]
    {
        let attachment = AttachmentRepo::get_by_id(conn, attachment_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("attachment {attachment_id} not found"))?;
        if attachment.storage_mode == StorageMode::ExternalHashRef {
            return Err(
                "this MDBX build does not include the filesystem encrypted Blob Provider"
                    .to_string(),
            );
        }
        AttachmentRepo::read_content(conn, attachment_id).map_err(|error| error.to_string())
    }
}

fn verify_attachment_content(
    conn: &VaultConnection,
    attachment_id: &str,
    _vault_path: &Path,
) -> Result<bool, String> {
    #[cfg(feature = "external-blob-store")]
    {
        let store = FileSystemBlobStore::new(default_blob_store_path(_vault_path));
        AttachmentRepo::verify_integrity_with_blob_store(conn, attachment_id, &store)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "external-blob-store"))]
    {
        let attachment = AttachmentRepo::get_by_id(conn, attachment_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("attachment {attachment_id} not found"))?;
        if attachment.storage_mode == StorageMode::ExternalHashRef {
            return Err(
                "this MDBX build does not include the filesystem encrypted Blob Provider"
                    .to_string(),
            );
        }
        AttachmentRepo::verify_integrity(conn, attachment_id).map_err(|error| error.to_string())
    }
}

fn cli_device_context() -> DeviceContext {
    DeviceContext {
        device_id: Some("cli-device".to_string()),
        assurance: DeviceAssurance::Standard,
        secure_clipboard_available: false,
        screen_capture_protection_available: false,
        secure_temp_files_available: true,
    }
}

fn apply_unlock_args(conn: &mut VaultConnection, unlock: UnlockArgs<'_>) -> Result<(), String> {
    match (unlock.password, unlock.pin) {
        (Some(_), Some(_)) => Err("use only one of --unlock-password or --unlock-pin".to_string()),
        (Some(password), None) => {
            UnlockService::unlock_with_password(conn, password)
                .map_err(|e| format!("unlock failed: {}", e))?;
            Ok(())
        }
        (None, Some(pin)) => {
            UnlockService::unlock_with_pin(conn, pin)
                .map_err(|e| format!("unlock failed: {}", e))?;
            Ok(())
        }
        (None, None) => Ok(()),
    }
}

fn require_unlock_if_configured(conn: &VaultConnection) -> Result<(), String> {
    let methods = UnlockService::list_methods(conn)
        .map_err(|e| format!("failed to inspect unlock methods: {}", e))?;
    if !methods.is_empty() && !conn.is_encrypted() {
        return Err(
            "vault has unlock methods configured; pass --unlock-password or --unlock-pin"
                .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// INIT
// ---------------------------------------------------------------------------

fn cmd_init(
    path: &std::path::Path,
    tiga: &str,
    password: Option<&str>,
    pin: Option<&str>,
) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "vault already exists at '{}'. Delete it first if you want to start fresh.",
            path.display()
        ));
    }
    if password.is_some() && pin.is_some() {
        return Err("use only one of --password or --pin".to_string());
    }

    let tiga_mode: TigaMode = tiga
        .parse()
        .map_err(|e: String| format!("invalid tiga mode: {}", e))?;
    println!(
        "Creating new vault at '{}' (Tiga: {})",
        path.display(),
        tiga_mode
    );

    let mut creation =
        PendingVaultCreation::begin(path).map_err(|e| format!("failed to create vault: {}", e))?;

    let device_id = format!(
        "cli-{}",
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let params = VaultInitParams {
        default_tiga_mode: tiga_mode.to_string(),
        device_id,
        ..VaultInitParams::default()
    };
    initialize_vault(creation.connection(), &params).map_err(|e| format!("init failed: {}", e))?;

    if let Some(pw) = password {
        UnlockService::setup_password_with_mode(creation.connection_mut(), pw, tiga_mode)
            .map_err(|e| format!("setup failed: {}", e))?;
        drop(creation.commit());
        println!("Vault initialized successfully at '{}'", path.display());
        return Ok(());
    }

    if let Some(pin) = pin {
        UnlockService::setup_pin(creation.connection_mut(), pin)
            .map_err(|e| format!("setup failed: {}", e))?;
        drop(creation.commit());
        println!("Vault initialized successfully at '{}'", path.display());
        return Ok(());
    }

    // 设置解锁凭据
    println!("Choose unlock method:");
    println!("  1. Password");
    println!("  2. PIN (4+ digits)");
    let choice = prompt("Choice [1]: ");
    let choice = if choice.is_empty() { "1" } else { &choice };

    match choice {
        "1" => {
            let pw = prompt_password("Enter password: ");
            let confirm = prompt_password("Confirm password: ");
            if pw != confirm {
                return Err("passwords do not match".to_string());
            }
            UnlockService::setup_password_with_mode(creation.connection_mut(), &pw, tiga_mode)
                .map_err(|e| format!("setup failed: {}", e))?;
        }
        "2" => {
            let pin = prompt_password("Enter PIN (4+ digits): ");
            let confirm = prompt_password("Confirm PIN: ");
            if pin != confirm {
                return Err("PINs do not match".to_string());
            }
            UnlockService::setup_pin(creation.connection_mut(), &pin)
                .map_err(|e| format!("setup failed: {}", e))?;
        }
        _ => return Err("invalid choice".to_string()),
    }

    drop(creation.commit());
    println!("Vault initialized successfully at '{}'", path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// UNLOCK
// ---------------------------------------------------------------------------

fn cmd_unlock(path: &std::path::Path, unlock: UnlockArgs<'_>) -> Result<(), String> {
    let mut conn =
        VaultConnection::open(path).map_err(|e| format!("failed to open vault: {}", e))?;

    if unlock.password.is_some() || unlock.pin.is_some() {
        apply_unlock_args(&mut conn, unlock)?;
        println!("Vault unlocked successfully.");
        return Ok(());
    }

    let methods =
        UnlockService::list_methods(&conn).map_err(|e| format!("failed to list methods: {}", e))?;
    if methods.is_empty() {
        return Err("no unlock methods configured. Run 'mdbx init' first.".to_string());
    }

    println!("Available unlock methods:");
    for (i, m) in methods.iter().enumerate() {
        println!("  {}. {:?}", i + 1, m.method_type);
    }

    let choice = prompt(&format!("Choose method [1-{}]: ", methods.len()));
    let idx: usize = choice
        .parse::<usize>()
        .map_err(|_| "invalid choice".to_string())?
        .checked_sub(1)
        .ok_or("invalid choice")?;

    if idx >= methods.len() {
        return Err("invalid choice".to_string());
    }

    match methods[idx].method_type {
        mdbx_core::model::UnlockMethodType::Password => {
            let pw = prompt_password("Password: ");
            UnlockService::unlock_with_password(&mut conn, &pw)
                .map_err(|e| format!("unlock failed: {}", e))?;
        }
        mdbx_core::model::UnlockMethodType::Pin => {
            let pin = prompt_password("PIN: ");
            UnlockService::unlock_with_pin(&mut conn, &pin)
                .map_err(|e| format!("unlock failed: {}", e))?;
        }
        mdbx_core::model::UnlockMethodType::SecurityKey => {
            return Err("security key unlock not yet supported in CLI".to_string());
        }
        mdbx_core::model::UnlockMethodType::PasswordSecurityKey => {
            return Err("password + security key unlock not yet supported in CLI".to_string());
        }
    }

    println!("Vault unlocked successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// PROJECT
// ---------------------------------------------------------------------------

fn cmd_project(conn: &mut VaultConnection, action: ProjectAction) -> Result<(), String> {
    let ctx = ctx();
    match action {
        ProjectAction::List => {
            let projects = ProjectRepo::list_all(conn).map_err(|e| format!("{}", e))?;
            if projects.is_empty() {
                println!("(no projects)");
            }
            for p in &projects {
                let title = String::from_utf8_lossy(&p.title_ct);
                let fav = if p.favorite { " ★" } else { "" };
                println!("{}  {}{}", p.project_id, title, fav);
            }
        }
        ProjectAction::Deleted => {
            let projects = ProjectRepo::list_deleted(conn).map_err(|e| format!("{}", e))?;
            if projects.is_empty() {
                println!("(no deleted projects)");
            }
            for p in &projects {
                let title = String::from_utf8_lossy(&p.title_ct);
                println!("{}  {}", p.project_id, title);
            }
        }
        ProjectAction::Create { title, group } => {
            let p = ProjectRepo::create(conn, &ctx, &title, group.as_deref(), None)
                .map_err(|e| format!("{}", e))?;
            println!("Created project {}", p.project_id);
        }
        ProjectAction::Get { project_id } => {
            let p = ProjectRepo::get_by_id(conn, &project_id)
                .map_err(|e| format!("{}", e))?
                .ok_or("project not found")?;
            let title = String::from_utf8_lossy(&p.title_ct);
            println!("ID:        {}", p.project_id);
            println!("Title:     {}", title);
            println!("Group:     {}", p.group_id.as_deref().unwrap_or("-"));
            println!("Favorite:  {}", p.favorite);
            println!("Archived:  {}", p.archived);
            println!("Attach:    {}", p.attachment_count);
            println!("Updated:   {}", p.updated_at);
        }
        ProjectAction::Edit {
            project_id,
            title,
            favorite,
        } => {
            let mut p = ProjectRepo::get_by_id(conn, &project_id)
                .map_err(|e| format!("{}", e))?
                .ok_or("project not found")?;
            if let Some(t) = title {
                p.title_ct = t.into_bytes();
            }
            if let Some(f) = favorite {
                p.favorite = f;
            }
            ProjectRepo::update(conn, &ctx, &p).map_err(|e| format!("{}", e))?;
            println!("Updated project {}", project_id);
        }
        ProjectAction::Delete { project_id } => {
            ProjectRepo::soft_delete(conn, &ctx, &project_id).map_err(|e| format!("{}", e))?;
            println!("Deleted project {}", project_id);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ENTRY
// ---------------------------------------------------------------------------

fn cmd_entry(conn: &mut VaultConnection, action: EntryAction) -> Result<(), String> {
    let ctx = ctx();
    match action {
        EntryAction::List {
            project_id,
            entry_type,
        } => {
            let entry_type = entry_type
                .map(|value| {
                    value
                        .parse::<EntryType>()
                        .map_err(|_| format!("unknown entry type: {value}"))
                })
                .transpose()?;
            let mut cursor = None;
            let mut found = false;
            loop {
                let page = ObjectSummaryRepo::list(
                    conn,
                    &project_id,
                    entry_type.as_ref(),
                    100,
                    cursor.as_deref(),
                )
                .map_err(|error| error.to_string())?;
                for object in page.items {
                    found = true;
                    let title = object
                        .title
                        .as_ref()
                        .map(|title| String::from_utf8_lossy(title).to_string())
                        .unwrap_or_else(|| "(untitled)".to_string());
                    println!(
                        "{}  {:?}  {}",
                        object.object_id, object.object_type_id, title
                    );
                }
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            if !found {
                println!("(no entries)");
            }
        }
        EntryAction::Create {
            project_id,
            entry_type,
            title,
            username,
            password,
            url,
            notes,
        } => {
            let et: EntryType = entry_type
                .parse()
                .map_err(|_| format!("unknown entry type: {}", entry_type))?;
            let mut payload = serde_json::Map::new();
            if let Some(u) = username {
                payload.insert("username".into(), u.into());
            }
            if let Some(p) = password {
                payload.insert("password".into(), p.into());
            }
            if let Some(u) = url {
                payload.insert("url".into(), u.into());
            }
            if let Some(n) = notes {
                payload.insert("notes".into(), n.into());
            }
            let payload = serde_json::Value::Object(payload);

            let e = EntryRepo::create(conn, &ctx, &project_id, et, title.as_deref(), &payload)
                .map_err(|e| format!("{}", e))?;
            println!("Created entry {}", e.entry_id);
        }
        EntryAction::Get { entry_id } => {
            let e = EntryRepo::get_by_id(conn, &entry_id)
                .map_err(|e| format!("{}", e))?
                .ok_or("entry not found")?;
            let title = e
                .title_ct
                .as_ref()
                .map(|t| String::from_utf8_lossy(t).to_string())
                .unwrap_or_else(|| "(untitled)".to_string());
            println!("ID:         {}", e.entry_id);
            println!("Project:    {}", e.project_id);
            println!("Type:       {:?}", e.entry_type);
            println!("Title:      {}", title);
            println!("Deleted:    {}", e.deleted);
            println!("Updated:    {}", e.updated_at);

            let payload: serde_json::Value =
                serde_json::from_slice(&e.payload_ct).unwrap_or(serde_json::Value::Null);
            if let Some(obj) = payload.as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        println!("  {}: {}", k, s);
                    } else {
                        println!("  {}: {}", k, v);
                    }
                }
            }
        }
        EntryAction::Edit {
            entry_id,
            title,
            username,
            password,
            url,
            notes,
        } => {
            let mut e = EntryRepo::get_by_id(conn, &entry_id)
                .map_err(|e| format!("{}", e))?
                .ok_or("entry not found")?;
            if let Some(t) = title {
                e.title_ct = Some(t.into_bytes());
            }

            let mut payload: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&e.payload_ct).unwrap_or_default();
            if let Some(u) = username {
                payload.insert("username".into(), u.into());
            }
            if let Some(p) = password {
                payload.insert("password".into(), p.into());
            }
            if let Some(u) = url {
                payload.insert("url".into(), u.into());
            }
            if let Some(n) = notes {
                payload.insert("notes".into(), n.into());
            }
            e.payload_ct = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;

            EntryRepo::update(conn, &ctx, &e).map_err(|e| format!("{}", e))?;
            println!("Updated entry {}", entry_id);
        }
        EntryAction::Deleted => {
            let entries = EntryRepo::list_deleted(conn).map_err(|e| format!("{}", e))?;
            if entries.is_empty() {
                println!("(no deleted entries)");
            }
            for e in &entries {
                let title = e
                    .title_ct
                    .as_ref()
                    .map(|t| String::from_utf8_lossy(t).to_string())
                    .unwrap_or_else(|| "(untitled)".to_string());
                println!("{}  {:?}  {}", e.entry_id, e.entry_type, title);
            }
        }
        EntryAction::Move {
            entry_id,
            target_project_id,
        } => {
            let moved = EntryRepo::move_to_project(conn, &ctx, &entry_id, &target_project_id)
                .map_err(|e| format!("{}", e))?;
            println!("Moved entry {} to {}", moved.entry_id, moved.project_id);
        }
        EntryAction::Copy {
            entry_id,
            target_project_id,
        } => {
            let copied = EntryRepo::copy_to_project(conn, &ctx, &entry_id, &target_project_id)
                .map_err(|e| format!("{}", e))?;
            println!("Copied entry {} to {}", copied.entry_id, copied.project_id);
        }
        EntryAction::Delete { entry_id } => {
            EntryRepo::soft_delete(conn, &ctx, &entry_id).map_err(|e| format!("{}", e))?;
            println!("Deleted entry {}", entry_id);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ATTACH
// ---------------------------------------------------------------------------

fn cmd_attach(
    conn: &mut VaultConnection,
    vault_path: &Path,
    action: AttachAction,
) -> Result<(), String> {
    let ctx = ctx();
    match action {
        AttachAction::List {
            project_id,
            entry_id,
        } => {
            let attachments = if let Some(eid) = entry_id {
                AttachmentRepo::list_by_entry(conn, &eid).map_err(|e| format!("{}", e))?
            } else if let Some(pid) = project_id {
                AttachmentRepo::list_by_project(conn, &pid).map_err(|e| format!("{}", e))?
            } else {
                return Err("specify --project-id or --entry-id".to_string());
            };
            if attachments.is_empty() {
                println!("(no attachments)");
            }
            for a in &attachments {
                let name = String::from_utf8_lossy(&a.file_name_ct);
                println!(
                    "{}  {}  {} bytes  {}",
                    a.attachment_id, name, a.original_size, a.content_hash
                );
            }
        }
        AttachAction::Add {
            project_id,
            entry_id,
            file,
            external,
        } => {
            #[cfg(not(feature = "external-blob-store"))]
            if external {
                return Err(
                    "this MDBX build does not include the filesystem encrypted Blob Provider"
                        .to_string(),
                );
            }
            let mut input =
                std::fs::File::open(&file).map_err(|e| format!("cannot open file: {}", e))?;
            let original_size = input
                .metadata()
                .map_err(|e| format!("cannot read file metadata: {}", e))?
                .len();
            let file_name = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unnamed")
                .to_string();
            let media_type = mime_guess_for_path(&file);

            let operation = CommitOperation::new(
                uuid::Uuid::new_v4().to_string(),
                "attachment-add",
                "main",
                "change",
                "attachment",
                Vec::new(),
            );
            let result = ctx
                .run_operation(conn, operation, |scoped| {
                    let att = AttachmentRepo::add(
                        conn,
                        scoped,
                        &project_id,
                        entry_id.as_deref(),
                        &file_name,
                        media_type.as_deref(),
                        "",
                        original_size,
                    )?;
                    #[cfg(feature = "external-blob-store")]
                    if external {
                        let store = FileSystemBlobStore::new(default_blob_store_path(vault_path));
                        AttachmentRepo::write_external_content_from_reader_with_options(
                            conn,
                            scoped,
                            &att.attachment_id,
                            &mut input,
                            AttachmentWriteOptions::exact(
                                ATTACHMENT_STREAM_CHUNK_SIZE,
                                original_size,
                            ),
                            &store,
                        )?;
                    } else {
                        AttachmentRepo::write_content_from_reader_with_options(
                            conn,
                            scoped,
                            &att.attachment_id,
                            &mut input,
                            AttachmentWriteOptions::exact(
                                ATTACHMENT_STREAM_CHUNK_SIZE,
                                original_size,
                            ),
                        )?;
                    }
                    #[cfg(not(feature = "external-blob-store"))]
                    AttachmentRepo::write_content_from_reader_with_options(
                        conn,
                        scoped,
                        &att.attachment_id,
                        &mut input,
                        AttachmentWriteOptions::exact(ATTACHMENT_STREAM_CHUNK_SIZE, original_size),
                    )?;
                    Ok(att)
                })
                .map_err(|e| format!("{}", e))?;
            let att = match result {
                OperationExecution::Applied { value, .. } => value,
                OperationExecution::AlreadyCommitted { commit_id } => {
                    return Err(format!(
                        "attachment add operation was already committed as {}",
                        commit_id
                    ));
                }
            };

            println!(
                "Added attachment {} ({} bytes)",
                att.attachment_id, original_size
            );
            if external {
                println!(
                    "Encrypted blobs: {}",
                    default_blob_store_path(vault_path).display()
                );
            }
        }
        AttachAction::Get {
            attachment_id,
            output,
        } => {
            if let Some(path) = output {
                let written = export_attachment_to_path(conn, &attachment_id, vault_path, &path)?;
                println!("Wrote {} bytes to {}", written, path.display());
            } else {
                let device = cli_device_context();
                AttachmentRepo::authorize_plaintext_access_with_active_session(
                    conn,
                    &attachment_id,
                    AttachmentPlaintextPurpose::InMemory,
                    &device,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|error| error.to_string())?;
                let data = read_attachment_content(conn, &attachment_id, vault_path)?;
                // stdout — only if looks like text
                match std::str::from_utf8(&data) {
                    Ok(s) => println!("{}", s),
                    Err(_) => println!("{:?}", &data[..data.len().min(256)]),
                }
            }
        }
        AttachAction::Info { attachment_id } => {
            let att = AttachmentRepo::get_by_id(conn, &attachment_id)
                .map_err(|e| format!("{}", e))?
                .ok_or("attachment not found")?;
            let name = String::from_utf8_lossy(&att.file_name_ct);
            let media_type = att
                .media_type_ct
                .as_ref()
                .map(|m| String::from_utf8_lossy(m).to_string())
                .unwrap_or_else(|| "-".to_string());
            println!("ID:        {}", att.attachment_id);
            println!("Project:   {}", att.project_id);
            println!("Entry:     {}", att.entry_id.as_deref().unwrap_or("-"));
            println!("Name:      {}", name);
            println!("Media:     {}", media_type);
            println!("Mode:      {}", att.storage_mode);
            println!("Size:      {}", att.original_size);
            println!("Stored:    {}", att.stored_size);
            println!("Chunks:    {}", att.chunk_count);
            println!("Hash:      {}", att.content_hash);
            println!("Deleted:   {}", att.deleted);
            println!("Updated:   {}", att.updated_at);
        }
        AttachAction::Rename {
            attachment_id,
            file_name,
            media_type,
        } => {
            let renamed = AttachmentRepo::rename(
                conn,
                &ctx,
                &attachment_id,
                &file_name,
                media_type.as_deref(),
            )
            .map_err(|e| format!("{}", e))?;
            println!("Renamed attachment {}", renamed.attachment_id);
        }
        AttachAction::Verify { attachment_id } => {
            let ok = verify_attachment_content(conn, &attachment_id, vault_path)?;
            if ok {
                println!("Attachment {} integrity OK", attachment_id);
            } else {
                return Err(format!(
                    "attachment {} integrity check failed",
                    attachment_id
                ));
            }
        }
        AttachAction::Delete { attachment_id } => {
            AttachmentRepo::soft_delete(conn, &ctx, &attachment_id)
                .map_err(|e| format!("{}", e))?;
            println!("Deleted attachment {}", attachment_id);
        }
        AttachAction::Deleted => {
            let attachments = AttachmentRepo::list_deleted(conn).map_err(|e| format!("{}", e))?;
            if attachments.is_empty() {
                println!("(no deleted attachments)");
            }
            for a in &attachments {
                let name = String::from_utf8_lossy(&a.file_name_ct);
                println!(
                    "{}  {}  {} bytes  {}",
                    a.attachment_id, name, a.original_size, a.content_hash
                );
            }
        }
    }
    Ok(())
}

#[cfg(feature = "external-blob-store")]
fn blob_cutoff_unix_secs(grace_hours: u64) -> Result<i64, String> {
    let grace_seconds = grace_hours
        .checked_mul(60 * 60)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| "Blob grace period exceeds supported time range".to_string())?;
    chrono::Utc::now()
        .timestamp()
        .checked_sub(grace_seconds)
        .ok_or_else(|| "Blob grace period underflowed the supported time range".to_string())
}

fn cmd_blob(_conn: &VaultConnection, _vault_path: &Path, action: BlobAction) -> Result<(), String> {
    #[cfg(not(feature = "external-blob-store"))]
    {
        let _ = action;
        Err("this MDBX build does not include filesystem Blob lifecycle management".to_string())
    }
    #[cfg(feature = "external-blob-store")]
    {
        let store = FileSystemBlobStore::new(default_blob_store_path(_vault_path));
        match action {
            BlobAction::Audit {
                grace_hours,
                skip_content_verification,
            } => {
                let cutoff = blob_cutoff_unix_secs(grace_hours)?;
                let report = BlobLifecycleService::audit(
                    _conn,
                    &store,
                    BlobAuditOptions {
                        limits: BlobLifecycleLimits::default(),
                        orphan_cutoff_unix_secs: cutoff,
                        verify_provider_contents: !skip_content_verification,
                    },
                )
                .map_err(|error| error.to_string())?;
                println!("Provider:            {}", report.namespace_id);
                println!("References:          {}", report.raw_reference_count);
                println!("Unique references:   {}", report.unique_reference_count);
                println!("Provider blobs:       {}", report.provider_blob_count);
                println!("Healthy references:  {}", report.healthy_reference_count);
                println!("Missing references:  {}", report.missing_references.len());
                println!("Corrupt blobs:       {}", report.corrupt_blobs.len());
                println!("Eligible orphans:    {}", report.eligible_orphans.len());
                println!("Recent orphans:      {}", report.recent_orphan_count);
                for issue in &report.missing_references {
                    println!("MISSING {}  {}", issue.blob_id, issue.detail);
                }
                for issue in &report.corrupt_blobs {
                    println!("CORRUPT {}  {}", issue.blob_id, issue.detail);
                }
                for blob in &report.eligible_orphans {
                    println!("ORPHAN {}  {} bytes", blob.blob_id, blob.stored_size);
                }
            }
            BlobAction::GcPlan { grace_hours } => {
                let cutoff = blob_cutoff_unix_secs(grace_hours)?;
                let plan = BlobLifecycleService::plan_gc(
                    _conn,
                    &store,
                    cutoff,
                    BlobLifecycleLimits::default(),
                )
                .map_err(|error| error.to_string())?;
                println!("Plan token:       {}", plan.plan_token);
                println!("Cutoff Unix secs: {}", plan.orphan_cutoff_unix_secs);
                println!("Eligible orphans: {}", plan.eligible_orphans.len());
                println!("Recent orphans:   {}", plan.recent_orphan_count);
                println!(
                    "Apply with: mdbx --vault {} blob gc-apply {} --cutoff-unix-secs {}",
                    _vault_path.display(),
                    plan.plan_token,
                    plan.orphan_cutoff_unix_secs
                );
            }
            BlobAction::GcApply {
                plan_token,
                cutoff_unix_secs,
            } => {
                let session = _conn.active_session().ok_or_else(|| {
                    "Blob garbage collection requires an active unlock session".to_string()
                })?;
                let device = cli_device_context();
                let (result, _decision) = BlobLifecycleService::apply_gc_authorized(
                    _conn,
                    &store,
                    &plan_token,
                    cutoff_unix_secs,
                    BlobLifecycleLimits::default(),
                    TigaAuthorizationContext {
                        session: Some(session),
                        device: &device,
                        now_unix_secs: chrono::Utc::now().timestamp(),
                    },
                )
                .map_err(|error| error.to_string())?;
                println!("Planned:        {}", result.planned_count);
                println!("Deleted:        {}", result.deleted_blob_ids.len());
                println!("Already absent: {}", result.already_absent_blob_ids.len());
                println!("Failures:       {}", result.failures.len());
                for failure in &result.failures {
                    println!("FAILED {}  {}", failure.blob_id, failure.detail);
                }
                if !result.completed() {
                    return Err(
                        "Blob garbage collection completed with failures; create a new plan before retrying"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

fn mime_guess_for_path(path: &std::path::Path) -> Option<String> {
    let ext = path.extension()?.to_str()?;
    let mime = match ext {
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "bin" => "application/octet-stream",
        _ => "application/octet-stream",
    };
    Some(mime.to_string())
}

// ---------------------------------------------------------------------------
// SNAPSHOT
// ---------------------------------------------------------------------------

fn cmd_snapshot(conn: &mut VaultConnection, action: SnapshotAction) -> Result<(), String> {
    let ctx = ctx();
    match action {
        SnapshotAction::Create => {
            let snap = SnapshotRepo::create_snapshot(conn, &ctx).map_err(|e| format!("{}", e))?;
            println!("Created snapshot {}", snap.snapshot_id);
            println!("  hash: {}", snap.snapshot_hash);
            println!("  time: {}", snap.created_at);
        }
        SnapshotAction::List => {
            let snaps = SnapshotRepo::list_all(conn).map_err(|e| format!("{}", e))?;
            if snaps.is_empty() {
                println!("(no snapshots)");
            }
            for s in &snaps {
                println!("{}  {}  {}", s.snapshot_id, s.created_at, s.snapshot_hash);
            }
        }
        SnapshotAction::Restore { snapshot_id } => {
            let device = cli_device_context();
            let session = conn
                .active_session()
                .ok_or_else(|| "snapshot restore requires an active unlock session".to_string())?;
            SnapshotRepo::restore_snapshot_authorized(
                conn,
                &ctx,
                &snapshot_id,
                TigaAuthorizationContext {
                    session: Some(session),
                    device: &device,
                    now_unix_secs: chrono::Utc::now().timestamp(),
                },
            )
            .map_err(|e| format!("{}", e))?;
            println!("Restored from snapshot {}", snapshot_id);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SEARCH
// ---------------------------------------------------------------------------

#[cfg(feature = "search")]
fn cmd_search(
    conn: &mut VaultConnection,
    query: Option<String>,
    tag: Option<String>,
    entry_type: Option<String>,
) -> Result<(), String> {
    let et = entry_type
        .as_deref()
        .map(|s| s.parse::<EntryType>())
        .transpose()
        .map_err(|_| "unknown entry type".to_string())?;

    let results = SearchService::search(conn, query.as_deref(), tag.as_deref(), et, None, None)
        .map_err(|e| format!("{}", e))?;

    if results.is_empty() {
        println!("(no results)");
    }
    for r in &results {
        let types = r.entry_types.join(",");
        let tags = if r.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", r.tags.join(", "))
        };
        println!("{}  {}  {}{}", r.project_id, r.title, types, tags);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SYNC
// ---------------------------------------------------------------------------

fn cmd_sync(conn: &mut VaultConnection, action: SyncAction) -> Result<(), String> {
    match action {
        SyncAction::Bundle { output } => {
            let bundle = export_sync_bundle(conn)?;
            let mut file = std::fs::File::create(&output)
                .map_err(|e| format!("failed to create bundle '{}': {}", output.display(), e))?;
            write_bundle(&bundle, &mut file).map_err(|e| format!("bundle write failed: {}", e))?;
            println!(
                "Exported {} commits to {}",
                bundle.commits.len(),
                output.display()
            );
            Ok(())
        }
        SyncAction::Apply { file } => {
            let mut input = std::fs::File::open(&file)
                .map_err(|e| format!("failed to open bundle '{}': {}", file.display(), e))?;
            let bundle = read_bundle_with_limits(&mut input, BundleReadLimits::desktop())
                .map_err(|e| format!("bundle read failed: {}", e))?;
            let summary = apply_sync_bundle(conn, &bundle)?;
            println!(
                "Applied bundle: applied={} skipped={} conflicts={} missing-parents={}",
                summary.applied_commits,
                summary.skipped_commits,
                summary.conflict_count,
                summary.missing_parent_count
            );
            Ok(())
        }
    }
}

fn cmd_health(conn: &VaultConnection) -> Result<(), String> {
    let result = RecoveryVerifier::full_health_check(conn)
        .map_err(|e| format!("health check failed: {}", e))?;

    if result.issues.is_empty() {
        println!("Vault health: OK");
        return Ok(());
    }

    println!("Vault health: {} issue(s)", result.issues.len());
    for issue in &result.issues {
        println!(
            "  [{}] {}: {}",
            severity_label(issue.severity),
            issue.category,
            issue.description
        );
    }

    if result.issues.iter().any(|issue| {
        matches!(
            issue.severity,
            IssueSeverity::Error | IssueSeverity::Critical
        )
    }) {
        Err("vault health check reported errors".to_string())
    } else {
        Ok(())
    }
}

fn cmd_backup(source: &std::path::Path, output: PathBuf) -> Result<(), String> {
    let info = BackupService::create_portable_copy_path(source, &output)
        .map_err(|error| format!("failed to create portable backup: {error}"))?;
    println!(
        "Created portable backup: vault={} format={} schema={} bytes={} -> {}",
        info.vault_id,
        info.format_version,
        info.schema_version,
        info.file_size_bytes,
        output.display()
    );
    Ok(())
}

fn severity_label(severity: IssueSeverity) -> &'static str {
    match severity {
        IssueSeverity::Info => "info",
        IssueSeverity::Warning => "warning",
        IssueSeverity::Error => "error",
        IssueSeverity::Critical => "critical",
    }
}

#[cfg(feature = "benchmark")]
fn cmd_benchmark(iterations: u32) -> Result<(), String> {
    if iterations == 0 {
        return Err("iterations must be greater than zero".to_string());
    }
    let suite = BenchmarkRunner::run_full_suite(iterations);
    suite.print();
    Ok(())
}

#[cfg(feature = "kdbx-import")]
fn cmd_import_kdbx_json(conn: &mut VaultConnection, file: PathBuf) -> Result<(), String> {
    let bytes =
        std::fs::read(&file).map_err(|e| format!("failed to read '{}': {}", file.display(), e))?;
    let entries: Vec<KdbxEntry> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse KDBX JSON '{}': {}", file.display(), e))?;
    let result = KdbxImporter::import_entries(conn, &ctx(), &entries);

    println!(
        "Imported KDBX JSON: projects={} entries={} attachments={} skipped={}",
        result.projects_created,
        result.entries_created,
        result.attachments_created,
        result.entries_skipped
    );
    for warning in result.warnings {
        println!("  warning: {}", warning);
    }
    Ok(())
}

#[cfg(feature = "kdbx-export")]
fn cmd_export_kdbx_json(conn: &VaultConnection, output: PathBuf) -> Result<(), String> {
    let mut entries: Vec<KdbxEntry> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut attachments_exported = 0u32;
    let mut projects_skipped = 0u32;

    let device = cli_device_context();
    let session = conn
        .active_session()
        .ok_or_else(|| "KDBX export requires an active unlock session".to_string())?;
    let authorization = TigaAuthorizationContext {
        session: Some(session),
        device: &device,
        now_unix_secs: chrono::Utc::now().timestamp(),
    };
    for project in ProjectRepo::list_all(conn).map_err(|e| format!("{}", e))? {
        match KdbxExporter::export_one_authorized(conn, &project, authorization) {
            Ok(((entry, attachment_count, project_warnings), _decision)) => {
                entries.push(entry);
                attachments_exported += attachment_count;
                warnings.extend(project_warnings);
            }
            Err(e) => {
                projects_skipped += 1;
                warnings.push(format!("skipped project '{}': {}", project.project_id, e));
            }
        }
    }

    let json = serde_json::to_vec_pretty(&entries)
        .map_err(|e| format!("failed to serialize KDBX JSON: {}", e))?;
    std::fs::write(&output, json)
        .map_err(|e| format!("failed to write '{}': {}", output.display(), e))?;

    println!(
        "Exported KDBX JSON: entries={} attachments={} skipped={} -> {}",
        entries.len(),
        attachments_exported,
        projects_skipped,
        output.display()
    );
    for warning in warnings {
        println!("  warning: {}", warning);
    }
    Ok(())
}

fn export_sync_bundle(conn: &VaultConnection) -> Result<mdbx_sync::SyncBundle, String> {
    let vault_id = vault_id(conn)?;
    let source_device_id = latest_device_id(conn)?.unwrap_or_else(|| "cli-device".to_string());
    let mut commits = load_serialized_commits(conn)?;
    if let Some(last) = commits.last_mut() {
        last.object_payloads.push(
            collect_core_sync_state_payload(conn)
                .map_err(|e| format!("failed to serialize core sync state: {}", e))?,
        );
    }
    Ok(build_bundle(&vault_id, &source_device_id, commits))
}

fn apply_sync_bundle(
    conn: &mut VaultConnection,
    bundle: &mdbx_sync::SyncBundle,
) -> Result<ApplyBatchResult, String> {
    let local_vault_id = vault_id(conn)?;
    if bundle.vault_id != local_vault_id {
        return Err(format!(
            "bundle vault_id {} does not match local vault_id {}",
            bundle.vault_id, local_vault_id
        ));
    }

    let device_id = latest_device_id(conn)?.unwrap_or_else(|| "mdbx-cli-sync".to_string());
    SyncApplyRepo::apply_batch_mut(
        conn,
        &CommitContext::new(device_id),
        &CommitBatch::new(bundle.commits.clone(), 0, true),
    )
    .map_err(|e| format!("storage-core sync apply failed: {e}"))
}

fn vault_id(conn: &VaultConnection) -> Result<String, String> {
    conn.inner()
        .query_row("SELECT vault_id FROM vault_meta LIMIT 1", [], |row| {
            row.get(0)
        })
        .map_err(|e| format!("failed to read vault_id: {}", e))
}

fn latest_device_id(conn: &VaultConnection) -> Result<Option<String>, String> {
    conn.inner()
        .query_row(
            "SELECT device_id FROM device_heads ORDER BY last_seen_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("failed to read device head: {}", e))
}

fn load_serialized_commits(conn: &VaultConnection) -> Result<Vec<SerializedCommit>, String> {
    let mut stmt = conn
        .inner()
        .prepare(
            "SELECT commit_id, device_id, local_seq, commit_kind, change_scope,
                    changed_object_ids_ct, vector_clock, message_ct, created_at, integrity_tag
             FROM commits
             ORDER BY created_at ASC, device_id ASC, local_seq ASC",
        )
        .map_err(|e| format!("failed to query commits: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            let commit_id: String = row.get(0)?;
            let operation = operation_for_commit(conn, &commit_id)?;
            Ok(SerializedCommit {
                parent_ids: parent_ids_for_commit(conn, &commit_id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)),
                    )
                })?,
                tombstones: Vec::new(),
                object_payloads: Vec::new(),
                commit: Commit {
                    commit_id,
                    device_id: row.get(1)?,
                    local_seq: row.get::<_, i64>(2)? as u64,
                    commit_kind: parse_commit_kind(&row.get::<_, String>(3)?),
                    change_scope: parse_change_scope(&row.get::<_, String>(4)?),
                    changed_object_ids_ct: row.get(5)?,
                    vector_clock: row.get(6)?,
                    message_ct: row.get(7)?,
                    created_at: row.get(8)?,
                    integrity_tag: row.get(9)?,
                },
                operation,
            })
        })
        .map_err(|e| format!("failed to map commits: {}", e))?;

    let mut commits = Vec::new();
    for row in rows {
        commits.push(row.map_err(|e| format!("failed to read commit: {}", e))?);
    }

    let tombstones = load_tombstones(conn)?;
    if let Some(first) = commits.first_mut() {
        first.tombstones = tombstones;
    }
    Ok(commits)
}

fn operation_for_commit(
    conn: &VaultConnection,
    commit_id: &str,
) -> rusqlite::Result<Option<CommitOperationMetadata>> {
    conn.inner()
        .query_row(
            "SELECT operation_id, operation_kind, branch_id, branch_name,
                    change_summary_ct, request_hash, integrity_tag
             FROM commit_operations WHERE commit_id = ?1",
            params![commit_id],
            |row| {
                Ok(CommitOperationMetadata {
                    operation_id: row.get(0)?,
                    operation_kind: row.get(1)?,
                    branch_id: row.get(2)?,
                    branch_name: row.get(3)?,
                    change_summary_ct: row.get(4)?,
                    request_hash: row.get(5)?,
                    integrity_tag: row.get(6)?,
                })
            },
        )
        .optional()
}

fn parent_ids_for_commit(conn: &VaultConnection, commit_id: &str) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .inner()
        .prepare(
            "SELECT parent_commit_id FROM commit_parents
             WHERE commit_id = ?1
             ORDER BY parent_commit_id",
        )
        .map_err(|e| format!("failed to query commit parents: {}", e))?;
    let rows = stmt
        .query_map(params![commit_id], |row| row.get(0))
        .map_err(|e| format!("failed to map commit parents: {}", e))?;
    let mut parents = Vec::new();
    for row in rows {
        parents.push(row.map_err(|e| format!("failed to read commit parent: {}", e))?);
    }
    Ok(parents)
}

fn load_tombstones(conn: &VaultConnection) -> Result<Vec<TombstoneRecord>, String> {
    let mut stmt = conn
        .inner()
        .prepare(
            "SELECT tombstone_id, target_object_type, target_object_id,
                    delete_clock, deleted_by_device_id, deleted_at
             FROM tombstones
             ORDER BY deleted_at ASC, tombstone_id ASC",
        )
        .map_err(|e| format!("failed to query tombstones: {}", e))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TombstoneRecord {
                tombstone_id: row.get(0)?,
                target_object_type: row.get(1)?,
                target_object_id: row.get(2)?,
                delete_clock: row.get(3)?,
                deleted_by_device_id: row.get(4)?,
                deleted_at: row.get(5)?,
            })
        })
        .map_err(|e| format!("failed to map tombstones: {}", e))?;
    let mut tombstones = Vec::new();
    for row in rows {
        tombstones.push(row.map_err(|e| format!("failed to read tombstone: {}", e))?);
    }
    Ok(tombstones)
}

fn parse_commit_kind(value: &str) -> CommitKind {
    match value {
        "merge" => CommitKind::Merge,
        "snapshot" => CommitKind::Snapshot,
        "key-rotation" => CommitKind::KeyRotation,
        _ => CommitKind::Change,
    }
}

fn parse_change_scope(value: &str) -> ChangeScope {
    match value {
        "project" => ChangeScope::Project,
        "entry" => ChangeScope::Entry,
        "attachment" => ChangeScope::Attachment,
        "object-relation" => ChangeScope::ObjectRelation,
        "object-label" => ChangeScope::ObjectLabel,
        "object-label-assignment" => ChangeScope::ObjectLabelAssignment,
        "vault-meta" => ChangeScope::VaultMeta,
        "key-epoch" => ChangeScope::KeyEpoch,
        _ => ChangeScope::Multi,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdbx_storage::sync_apply::SyncApplyRepo;
    use mdbx_storage::sync_state::SYNC_STATE_OBJECT_TYPE;
    use mdbx_storage::tiga::TigaService;
    use mdbx_sync::CommitBatch;
    use std::path::{Path, PathBuf};

    const TEST_PASSWORD: &str = "test-password";

    struct TempVault {
        path: PathBuf,
    }

    impl TempVault {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mdbx-cli-{}.mdbx", uuid::Uuid::new_v4()));
            Self { path }
        }

        fn path(&self) -> PathBuf {
            self.path.clone()
        }
    }

    impl Drop for TempVault {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let candidate = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = std::fs::remove_file(candidate);
            }
        }
    }

    fn cli(vault: &Path, command: Commands) -> Cli {
        Cli {
            vault: vault.to_path_buf(),
            unlock_password: Some(TEST_PASSWORD.to_string()),
            unlock_pin: None,
            command,
        }
    }

    fn locked_cli(vault: &Path, command: Commands) -> Cli {
        Cli {
            vault: vault.to_path_buf(),
            unlock_password: None,
            unlock_pin: None,
            command,
        }
    }

    fn sync_bundle_path() -> PathBuf {
        std::env::temp_dir().join(format!("mdbx-cli-sync-{}.mdbx-sync", uuid::Uuid::new_v4()))
    }

    fn backup_vault(source: &Path, target: &Path) {
        BackupService::create_portable_copy_path(source, target).unwrap();
    }

    fn init_cli(vault: &Path) -> Cli {
        Cli {
            vault: vault.to_path_buf(),
            unlock_password: None,
            unlock_pin: None,
            command: Commands::Init {
                tiga: "sky".to_string(),
                password: Some(TEST_PASSWORD.to_string()),
                pin: None,
            },
        }
    }

    fn open_unlocked(vault: &Path) -> VaultConnection {
        let mut conn = VaultConnection::open(vault).unwrap();
        UnlockService::unlock_with_password(&mut conn, TEST_PASSWORD).unwrap();
        conn
    }

    fn project_title(project: &mdbx_core::model::Project) -> String {
        String::from_utf8(project.title_ct.clone()).unwrap()
    }

    fn entry_title(entry: &mdbx_core::model::Entry) -> String {
        String::from_utf8(entry.title_ct.clone().unwrap()).unwrap()
    }

    #[test]
    fn cli_can_init_unlock_and_project_crud() {
        let vault = TempVault::new();
        let path = vault.path();

        run(init_cli(&path)).unwrap();
        run(cli(&path, Commands::Unlock)).unwrap();

        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "CLI Project".to_string(),
                    group: Some("work".to_string()),
                },
            },
        ))
        .unwrap();

        let mut conn = open_unlocked(&path);
        let project = ProjectRepo::list_all(&conn).unwrap().remove(0);
        assert_eq!(project_title(&project), "CLI Project");
        assert_eq!(project.group_id.as_deref(), Some("work"));

        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Get {
                    project_id: project.project_id.clone(),
                },
            },
        ))
        .unwrap();

        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Edit {
                    project_id: project.project_id.clone(),
                    title: Some("CLI Project Renamed".to_string()),
                    favorite: Some(true),
                },
            },
        ))
        .unwrap();

        conn = open_unlocked(&path);
        let updated = ProjectRepo::get_by_id(&conn, &project.project_id)
            .unwrap()
            .unwrap();
        assert_eq!(project_title(&updated), "CLI Project Renamed");
        assert!(updated.favorite);

        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::List,
            },
        ))
        .unwrap();

        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Delete {
                    project_id: project.project_id.clone(),
                },
            },
        ))
        .unwrap();

        conn = open_unlocked(&path);
        assert!(ProjectRepo::list_all(&conn).unwrap().is_empty());
        assert_eq!(ProjectRepo::list_deleted(&conn).unwrap().len(), 1);

        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Deleted,
            },
        ))
        .unwrap();
    }

    #[test]
    fn init_failure_removes_new_vault_and_sidecars() {
        let vault = TempVault::new();
        let path = vault.path();
        let command = Commands::Init {
            tiga: "sky".to_string(),
            password: None,
            pin: Some("12".to_string()),
        };

        let result = run(Cli {
            vault: path.clone(),
            unlock_password: None,
            unlock_pin: None,
            command,
        });

        assert!(result.is_err());
        assert!(!path.exists());
        assert!(!PathBuf::from(format!("{}-wal", path.display())).exists());
        assert!(!PathBuf::from(format!("{}-shm", path.display())).exists());
    }

    #[test]
    fn non_mdbx_sqlite_is_rejected_without_modification() {
        let vault = TempVault::new();
        let path = vault.path();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE unrelated_data (value TEXT NOT NULL);
                 INSERT INTO unrelated_data VALUES ('preserve-me');",
            )
            .unwrap();
        }
        let before = std::fs::read(&path).unwrap();

        let result = run(locked_cli(&path, Commands::Unlock));

        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn cli_can_entry_crud_move_and_copy() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();

        for title in ["Source", "Target"] {
            run(cli(
                &path,
                Commands::Project {
                    action: ProjectAction::Create {
                        title: title.to_string(),
                        group: None,
                    },
                },
            ))
            .unwrap();
        }

        let conn = open_unlocked(&path);
        let projects = ProjectRepo::list_all(&conn).unwrap();
        let source_id = projects
            .iter()
            .find(|p| project_title(p) == "Source")
            .unwrap()
            .project_id
            .clone();
        let target_id = projects
            .iter()
            .find(|p| project_title(p) == "Target")
            .unwrap()
            .project_id
            .clone();
        drop(conn);

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::Create {
                    project_id: source_id.clone(),
                    entry_type: "login".to_string(),
                    title: Some("Example Login".to_string()),
                    username: Some("alice".to_string()),
                    password: Some("secret".to_string()),
                    url: Some("https://example.com".to_string()),
                    notes: Some("created from CLI".to_string()),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let mut entries = EntryRepo::list_by_project(&conn, &source_id).unwrap();
        assert_eq!(entries.len(), 1);
        let entry_id = entries.remove(0).entry_id;
        drop(conn);

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::Get {
                    entry_id: entry_id.clone(),
                },
            },
        ))
        .unwrap();

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::Edit {
                    entry_id: entry_id.clone(),
                    title: Some("Example Login v2".to_string()),
                    username: Some("bob".to_string()),
                    password: None,
                    url: None,
                    notes: Some("updated from CLI".to_string()),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let updated = EntryRepo::get_by_id(&conn, &entry_id).unwrap().unwrap();
        assert_eq!(entry_title(&updated), "Example Login v2");
        let payload: serde_json::Value = serde_json::from_slice(&updated.payload_ct).unwrap();
        assert_eq!(payload["username"], "bob");
        assert_eq!(payload["password"], "secret");
        drop(conn);

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::Copy {
                    entry_id: entry_id.clone(),
                    target_project_id: target_id.clone(),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        assert_eq!(
            EntryRepo::list_by_project(&conn, &source_id).unwrap().len(),
            1
        );
        assert_eq!(
            EntryRepo::list_by_project(&conn, &target_id).unwrap().len(),
            1
        );
        drop(conn);

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::Move {
                    entry_id: entry_id.clone(),
                    target_project_id: target_id.clone(),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        assert!(EntryRepo::list_by_project(&conn, &source_id)
            .unwrap()
            .is_empty());
        let target_entries = EntryRepo::list_by_project(&conn, &target_id).unwrap();
        assert_eq!(target_entries.len(), 2);
        drop(conn);

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::List {
                    project_id: target_id,
                    entry_type: Some("login".to_string()),
                },
            },
        ))
        .unwrap();

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::Delete {
                    entry_id: entry_id.clone(),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let deleted = EntryRepo::get_by_id(&conn, &entry_id).unwrap().unwrap();
        assert!(deleted.deleted);
        assert_eq!(EntryRepo::list_deleted(&conn).unwrap().len(), 1);
        drop(conn);

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::Deleted,
            },
        ))
        .unwrap();
    }

    #[test]
    fn cli_entry_list_does_not_decrypt_object_payloads() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();
        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Summary Collection".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();
        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        let entry = EntryRepo::create(
            &conn,
            &ctx(),
            &project_id,
            EntryType::Login,
            Some("Visible title"),
            &serde_json::json!({"password": "secret"}),
        )
        .unwrap();
        conn.inner()
            .execute(
                "UPDATE entries SET payload_ct = X'00' WHERE entry_id = ?1",
                params![entry.entry_id],
            )
            .unwrap();
        drop(conn);

        run(cli(
            &path,
            Commands::Entry {
                action: EntryAction::List {
                    project_id,
                    entry_type: Some("login".to_string()),
                },
            },
        ))
        .unwrap();
    }

    #[test]
    fn cli_can_attachment_crud_and_snapshot_roundtrip() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();

        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Attachments".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        let commit_count_before_attachment: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        drop(conn);

        let input =
            std::env::temp_dir().join(format!("mdbx-cli-input-{}.txt", uuid::Uuid::new_v4()));
        let output =
            std::env::temp_dir().join(format!("mdbx-cli-output-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&input, b"hello from attachment").unwrap();

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Add {
                    project_id: project_id.clone(),
                    entry_id: None,
                    file: input.clone(),
                    external: false,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let attachment = AttachmentRepo::list_by_project(&conn, &project_id)
            .unwrap()
            .remove(0);
        let commit_count_after_attachment: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            commit_count_after_attachment,
            commit_count_before_attachment + 1
        );
        assert_eq!(
            String::from_utf8(attachment.file_name_ct.clone()).unwrap(),
            input.file_name().unwrap().to_string_lossy()
        );
        drop(conn);

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Info {
                    attachment_id: attachment.attachment_id.clone(),
                },
            },
        ))
        .unwrap();
        std::fs::write(&output, b"stale output").unwrap();
        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Verify {
                    attachment_id: attachment.attachment_id.clone(),
                },
            },
        ))
        .unwrap();
        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Get {
                    attachment_id: attachment.attachment_id.clone(),
                    output: Some(output.clone()),
                },
            },
        ))
        .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"hello from attachment");

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Rename {
                    attachment_id: attachment.attachment_id.clone(),
                    file_name: "renamed.txt".to_string(),
                    media_type: Some("text/plain".to_string()),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let renamed = AttachmentRepo::get_by_id(&conn, &attachment.attachment_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            String::from_utf8(renamed.file_name_ct).unwrap(),
            "renamed.txt"
        );
        drop(conn);

        run(cli(
            &path,
            Commands::Snapshot {
                action: SnapshotAction::Create,
            },
        ))
        .unwrap();
        let conn = open_unlocked(&path);
        let snapshot_id = SnapshotRepo::list_all(&conn).unwrap()[0]
            .snapshot_id
            .clone();
        drop(conn);
        run(cli(
            &path,
            Commands::Snapshot {
                action: SnapshotAction::List,
            },
        ))
        .unwrap();
        run(cli(
            &path,
            Commands::Snapshot {
                action: SnapshotAction::Restore { snapshot_id },
            },
        ))
        .unwrap();

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Delete {
                    attachment_id: attachment.attachment_id.clone(),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let deleted = AttachmentRepo::get_by_id(&conn, &attachment.attachment_id)
            .unwrap()
            .unwrap();
        assert!(deleted.deleted);
        assert_eq!(AttachmentRepo::list_deleted(&conn).unwrap().len(), 1);
        drop(conn);

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Deleted,
            },
        ))
        .unwrap();

        let _ = std::fs::remove_file(input);
        let _ = std::fs::remove_file(output);
    }

    #[test]
    fn cli_attachment_export_failure_preserves_existing_target() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();
        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Protected Export".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        drop(conn);
        let input =
            std::env::temp_dir().join(format!("mdbx-cli-corrupt-{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&input, b"authenticated attachment content").unwrap();
        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Add {
                    project_id: project_id.clone(),
                    entry_id: None,
                    file: input.clone(),
                    external: false,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let attachment = AttachmentRepo::list_by_project(&conn, &project_id)
            .unwrap()
            .remove(0);
        conn.inner()
            .execute(
                "UPDATE attachments SET content_hash = ?1 WHERE attachment_id = ?2",
                params!["0".repeat(64), attachment.attachment_id],
            )
            .unwrap();
        drop(conn);

        let output_dir = tempfile::tempdir().unwrap();
        let output = output_dir.path().join("existing.bin");
        std::fs::write(&output, b"keep this target").unwrap();
        let error = run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Get {
                    attachment_id: attachment.attachment_id,
                    output: Some(output.clone()),
                },
            },
        ))
        .unwrap_err();

        assert!(error.contains("content hash mismatch"));
        assert_eq!(std::fs::read(&output).unwrap(), b"keep this target");
        let remaining_files: Vec<_> = std::fs::read_dir(output_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(remaining_files, vec![output.file_name().unwrap()]);

        let _ = std::fs::remove_file(input);
    }

    #[test]
    fn cli_attachment_export_is_denied_before_temporary_file_creation() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();
        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Power Export".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        let session = conn.active_session().cloned().unwrap();
        let device = cli_device_context();
        TigaService::set_project_profile_authorized(
            &conn,
            &ctx(),
            &project_id,
            Some(TigaMode::Power),
            None,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: chrono::Utc::now().timestamp(),
            },
        )
        .unwrap();
        drop(conn);

        let input =
            std::env::temp_dir().join(format!("mdbx-cli-denied-{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&input, b"protected content").unwrap();
        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Add {
                    project_id: project_id.clone(),
                    entry_id: None,
                    file: input.clone(),
                    external: false,
                },
            },
        ))
        .unwrap();
        let conn = open_unlocked(&path);
        let attachment = AttachmentRepo::list_by_project(&conn, &project_id)
            .unwrap()
            .remove(0);
        drop(conn);

        let output_dir = tempfile::tempdir().unwrap();
        let output = output_dir.path().join("existing.bin");
        std::fs::write(&output, b"keep existing content").unwrap();
        let error = run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Get {
                    attachment_id: attachment.attachment_id.clone(),
                    output: Some(output.clone()),
                },
            },
        ))
        .unwrap_err();
        assert!(error.contains("authorization"));
        assert_eq!(std::fs::read(&output).unwrap(), b"keep existing content");
        let remaining_files: Vec<_> = std::fs::read_dir(output_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(remaining_files, vec![output.file_name().unwrap()]);

        let conn = open_unlocked(&path);
        let event = TigaService::list_security_audit_events(&conn, 10)
            .unwrap()
            .into_iter()
            .find(|event| event.operation == mdbx_core::tiga::TigaOperation::ExportData)
            .unwrap();
        assert_eq!(
            event.scope,
            mdbx_core::tiga::TigaScope::Attachment {
                attachment_id: attachment.attachment_id
            }
        );
        assert!(event.policy_fingerprint.is_some());

        let _ = std::fs::remove_file(input);
    }

    #[test]
    fn cli_streams_large_attachment_in_single_commit() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();
        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Large Attachments".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        let commit_count_before: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        drop(conn);

        let input =
            std::env::temp_dir().join(format!("mdbx-cli-large-{}.bin", uuid::Uuid::new_v4()));
        let output =
            std::env::temp_dir().join(format!("mdbx-cli-large-out-{}.bin", uuid::Uuid::new_v4()));
        let data: Vec<u8> = (0..ATTACHMENT_STREAM_CHUNK_SIZE + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        std::fs::write(&input, &data).unwrap();

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Add {
                    project_id: project_id.clone(),
                    entry_id: None,
                    file: input.clone(),
                    external: false,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let attachment = AttachmentRepo::list_by_project(&conn, &project_id)
            .unwrap()
            .remove(0);
        let commit_count_after: i64 = conn
            .inner()
            .query_row("SELECT COUNT(*) FROM commits", [], |row| row.get(0))
            .unwrap();
        assert_eq!(commit_count_after, commit_count_before + 1);
        assert_eq!(attachment.chunk_count, 2);
        assert_eq!(
            attachment.storage_mode,
            mdbx_core::model::attachment::StorageMode::EmbeddedChunked
        );
        drop(conn);

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Get {
                    attachment_id: attachment.attachment_id,
                    output: Some(output.clone()),
                },
            },
        ))
        .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), data);

        let _ = std::fs::remove_file(input);
        let _ = std::fs::remove_file(output);
    }

    #[cfg(feature = "external-blob-store")]
    #[test]
    fn cli_roundtrips_external_encrypted_attachment() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();
        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "External Attachments".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        drop(conn);
        let input =
            std::env::temp_dir().join(format!("mdbx-cli-external-{}.bin", uuid::Uuid::new_v4()));
        let output = std::env::temp_dir().join(format!(
            "mdbx-cli-external-out-{}.bin",
            uuid::Uuid::new_v4()
        ));
        let data: Vec<u8> = (0..ATTACHMENT_STREAM_CHUNK_SIZE + 31)
            .map(|index| (index % 241) as u8)
            .collect();
        std::fs::write(&input, &data).unwrap();

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Add {
                    project_id: project_id.clone(),
                    entry_id: None,
                    file: input.clone(),
                    external: true,
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let attachment = AttachmentRepo::list_by_project(&conn, &project_id)
            .unwrap()
            .remove(0);
        assert_eq!(attachment.storage_mode, StorageMode::ExternalHashRef);
        assert_eq!(attachment.chunk_count, 2);
        let (embedded_count, external_count): (i64, i64) = conn
            .inner()
            .query_row(
                "SELECT COUNT(chunk_ct), COUNT(external_uri_ct)
                 FROM attachment_chunks WHERE attachment_id = ?1",
                params![attachment.attachment_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(embedded_count, 0);
        assert_eq!(external_count, 2);
        drop(conn);
        assert!(default_blob_store_path(&path).is_dir());

        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Verify {
                    attachment_id: attachment.attachment_id.clone(),
                },
            },
        ))
        .unwrap();
        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Get {
                    attachment_id: attachment.attachment_id,
                    output: Some(output.clone()),
                },
            },
        ))
        .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), data);

        let _ = std::fs::remove_file(input);
        let _ = std::fs::remove_file(output);
        let _ = std::fs::remove_dir_all(default_blob_store_path(&path));
    }

    #[cfg(feature = "external-blob-store")]
    #[test]
    fn cli_audits_plans_and_applies_blob_garbage_collection() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();
        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Blob maintenance".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();
        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        drop(conn);
        let input =
            std::env::temp_dir().join(format!("mdbx-cli-blob-{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&input, b"referenced external content").unwrap();
        run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Add {
                    project_id,
                    entry_id: None,
                    file: input.clone(),
                    external: true,
                },
            },
        ))
        .unwrap();

        let store = FileSystemBlobStore::new(default_blob_store_path(&path));
        let orphan = b"opaque orphan ciphertext";
        let orphan_id = mdbx_storage::blob_store::compute_blob_id(orphan);
        mdbx_storage::blob_store::EncryptedBlobStore::put(&store, &orphan_id, orphan).unwrap();
        let conn = open_unlocked(&path);
        let cutoff = chrono::Utc::now().timestamp().saturating_add(1);
        let plan =
            BlobLifecycleService::plan_gc(&conn, &store, cutoff, BlobLifecycleLimits::default())
                .unwrap();
        assert_eq!(plan.eligible_orphans.len(), 1);
        drop(conn);

        run(cli(
            &path,
            Commands::Blob {
                action: BlobAction::Audit {
                    grace_hours: 0,
                    skip_content_verification: false,
                },
            },
        ))
        .unwrap();
        run(cli(
            &path,
            Commands::Blob {
                action: BlobAction::GcPlan { grace_hours: 0 },
            },
        ))
        .unwrap();
        run(cli(
            &path,
            Commands::Blob {
                action: BlobAction::GcApply {
                    plan_token: plan.plan_token,
                    cutoff_unix_secs: cutoff,
                },
            },
        ))
        .unwrap();

        assert!(!store.blob_path(&orphan_id).unwrap().exists());
        let conn = open_unlocked(&path);
        let audit_count: i64 = conn
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM security_audit_events
                 WHERE operation = 'purge-deleted-object'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(audit_count, 1);

        let _ = std::fs::remove_file(input);
        let _ = std::fs::remove_dir_all(default_blob_store_path(&path));
    }

    #[cfg(not(feature = "external-blob-store"))]
    #[test]
    fn core_cli_reports_missing_external_blob_provider_before_mutation() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();
        run(cli(
            &path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Core Attachments".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();
        let conn = open_unlocked(&path);
        let project_id = ProjectRepo::list_all(&conn).unwrap()[0].project_id.clone();
        drop(conn);
        let input =
            std::env::temp_dir().join(format!("mdbx-cli-core-{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&input, b"external").unwrap();

        let error = run(cli(
            &path,
            Commands::Attach {
                action: AttachAction::Add {
                    project_id: project_id.clone(),
                    entry_id: None,
                    file: input.clone(),
                    external: true,
                },
            },
        ))
        .unwrap_err();

        assert!(error.contains("does not include the filesystem encrypted Blob Provider"));
        let conn = open_unlocked(&path);
        assert!(AttachmentRepo::list_by_project(&conn, &project_id)
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_file(input);
    }

    #[cfg(not(feature = "external-blob-store"))]
    #[test]
    fn core_cli_reports_missing_blob_lifecycle_capability() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();

        let error = run(cli(
            &path,
            Commands::Blob {
                action: BlobAction::Audit {
                    grace_hours: 168,
                    skip_content_verification: false,
                },
            },
        ))
        .unwrap_err();

        assert!(error.contains("does not include filesystem Blob lifecycle management"));
    }

    #[test]
    fn cli_backup_reopens_with_latest_project_and_has_no_sidecars() {
        let source = TempVault::new();
        let backup = TempVault::new();
        let source_path = source.path();
        let backup_path = backup.path();
        run(init_cli(&source_path)).unwrap();
        run(cli(
            &source_path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Portable backup project".to_string(),
                    group: None,
                },
            },
        ))
        .unwrap();

        run(locked_cli(
            &source_path,
            Commands::Backup {
                output: backup_path.clone(),
            },
        ))
        .unwrap();

        assert!(!PathBuf::from(format!("{}-wal", backup_path.display())).exists());
        assert!(!PathBuf::from(format!("{}-shm", backup_path.display())).exists());
        let reopened = open_unlocked(&backup_path);
        let projects = ProjectRepo::list_all(&reopened).unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(project_title(&projects[0]), "Portable backup project");
    }

    #[test]
    fn cli_backup_preserves_existing_output() {
        let source = TempVault::new();
        let backup = TempVault::new();
        let source_path = source.path();
        let backup_path = backup.path();
        run(init_cli(&source_path)).unwrap();
        std::fs::write(&backup_path, b"preserve CLI output").unwrap();

        let result = run(cli(
            &source_path,
            Commands::Backup {
                output: backup_path.clone(),
            },
        ));

        assert!(result.is_err());
        assert_eq!(std::fs::read(backup_path).unwrap(), b"preserve CLI output");
    }

    #[test]
    fn cli_backup_preserves_legacy_format_before_automatic_open() {
        let source = TempVault::new();
        let backup = TempVault::new();
        let source_path = source.path();
        let backup_path = backup.path();
        {
            let conn = rusqlite::Connection::open(&source_path).unwrap();
            mdbx_storage::schema::v1::create_all_tables(&conn).unwrap();
            conn.execute(
                "INSERT INTO vault_meta
                    (vault_id, format_version, created_at, updated_at,
                     default_tiga_mode, active_key_epoch_id, compat_flags,
                     critical_extensions)
                 VALUES ('cli-legacy-backup-vault', 'MDBX-1',
                         '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                         'multi', 'epoch-1', '', '')",
                [],
            )
            .unwrap();
        }

        run(locked_cli(
            &source_path,
            Commands::Backup {
                output: backup_path.clone(),
            },
        ))
        .unwrap();

        let source_plan = mdbx_storage::migration::inspect_migration_path(&source_path).unwrap();
        let backup_plan = mdbx_storage::migration::inspect_migration_path(&backup_path).unwrap();
        assert_eq!(source_plan, backup_plan);
        assert_eq!(source_plan.format_version.as_deref(), Some("MDBX-1"));
        assert!(source_plan.requires_upgrade);
    }

    #[test]
    fn cli_can_export_and_apply_sync_bundle_to_same_vault_copy() {
        let source = TempVault::new();
        let target = TempVault::new();
        let core_target = TempVault::new();
        let source_path = source.path();
        let target_path = target.path();
        let core_target_path = core_target.path();
        let bundle_path = sync_bundle_path();

        run(init_cli(&source_path)).unwrap();
        backup_vault(&source_path, &target_path);
        backup_vault(&source_path, &core_target_path);

        run(cli(
            &source_path,
            Commands::Project {
                action: ProjectAction::Create {
                    title: "Synced Project".to_string(),
                    group: Some("sync".to_string()),
                },
            },
        ))
        .unwrap();

        let conn = open_unlocked(&source_path);
        let project = ProjectRepo::list_all(&conn).unwrap().remove(0);
        let project_id = project.project_id.clone();
        drop(conn);

        run(cli(
            &source_path,
            Commands::Entry {
                action: EntryAction::Create {
                    project_id: project_id.clone(),
                    entry_type: "login".to_string(),
                    title: Some("Synced Login".to_string()),
                    username: Some("alice".to_string()),
                    password: Some("synced-secret".to_string()),
                    url: Some("https://sync.example".to_string()),
                    notes: Some("created before bundle".to_string()),
                },
            },
        ))
        .unwrap();

        run(cli(
            &source_path,
            Commands::Sync {
                action: SyncAction::Bundle {
                    output: bundle_path.clone(),
                },
            },
        ))
        .unwrap();

        let bundle = {
            let bytes = std::fs::read(&bundle_path).unwrap();
            assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3);
            let mut file = std::fs::File::open(&bundle_path).unwrap();
            mdbx_sync::read_bundle(&mut file).unwrap()
        };
        assert!(bundle.commits.iter().any(|commit| {
            commit
                .object_payloads
                .iter()
                .any(|payload| payload.object_type == SYNC_STATE_OBJECT_TYPE)
        }));

        let core_target_conn = open_unlocked(&core_target_path);
        let core_result = SyncApplyRepo::apply_batch(
            &core_target_conn,
            &CommitContext::new("core-target-device".to_string()),
            &CommitBatch::new(bundle.commits.clone(), 0, true),
        )
        .unwrap();
        assert_eq!(core_result.conflict_count, 0);

        run(cli(
            &target_path,
            Commands::Sync {
                action: SyncAction::Apply {
                    file: bundle_path.clone(),
                },
            },
        ))
        .unwrap();

        let target_conn = open_unlocked(&target_path);
        let target_projects = ProjectRepo::list_all(&target_conn).unwrap();
        let synced_project = target_projects
            .iter()
            .find(|project| project_title(project) == "Synced Project")
            .unwrap();
        assert_eq!(synced_project.group_id.as_deref(), Some("sync"));

        let target_entries =
            EntryRepo::list_by_project(&target_conn, &synced_project.project_id).unwrap();
        assert_eq!(target_entries.len(), 1);
        assert_eq!(entry_title(&target_entries[0]), "Synced Login");
        let payload: serde_json::Value =
            serde_json::from_slice(&target_entries[0].payload_ct).unwrap();
        assert_eq!(payload["username"], "alice");
        assert_eq!(payload["password"], "synced-secret");

        let core_projects = ProjectRepo::list_all(&core_target_conn).unwrap();
        let core_project = core_projects
            .iter()
            .find(|project| project_title(project) == "Synced Project")
            .unwrap();
        let core_entries =
            EntryRepo::list_by_project(&core_target_conn, &core_project.project_id).unwrap();
        assert_eq!(core_entries.len(), 1);
        assert_eq!(entry_title(&core_entries[0]), "Synced Login");

        let _ = std::fs::remove_file(bundle_path);
    }

    #[test]
    fn cli_rejects_configured_vault_without_unlock() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();

        let result = run(locked_cli(
            &path,
            Commands::Project {
                action: ProjectAction::List,
            },
        ));

        assert!(result
            .unwrap_err()
            .contains("pass --unlock-password or --unlock-pin"));
    }

    #[cfg(feature = "benchmark")]
    #[test]
    fn cli_exposes_health_and_benchmark() {
        let vault = TempVault::new();
        let path = vault.path();
        run(init_cli(&path)).unwrap();

        run(cli(&path, Commands::Health)).unwrap();
        run(cli(&path, Commands::Benchmark { iterations: 1 })).unwrap();
    }

    #[cfg(all(feature = "kdbx-import", feature = "kdbx-export"))]
    #[test]
    fn cli_can_import_and_export_kdbx_json() {
        let vault = TempVault::new();
        let path = vault.path();
        let import_path =
            std::env::temp_dir().join(format!("mdbx-cli-import-{}.json", uuid::Uuid::new_v4()));
        let export_path =
            std::env::temp_dir().join(format!("mdbx-cli-export-{}.json", uuid::Uuid::new_v4()));

        run(init_cli(&path)).unwrap();

        let entries = vec![KdbxEntry {
            uuid: "kdbx-entry-1".to_string(),
            title: "Imported Login".to_string(),
            username: "alice".to_string(),
            password: "secret".to_string(),
            url: "https://example.com".to_string(),
            notes: "imported note".to_string(),
            totp_seed: Some("totp-seed".to_string()),
            custom_fields: vec![("env".to_string(), "prod".to_string())],
            attachments: vec![],
            group_path: vec!["Work".to_string(), "Infra".to_string()],
            icon_id: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }];
        std::fs::write(&import_path, serde_json::to_vec(&entries).unwrap()).unwrap();

        run(cli(
            &path,
            Commands::ImportKdbxJson {
                file: import_path.clone(),
            },
        ))
        .unwrap();

        let conn = open_unlocked(&path);
        let projects = ProjectRepo::list_all(&conn).unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(project_title(&projects[0]), "Imported Login");
        drop(conn);

        run(cli(
            &path,
            Commands::ExportKdbxJson {
                output: export_path.clone(),
            },
        ))
        .unwrap();

        let exported: Vec<KdbxEntry> =
            serde_json::from_slice(&std::fs::read(&export_path).unwrap()).unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].title, "Imported Login");
        assert_eq!(exported[0].username, "alice");
        assert_eq!(exported[0].password, "secret");
        assert_eq!(exported[0].group_path, vec!["Work", "Infra"]);

        let _ = std::fs::remove_file(import_path);
        let _ = std::fs::remove_file(export_path);
    }
}
