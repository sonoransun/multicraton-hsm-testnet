// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
mod commands;
mod output;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "craton-hsm-admin", about = "Craton HSM Admin CLI")]
struct Cli {
    /// Path to craton_hsm.toml config file
    #[arg(long, default_value = "craton_hsm.toml")]
    config: String,

    /// Output in JSON format
    #[arg(long, default_value_t = false)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Token management
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Key management
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// PIN management
    Pin {
        #[command(subcommand)]
        action: PinAction,
    },
    /// Dump audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Show HSM status
    Status,
    /// Create encrypted backup of token objects
    Backup {
        /// Output backup file path
        #[arg(long)]
        output: String,
    },
    /// Restore token objects from encrypted backup
    Restore {
        /// Input backup file path
        #[arg(long)]
        input: String,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Initialize a new token
    Init {
        /// Token label
        #[arg(long)]
        label: String,
    },
    /// Display token information
    Info,
}

#[derive(Subcommand)]
enum KeyAction {
    /// List all keys
    List,
    /// Import a key from file
    Import {
        /// Path to key file (PEM or DER)
        #[arg(long)]
        file: String,
        /// Key label
        #[arg(long)]
        label: String,
        /// Key type (RSA, EC, AES)
        #[arg(long, name = "type")]
        key_type: String,
    },
    /// Delete a key
    Delete {
        /// Key handle
        #[arg(long)]
        handle: u64,
        /// Skip confirmation
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Wrap a key with another key
    Wrap {
        /// Wrapping key handle
        #[arg(long)]
        wrapping_key: u64,
        /// Target key handle to wrap
        #[arg(long)]
        target_key: u64,
        /// Output file path
        #[arg(long)]
        output: String,
    },
    /// Unwrap a wrapped key
    Unwrap {
        /// Unwrapping key handle
        #[arg(long)]
        unwrapping_key: u64,
        /// Input file path with wrapped key
        #[arg(long)]
        input: String,
        /// Label for the unwrapped key
        #[arg(long)]
        label: String,
    },
    /// Export wrapped key in structured format
    ExportWrapped {
        /// Wrapping key handle
        #[arg(long)]
        wrapping_key: u64,
        /// Target key handle to export
        #[arg(long)]
        target_key: u64,
        /// Export format (json, pkcs8, pkcs12)
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path
        #[arg(long)]
        output: String,
    },
    /// Import wrapped key from structured format
    ImportWrapped {
        /// Unwrapping key handle
        #[arg(long)]
        unwrapping_key: u64,
        /// Import format (json, pkcs8, pkcs12)
        #[arg(long, default_value = "json")]
        format: String,
        /// Input file path
        #[arg(long)]
        input: String,
        /// Label for the imported key
        #[arg(long)]
        label: String,
    },
}

#[derive(Subcommand)]
enum PinAction {
    /// Change user or SO PIN
    Change {
        /// User type: USER or SO
        #[arg(long, default_value = "USER")]
        user_type: String,
    },
    /// Reset user PIN (requires SO authentication)
    Reset,
}

#[derive(Subcommand)]
enum AuditAction {
    /// Dump recent audit log entries
    Dump {
        /// Number of recent entries to show
        #[arg(long, default_value_t = 50)]
        last: usize,
    },
    /// Export audit log as JSON array
    ExportJson,
    /// Export audit log as newline-delimited JSON (NDJSON) for SIEM ingestion
    ExportNdjson,
    /// Export audit log in syslog RFC 5424 format
    ExportSyslog,
    /// Verify integrity of the audit log hash chain
    VerifyChain,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Token { action } => match action {
            TokenAction::Init { label } => commands::token::init(&cli.config, &label),
            TokenAction::Info => commands::token::info(&cli.config, cli.json),
        },
        Commands::Key { action } => match action {
            KeyAction::List => commands::key::list(&cli.config, cli.json),
            KeyAction::Import {
                file,
                label,
                key_type,
            } => commands::key::import(&cli.config, &file, &label, &key_type),
            KeyAction::Delete { handle, force } => {
                commands::key::delete(&cli.config, handle, force)
            }
            KeyAction::Wrap {
                wrapping_key,
                target_key,
                output,
            } => commands::key::wrap_key(&cli.config, wrapping_key, target_key, &output),
            KeyAction::Unwrap {
                unwrapping_key,
                input,
                label,
            } => commands::key::unwrap_key(&cli.config, unwrapping_key, &input, &label),
            KeyAction::ExportWrapped {
                wrapping_key,
                target_key,
                format,
                output,
            } => commands::key::export_wrapped_key(
                &cli.config,
                wrapping_key,
                target_key,
                &format,
                &output,
            ),
            KeyAction::ImportWrapped {
                unwrapping_key,
                format,
                input,
                label,
            } => commands::key::import_wrapped_key(
                &cli.config,
                unwrapping_key,
                &format,
                &input,
                &label,
            ),
        },
        Commands::Pin { action } => match action {
            PinAction::Change { user_type } => commands::pin::change(&cli.config, &user_type),
            PinAction::Reset => commands::pin::reset(&cli.config),
        },
        Commands::Audit { action } => match action {
            AuditAction::Dump { last } => commands::audit::dump(&cli.config, last, cli.json),
            AuditAction::ExportJson => commands::audit::export_json(&cli.config),
            AuditAction::ExportNdjson => commands::audit::export_ndjson(&cli.config),
            AuditAction::ExportSyslog => commands::audit::export_syslog(&cli.config),
            AuditAction::VerifyChain => commands::audit::verify_chain(&cli.config, cli.json),
        },
        Commands::Status => commands::token::status(&cli.config, cli.json),
        Commands::Backup { output } => commands::backup::create_backup(&cli.config, &output),
        Commands::Restore { input } => commands::backup::restore_backup(&cli.config, &input),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
