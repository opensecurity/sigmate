use clap::{ArgGroup, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, global = true, help = "Enable debug logging output.")]
    pub debug: bool,

    #[arg(long, short = 'n', global = true, help = "Disable emoji output.")]
    pub no_emojis: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Generates Ed25519 signatures and/or traditional checksum files.")]
    Sign(SignArgs),
    #[command(about = "Verifies files using Ed25519 signatures OR traditional checksum files.")]
    Verify(VerifyArgs),
    #[command(about = "Manage trusted public keys and the keyring.")]
    Trust(TrustArgs),
    #[command(
        about = "Configure default settings for sigmate.",
        long_about = "Run with arguments to set values directly, or run without arguments for an interactive setup session."
    )]
    Configure(ConfigureArgs),
    #[command(
        about = "Removes generated signature artifacts, always prompting for confirmation.",
        long_about = "If a PATH is provided, this command inspects that directory for artifacts. If no PATH is provided, it defaults to cleaning the './signatures' directory and any default checksum files from the current directory."
    )]
    Clean(CleanArgs),
}

#[derive(Parser, Debug)]
#[command(group(ArgGroup::new("input").required(true).args(&["target_path_or_file", "walk", "file_list"])))]
pub struct SignArgs {
    #[arg(value_name = "TARGET", help = "Path to the file or directory to process.")]
    pub target_path_or_file: Option<PathBuf>,

    #[arg(long, value_name = "DIR", help = "Directory to recursively process.")]
    pub walk: Option<PathBuf>,

    #[arg(long = "list", value_name = "FILE", help = "Text file listing files/directories to process.")]
    pub file_list: Option<PathBuf>,

    #[arg(long, value_name = "PATH", help = "Path to private key (PEM). Overrides configured default.")]
    pub key: Option<PathBuf>,

    #[arg(long, value_name = "ENV_VAR", help = "Environment variable for the private key password.")]
    pub key_password_env: Option<String>,

    #[arg(long, value_name = "DIR", help = "Base directory for all generated files.")]
    pub signatures_output: Option<PathBuf>,

    #[arg(long, help = "Output raw Ed25519 .sig file.")]
    pub raw: bool,

    #[arg(long, help = "Output sigmate.meta.json.")]
    pub meta: bool,

    #[arg(long, help = "Output both .sig and sigmate.meta.json.")]
    pub both: bool,

    #[arg(long, help = "Generate CycloneDX SBOM (sigmate.sbom.json).")]
    pub sbom: bool,

    #[arg(long, short, help = "Print a JSON summary of operations.")]
    pub json: bool,

    #[arg(long, value_name = "IDENTITY", help = "Override signer identity. Overrides configured default.")]
    pub identity: Option<String>,

    #[arg(long, value_name = "HOST", help = "Override host name for metadata.")]
    pub host: Option<String>,

    #[arg(long, value_name = "HOURS", help = "Expiration for signatures in hours (e.g., 72).")]
    pub expires_in: Option<u64>,

    #[arg(long, help = "Exclude absolute file paths in metadata and SBOMs.")]
    pub no_abspath: bool,

    #[arg(long, help = "Generate MD5SUMS file.")]
    pub gen_md5sums: bool,
    
    #[arg(long, help = "Generate SHA1SUMS file.")]
    pub gen_sha1sums: bool,

    #[arg(long, help = "Generate SHA256SUMS file.")]
    pub gen_sha256sums: bool,

    #[arg(long, help = "Generate SHA512SUMS file.")]
    pub gen_sha512sums: bool,

    #[arg(long, help = "Overwrite existing signature and checksum artifacts.")]
    pub force: bool,
}

#[derive(Parser, Debug)]
#[command(group(ArgGroup::new("verify-input").args(&["target_path_or_file", "walk", "file_list"])))]
pub struct VerifyArgs {
    #[arg(value_name = "TARGET", help = "Path to the file or directory to verify.")]
    pub target_path_or_file: Option<PathBuf>,

    #[arg(long, value_name = "PATH", help = "Path to a public key (PEM) for verification.", conflicts_with = "signer")]
    pub key: Option<PathBuf>,

    #[arg(long, value_name = "NAME", help = "Verify using a trusted signer's name from the keyring.")]
    pub signer: Option<String>,

    #[arg(long, value_name = "FILE", help = "Explicit Ed25519 signature file (.sig).")]
    pub signature: Option<PathBuf>,

    #[arg(long, value_name = "TYPE", default_value = "auto", value_parser = ["auto", "raw", "meta"])]
    pub sig_type: String,
    
    #[arg(long, value_name = "DIR", help = "Directory containing Ed25519 signature files.")]
    pub signatures_input: Option<PathBuf>,

    #[arg(long, help = "Enforce that the signer's public key is in the trust store and 'verified'.")]
    pub require_trusted: bool,

    #[arg(long, value_name = "FILE", help = "Path to the checksum file for verification.")]
    pub checksum_file: Option<PathBuf>,

    #[arg(long, value_name = "ALGO", default_value = "auto", value_parser = ["auto", "md5", "sha1", "sha256", "sha512"])]
    pub checksum_algo: String,
    
    #[arg(long, value_name = "FORMAT", default_value = "auto", value_parser = ["auto", "gnu", "bsd"])]
    pub checksum_format: String,

    #[arg(long, value_name = "DIR", help = "Directory to recursively verify.")]
    pub walk: Option<PathBuf>,

    #[arg(long = "list", value_name = "FILE", help = "Text file listing files/directories to verify.")]
    pub file_list: Option<PathBuf>,

    #[arg(long, short, help = "Output result as structured JSON.")]
    pub json: bool,

    #[arg(long, help = "Use relative paths in JSON output.")]
    pub no_abspath: bool,
}

#[derive(Parser, Debug)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommands,
}

#[derive(Subcommand, Debug)]
pub enum TrustCommands {
    #[command(about = "Adds a key to the trust store and keyring.")]
    Add(TrustAddArgs),
    #[command(about = "Shows all keys in the trust store.")]
    List(TrustListArgs),
    #[command(about = "Changes the verification status of a key.")]
    Update(TrustUpdateArgs),
    #[command(about = "Removes a key from the trust store.")]
    Remove(TrustRemoveArgs),
}

#[derive(Parser, Debug)]
pub struct TrustAddArgs {
    #[arg(value_name = "KEYFILE", help = "Path to the public key file to add.")]
    pub keyfile: PathBuf,

    #[arg(long, help = "A unique, memorable name (alias) for this key.")]
    pub name: String,
    
    #[arg(long, help = "Signer organization (optional).")]
    pub org: Option<String>,

    #[arg(long, help = "User or entity adding this key to the store.")]
    pub added_by: String,
    
    #[arg(long, help = "Overwrite an existing key alias in the keyring.")]
    pub force: bool,
}

#[derive(Parser, Debug)]
pub struct TrustListArgs {
    #[arg(long, help = "Display keys in JSON format.")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct TrustUpdateArgs {
    #[arg(value_name = "FINGERPRINT", help = "The fingerprint of the key to update.")]
    pub fingerprint: String,

    #[arg(long, value_parser = ["pending", "verified", "revoked", "compromised"], help = "New verification status.")]
    pub status: String,

    #[arg(long, help = "User or entity updating the key's status.")]
    pub updated_by: String,

    #[arg(long, help = "Optional notes for this status update.")]
    pub notes: Option<String>,
}

#[derive(Parser, Debug)]
pub struct TrustRemoveArgs {
    #[arg(value_name = "FINGERPRINT", help = "The fingerprint of the key to remove.")]
    pub fingerprint: String,
}

#[derive(Parser, Debug)]
pub struct ConfigureArgs {
    #[arg(long, value_name = "PATH", help = "Set the default private key path for signing.")]
    pub private_key_path: Option<PathBuf>,

    #[arg(long, value_name = "IDENTITY", help = "Set the default signer identity (e.g., 'Name <email@host.com>').")]
    pub signer_identity: Option<String>,

    #[arg(long, value_name = "PATH", help = "Set the default public key keyring path.")]
    pub keyring_path: Option<PathBuf>,
    
    #[arg(long, short, help = "Output result as structured JSON.")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct CleanArgs {
    #[arg(value_name = "PATH", help = "Path to the artifact directory to clean.")]
    pub path: Option<PathBuf>,
}