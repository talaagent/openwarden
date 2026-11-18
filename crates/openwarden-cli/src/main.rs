//! `ow`: a fast, `bw`-compatible command-line client for Bitwarden and
//! Vaultwarden, built on the openwarden library.

// A binary: std is the platform.
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]
// The doc comments on the command types are `--help` text, not rustdoc.
#![allow(clippy::doc_markdown)]

mod commands;
mod error;
mod items;
mod output;
mod state;
mod wire;

use std::path::PathBuf;
use std::process::ExitCode;

use bpaf::Bpaf;
use bpaf_kit::Cli;
use bpaf_kit::report::report;
use bpaf_kit::suggest::{UnknownValue, parse_choice};

/// What `list` lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListObject {
    Items,
    Folders,
}

/// What `get` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetObject {
    Item,
    Password,
    Username,
    Totp,
    Notes,
    Uri,
}

/// The object `create`, `edit` and `delete` work on: items only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteObject {
    Item,
}

#[allow(clippy::needless_pass_by_value)] // bpaf's `parse` hands over the String
fn list_object(value: String) -> Result<ListObject, UnknownValue> {
    parse_choice(
        "object",
        &value,
        &[
            ("items", ListObject::Items),
            ("folders", ListObject::Folders),
        ],
    )
}

#[allow(clippy::needless_pass_by_value)] // bpaf's `parse` hands over the String
fn get_object(value: String) -> Result<GetObject, UnknownValue> {
    parse_choice(
        "object",
        &value,
        &[
            ("item", GetObject::Item),
            ("password", GetObject::Password),
            ("username", GetObject::Username),
            ("totp", GetObject::Totp),
            ("notes", GetObject::Notes),
            ("uri", GetObject::Uri),
        ],
    )
}

#[allow(clippy::needless_pass_by_value)] // bpaf's `parse` hands over the String
fn write_object(value: String) -> Result<WriteObject, UnknownValue> {
    parse_choice("object", &value, &[("item", WriteObject::Item)])
}

/// Options every command takes.
#[derive(Debug, Clone, Bpaf)]
#[allow(clippy::struct_excessive_bools)] // flags
struct Common {
    /// Indent JSON output.
    #[bpaf(long("pretty"))]
    pretty: bool,
    /// Print only the value: the session key, for `login` and `unlock`.
    #[bpaf(long("raw"))]
    raw: bool,
    /// Print nothing but errors.
    #[bpaf(long("quiet"))]
    quiet: bool,
    /// Leave secrets out of item JSON (passwords, TOTP seeds, notes, field
    /// values, password history, card, identity and SSH key values), and
    /// refuse `get password|totp|notes`. For a caller that may see an
    /// item's shape but not its secrets. Set OW_REDACT (to anything) to
    /// turn it on for every command.
    #[bpaf(long("redact"), env("OW_REDACT"))]
    redact: bool,
    /// Never prompt (ow never does; accepted for bw compatibility).
    #[bpaf(long("nointeraction"))]
    #[allow(dead_code)] // accepted and ignored
    nointeraction: bool,
    /// Refused: a session key on the command line is visible to other
    /// processes. Set BW_SESSION instead.
    #[bpaf(long("session"), argument("KEY"), hide)]
    session: Option<String>,
}

/// Where a master password comes from: never the command line.
#[derive(Debug, Clone, Bpaf)]
struct PasswordSource {
    /// Read the master password from this environment variable.
    #[bpaf(long("passwordenv"), argument("VAR"))]
    env: Option<String>,
    /// Read the master password from the first line of this file.
    #[bpaf(long("passwordfile"), argument("FILE"))]
    file: Option<PathBuf>,
}

#[derive(Debug, Clone, Bpaf, Cli)]
#[bpaf(options)]
/// A fast, bw-compatible Bitwarden and Vaultwarden CLI. State lives in
/// $OPENWARDEN_APPDATA_DIR (else $BITWARDENCLI_APPDATA_DIR); the vault cache
/// is encrypted, and the session key comes from BW_SESSION.
enum Command {
    /// Show or set the server: `config server [URL]`.
    #[bpaf(command)]
    Config {
        #[bpaf(external(common))]
        common: Common,
        /// `server`.
        #[bpaf(positional("SETTING"))]
        setting: String,
        /// The server's base URL (Bitwarden's US cloud if never set).
        #[bpaf(positional("VALUE"))]
        value: Option<String>,
    },
    /// Log in with the master password (and unlock), or with an API key
    /// from BW_CLIENTID and BW_CLIENTSECRET (`--apikey`, then `unlock`).
    #[bpaf(command)]
    Login {
        /// Log in with the personal API key in BW_CLIENTID and
        /// BW_CLIENTSECRET.
        #[bpaf(long("apikey"))]
        apikey: bool,
        #[bpaf(external(password_source))]
        password: PasswordSource,
        #[bpaf(external(common))]
        common: Common,
        /// The account's email.
        #[bpaf(positional("EMAIL"))]
        email: Option<String>,
        /// Refused: pass the password with --passwordenv, --passwordfile or
        /// stdin.
        #[bpaf(positional("PASSWORD"), hide)]
        password_arg: Option<String>,
    },
    /// Unlock the vault with the master password and print a session key.
    #[bpaf(command)]
    Unlock {
        #[bpaf(external(password_source))]
        password: PasswordSource,
        #[bpaf(external(common))]
        common: Common,
        /// Refused: pass the password with --passwordenv, --passwordfile or
        /// stdin.
        #[bpaf(positional("PASSWORD"), hide)]
        password_arg: Option<String>,
    },
    /// Lock the vault: every session key stops working.
    #[bpaf(command)]
    Lock {
        #[bpaf(external(common))]
        common: Common,
    },
    /// Log out: forget the account, its tokens and the vault cache.
    #[bpaf(command)]
    Logout {
        #[bpaf(external(common))]
        common: Common,
    },
    /// Sync the vault, if it changed on the server.
    #[bpaf(command)]
    Sync {
        /// Sync even when the server's revision date hasn't moved.
        #[bpaf(long("force"), short('f'))]
        force: bool,
        /// Print the last sync's time instead.
        #[bpaf(long("last"))]
        last: bool,
        #[bpaf(external(common))]
        common: Common,
    },
    /// Print the server, the account and whether the vault is locked, as
    /// JSON.
    #[bpaf(command)]
    Status {
        #[bpaf(external(common))]
        common: Common,
    },
    /// List items or folders, as JSON.
    #[bpaf(command)]
    List {
        /// Only items whose name, username or a URI contains this text.
        #[bpaf(long("search"), argument("TEXT"))]
        search: Option<String>,
        /// Only items in this folder (`null`: in none).
        #[bpaf(long("folderid"), argument("ID"))]
        folderid: Option<String>,
        /// Only items in this collection (`null`: in none).
        #[bpaf(long("collectionid"), argument("ID"))]
        collectionid: Option<String>,
        /// Only items of this organization (`null`: personal ones).
        #[bpaf(long("organizationid"), argument("ID"))]
        organizationid: Option<String>,
        /// Items in the trash instead.
        #[bpaf(long("trash"))]
        trash: bool,
        #[bpaf(external(common))]
        common: Common,
        /// `items` or `folders`.
        #[bpaf(positional::<String>("OBJECT"), parse(list_object))]
        object: ListObject,
    },
    /// Print an item (JSON) or one of its fields, by id or search text.
    #[bpaf(command)]
    Get {
        #[bpaf(external(common))]
        common: Common,
        /// `item`, `password`, `username`, `totp`, `notes` or `uri`.
        #[bpaf(positional::<String>("OBJECT"), parse(get_object))]
        object: GetObject,
        /// An item id, or text its name, username or a URI contains.
        #[bpaf(positional("ID"))]
        id: String,
    },
    /// Create an item from base64 JSON (`ow encode`) on stdin.
    #[bpaf(command)]
    Create {
        #[bpaf(external(common))]
        common: Common,
        /// `item`.
        #[bpaf(positional::<String>("OBJECT"), parse(write_object))]
        object: WriteObject,
        /// Refused: pipe the encoded JSON on stdin.
        #[bpaf(positional("ENCODED"), hide)]
        encoded: Option<String>,
    },
    /// Edit an item from base64 JSON (`ow encode`) on stdin.
    #[bpaf(command)]
    Edit {
        #[bpaf(external(common))]
        common: Common,
        /// `item`.
        #[bpaf(positional::<String>("OBJECT"), parse(write_object))]
        object: WriteObject,
        /// The item's id.
        #[bpaf(positional("ID"))]
        id: String,
        /// Refused: pipe the encoded JSON on stdin.
        #[bpaf(positional("ENCODED"), hide)]
        encoded: Option<String>,
    },
    /// Move an item to the trash, or delete it for good.
    #[bpaf(command)]
    Delete {
        /// Delete it for good instead of moving it to the trash.
        #[bpaf(long("permanent"), short('p'))]
        permanent: bool,
        #[bpaf(external(common))]
        common: Common,
        /// `item`.
        #[bpaf(positional::<String>("OBJECT"), parse(write_object))]
        object: WriteObject,
        /// The item's id.
        #[bpaf(positional("ID"))]
        id: String,
    },
    /// Base64-encode stdin, for `create` and `edit`.
    #[bpaf(command)]
    Encode {
        #[bpaf(external(common))]
        common: Common,
    },
}

fn main() -> ExitCode {
    let command = Command::cli();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => return report(&error::CliError::Output(err)),
    };
    #[allow(clippy::disallowed_methods)] // the one runtime, in main
    let result = runtime.block_on(commands::run(command));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => report(&err),
    }
}
