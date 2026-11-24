use anyhow::Result;
use tracing::{info, warn};
use warpgate_common::GlobalParams;
use warpgate_core::db::{AccessMigrationPreview, connect_to_db, preview_access_migration};

use crate::config::load_config;

/// Print what the access-control migration (m00098) would do to the configured database,
/// without running it: what it migrates, and what it leaves for an administrator to review.
/// Run with the new binary against the database as the previous release left it, before
/// upgrading. Writes nothing to the data.
pub async fn command(params: &GlobalParams) -> Result<()> {
    let config = load_config(params, true)?;
    let connection = connect_to_db(&config, params).await?;

    match preview_access_migration(&connection).await? {
        AccessMigrationPreview::Report(report) => {
            println!("{report}");
        }
        AccessMigrationPreview::EarlierMigrationsPending => {
            warn!(
                "This database is older than the release before access control: upgrade to that release first, or run the preview with it."
            );
        }
        AccessMigrationPreview::AlreadyApplied => {
            info!(
                "The access-control migration has already run. Its report is in the admin UI, Access control, Migration review."
            );
        }
    }
    Ok(())
}
