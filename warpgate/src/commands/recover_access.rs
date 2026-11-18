use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set};
use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::CredentialKind;
use warpgate_common::{GlobalParams, Secret, User as UserConfig, UserPasswordCredential};
use warpgate_core::Services;
use warpgate_db_entities::{PasswordCredential, User};

use crate::commands::common::assert_interactive_terminal;
use crate::config::load_config;

pub async fn command(params: &GlobalParams, username: Option<&String>) -> Result<()> {
    assert_interactive_terminal();

    let config = load_config(params, true)?;
    let services = Services::new(config.clone(), None, params.clone()).await?;
    let keys_path = config.store.ssh.keys_path(params);
    warpgate_protocol_ssh::ensure_host_keys(&services.db, &keys_path).await?;
    warpgate_protocol_ssh::ensure_client_keys(&services.db, &keys_path).await?;

    let theme = ColorfulTheme::default();
    let db = &services.db;

    let users = User::Entity::find()
        .order_by_asc(User::Column::Username)
        .all(db)
        .await?;

    let users: Result<Vec<UserConfig>, _> = users
        .into_iter()
        .map(std::convert::TryInto::try_into)
        .collect();
    let mut users = users?;
    let usernames = users.iter().map(|x| x.username.clone()).collect::<Vec<_>>();

    let user = match username {
        Some(username) => users
            .iter_mut()
            .find(|x| x.username.to_lowercase() == username.to_lowercase())
            .ok_or_else(|| anyhow::anyhow!("User not found"))?,
        None =>
        {
            #[allow(clippy::indexing_slicing)]
            &mut users[dialoguer::Select::with_theme(&theme)
                .with_prompt("Select a user to recover access for")
                .items(&usernames)
                .default(0)
                .interact()?]
        }
    };

    // A local password is never checked for a user whose LDAP server signs
    // them in, and recovering access is often needed precisely because that
    // server is unreachable — so such a user is unlinked from it.
    let ldap_server = match User::Entity::find_by_id(user.id).one(db).await? {
        Some(model) => model.ldap_password_server(db).await?,
        None => None,
    };

    let password = Secret::new(
        dialoguer::Password::with_theme(&theme)
            .with_prompt(format!("New password for {}", user.username))
            .interact()?,
    );

    let prompt = match &ldap_server {
        Some(server) => format!(
            "This tool will add a new password for the user, set their HTTP auth policy to only require a password, and unlink them from the LDAP server {} that signs them in now. Continue?",
            server.name
        ),
        None => "This tool will add a new password for the user and set their HTTP auth policy to only require a password. Continue?".to_owned(),
    };
    if !dialoguer::Confirm::with_theme(&theme)
        .default(true)
        .with_prompt(prompt)
        .interact()?
    {
        std::process::exit(0);
    }

    PasswordCredential::ActiveModel {
        user_id: Set(user.id),
        id: Set(Uuid::new_v4()),
        ..UserPasswordCredential::from_password(&password).into()
    }
    .insert(db)
    .await?;

    user.credential_policy
        .get_or_insert_with(Default::default)
        .http = Some(vec![CredentialKind::Password]);

    let mut update = User::ActiveModel {
        id: Set(user.id),
        credential_policy: Set(serde_json::to_value(Some(&user.credential_policy))?),
        ..Default::default()
    };
    if ldap_server.is_some() {
        update.ldap_server_id = Set(None);
        update.ldap_object_uuid = Set(None);
    }
    update.update(db).await?;

    if let Some(server) = &ldap_server {
        info!(
            "Unlinked {} from the LDAP server {}; link them again from the admin UI once it is reachable",
            user.username, server.name
        );
    }

    info!("All done. You can now log in");

    Ok(())
}
