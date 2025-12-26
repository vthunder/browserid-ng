//! /.well-known/browserid endpoint

use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use browserid_core::discovery::SupportDocument;

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

/// GET /.well-known/browserid
pub async fn get_support_document<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
) -> Json<SupportDocument>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let doc = SupportDocument::new(state.keypair.public_key())
        .with_authentication("/auth")
        .with_provisioning("/provision");

    Json(doc)
}
