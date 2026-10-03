//! `mcpjump login`.

use crate::app::Deps;
use crate::auth::flow::{self, Login};
use crate::cli::LoginArgs;
use crate::commands::{Console, Context, Reply};
use crate::config::validate::ServerName;
use crate::error::Error;

pub(crate) async fn run(
    args: LoginArgs,
    context: &Context,
    deps: &Deps<'_>,
    console: &mut Console<'_>,
) -> Result<Reply, Error> {
    let name = ServerName::parse(&args.name)?;
    let login = Login {
        context,
        deps,
        name: &name,
        open_browser: !args.no_browser,
    };
    flow::login(login, console).await
}
