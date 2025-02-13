use anyhow::{Context, Result};
use app::config::AppConfig;
use app::App as AppTrait;
use clap::{arg, value_parser, Arg, ArgMatches, Command};
use payjoin::bitcoin::amount::ParseAmountError;
use payjoin::bitcoin::{Amount, FeeRate};
use url::Url;

mod app;
mod db;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let matches = cli();
    let config = AppConfig::new(&matches)?;
    let app: Box<dyn AppTrait> = {
        #[cfg(feature = "v2")]
        {
            Box::new(crate::app::v2::App::new(config)?)
        }
        #[cfg(all(feature = "v1", not(feature = "v2")))]
        {
            Box::new(crate::app::v1::App::new(config)?)
        }
        #[cfg(not(any(feature = "v1", feature = "v2")))]
        compile_error!("Either feature \"v1\" or \"v2\" must be enabled");
    };

    match matches.subcommand() {
        Some(("send", sub_matches)) => {
            let bip21 = sub_matches.get_one::<String>("BIP21").context("Missing BIP21 argument")?;
            let fee_rate = sub_matches
                .get_one::<FeeRate>("fee_rate")
                .context("Missing --fee-rate argument")?;
            app.send_payjoin(bip21, *fee_rate).await?;
        }
        Some(("receive", sub_matches)) => {
            let amount =
                sub_matches.get_one::<Amount>("AMOUNT").context("Missing AMOUNT argument")?;
            app.receive_payjoin(*amount).await?;
        }
        #[cfg(feature = "v2")]
        Some(("resume", _)) => {
            println!("resume");
            app.resume_payjoins().await?;
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }

    Ok(())
}

fn cli() -> ArgMatches {
    let mut cmd = Command::new("payjoin")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Payjoin - bitcoin scaling, savings, and privacy by default")
        .arg(
            Arg::new("rpchost")
                .long("rpchost")
                .short('r')
                .num_args(1)
                .help("The port of the bitcoin node")
                .value_parser(value_parser!(Url)),
        )
        .arg(
            Arg::new("cookie_file")
                .long("cookie-file")
                .short('c')
                .num_args(1)
                .help("Path to the cookie file of the bitcoin node"),
        )
        .arg(
            Arg::new("rpcuser")
                .long("rpcuser")
                .num_args(1)
                .help("The username for the bitcoin node"),
        )
        .arg(
            Arg::new("rpcpassword")
                .long("rpcpassword")
                .num_args(1)
                .help("The password for the bitcoin node"),
        )
        .arg(Arg::new("db_path").short('d').long("db-path").help("Sets a custom database path"))
        .subcommand_required(true);

    // Conditional arguments based on features
    #[cfg(feature = "v2")]
    {
        cmd = cmd.arg(
            Arg::new("ohttp_relay")
                .long("ohttp-relay")
                .help("The ohttp relay url")
                .value_parser(value_parser!(Url)),
        );
    }

    cmd = cmd.subcommand(
        Command::new("send")
            .arg_required_else_help(true)
            .arg(arg!(<BIP21> "The `bitcoin:...` payjoin uri to send to"))
            .arg_required_else_help(true)
            .arg(
                Arg::new("fee_rate")
                    .long("fee-rate")
                    .value_name("FEE_SAT_PER_VB")
                    .help("Fee rate in sat/vB")
                    .value_parser(parse_fee_rate_in_sat_per_vb),
            ),
    );

    let mut receive_cmd = Command::new("receive")
        .arg_required_else_help(true)
        .arg(arg!(<AMOUNT> "The amount to receive in satoshis").value_parser(parse_amount_in_sat))
        .arg_required_else_help(true);

    #[cfg(feature = "v2")]
    let mut cmd = cmd.subcommand(Command::new("resume"));

    // Conditional arguments based on features for the receive subcommand
    receive_cmd = receive_cmd.arg(
        Arg::new("max_fee_rate")
            .long("max-fee-rate")
            .num_args(1)
            .help("The maximum effective fee rate the receiver is willing to pay (in sat/vB)")
            .value_parser(parse_fee_rate_in_sat_per_vb),
    );
    #[cfg(not(feature = "v2"))]
    {
        receive_cmd = receive_cmd.arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .num_args(1)
                .help("The local port to listen on"),
        );
        receive_cmd = receive_cmd.arg(
            Arg::new("pj_endpoint")
                .long("pj-endpoint")
                .short('e')
                .num_args(1)
                .help("The `pj=` endpoint to receive the payjoin request")
                .value_parser(value_parser!(Url)),
        );
    }

    #[cfg(feature = "v2")]
    {
        receive_cmd = receive_cmd.arg(
            Arg::new("pj_directory")
                .long("pj-directory")
                .num_args(1)
                .help("The directory to store payjoin requests")
                .value_parser(value_parser!(Url)),
        );
        receive_cmd = receive_cmd
            .arg(Arg::new("ohttp_keys").long("ohttp-keys").help("The ohttp key config file path"));
    }

    cmd = cmd.subcommand(receive_cmd);
    cmd.get_matches()
}

fn parse_amount_in_sat(s: &str) -> Result<Amount, ParseAmountError> {
    Amount::from_str_in(s, payjoin::bitcoin::Denomination::Satoshi)
}

fn parse_fee_rate_in_sat_per_vb(s: &str) -> Result<FeeRate, std::num::ParseFloatError> {
    let fee_rate_sat_per_vb: f32 = s.parse()?;
    let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
    Ok(FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64))
}
