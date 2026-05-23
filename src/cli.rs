use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "heisspunk",
    about = "Hotspot manager via hostapd + built-in DHCP/DNS",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Start(StartArgs),

    Stop,

    Status,

    Show {
        #[command(flatten)]
        args: StartArgs,
    },

    ConfigPath,

    GenerateConfig {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(clap::Args, Debug, Default, Clone)]
pub struct StartArgs {
    #[arg(short, long)]
    pub interface: Option<String>,

    #[arg(short, long)]
    pub ssid: Option<String>,

    #[arg(short, long)]
    pub passphrase: Option<String>,

    #[arg(long, short = 'C')]
    pub channel: Option<u8>,

    #[arg(long)]
    pub hw_mode: Option<String>,

    #[arg(long, value_name = "a|b|c")]
    pub network_class: Option<String>,

    #[arg(short = 'u', long)]
    pub upstream: Option<String>,

    #[arg(long)]
    pub country_code: Option<String>,

    #[arg(long)]
    pub hidden: bool,

    #[arg(long)]
    pub ieee80211ac: bool,
}
