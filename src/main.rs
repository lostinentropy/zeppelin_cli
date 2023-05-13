use clap::Parser;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{ExitCode, Termination};
use std::thread;
use std::time::Duration;
use zeppelin_core::cipher::CryptSettings;
use zeppelin_core::container::{create_container, read_container};
use zeppelin_core::progress::{self, Progress};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to file to encrypt
    file: PathBuf,
    #[clap(long, short, value_parser)]
    /// File used in combination with key
    key_file: Option<PathBuf>,
    #[clap(long, short = 'l', value_parser)]
    /// Encryption level
    level: Option<String>,
    #[clap(long, value_parser)]
    /// Memory scaling factor of encryption
    s_cost: Option<u64>,
    #[clap(long, value_parser)]
    /// Time scaling factor of encryption
    t_cost: Option<u64>,
    /// Output file name
    output: Option<PathBuf>,
    #[clap(short, long, value_parser)]
    /// Decrypt instead of encrypt
    decrypt: bool,
    #[clap(short = 'r', value_parser)]
    /// Erase original file
    erase: bool,
}

/// Returns stdout to a clean state.
/// Should be called before exit to not mess up future terminal output.
fn clean_terminal() -> std::io::Result<()> {
    let out = console::Term::stderr();
    out.clear_line()?;
    out.flush()?; // Probably redundant
    out.show_cursor()?;
    Ok(())
}

/// Enum returned by the main function. Represents the state of main on exit.
enum MainStatus {
    Ok,
    Err(String),
    FileNotFound(PathBuf),
}

impl Termination for MainStatus {
    fn report(self) -> ExitCode {
        clean_terminal().unwrap();
        match self {
            MainStatus::Ok => {
                eprintln!("Operation successful!");
                ExitCode::from(0)
            }
            MainStatus::Err(reason) => {
                eprintln!("{}", reason);
                ExitCode::from(1)
            }
            MainStatus::FileNotFound(file) => {
                eprintln!("File {:?} not found!", file);
                ExitCode::from(2)
            }
        }
    }
}

fn append_extension(path: &mut PathBuf, ext: impl AsRef<std::ffi::OsStr>) {
    let mut os_string: std::ffi::OsString = path.clone().into();
    os_string.push(".");
    os_string.push(ext.as_ref());
    *path = os_string.into()
}

// fn run_thread<R: Read + Seek>(
//     source: &mut R,
//     output: Option<PathBuf>,
//     key: String,
//     decrypt: bool,
//     progress: Progress,
// ) -> MainStatus {
//     let res = if decrypt {
//         read_container(source, dest, key, progress)
//     } else {
//         create_container(source, dest, key, settings, progress)
//     };

//     MainStatus::Ok
// }

fn main() -> MainStatus {
    let args = Args::parse();

    // Check if given file exists
    let file = args.file.clone();
    if !file.exists() {
        return MainStatus::FileNotFound(file);
    }

    // Check if file extension indicates that file should be decrypted
    let mut decrypt = if let Some(extension) = file.extension() {
        extension == "zep"
    } else {
        false
    };

    // Let user override the automatically detected value
    if args.decrypt {
        decrypt = true
    }

    // Try to open file
    let file = if let Ok(inner) = fs::File::open(file) {
        inner
    } else {
        return MainStatus::Err(String::from("Unable to open file"));
    };
    let mut file = io::BufReader::new(file);

    // Choose appropriate name for output file
    let output_path = if let Some(path) = args.output {
        path
    } else {
        let mut tmp = args.file.clone();
        if decrypt {
            if let Some(ext) = tmp.extension() {
                if ext == "zep" {
                    tmp.set_extension("");
                    tmp
                } else {
                    append_extension(&mut tmp, "unzep");
                    tmp
                }
            } else {
                tmp.set_extension("unzep");
                tmp
            }
        } else {
            append_extension(&mut tmp, "zep");
            tmp
        }
    };

    // Sanity check, to make sure we don't write to file we are reading
    // `output_path` should have been chosen in a way to be distinct from `file`
    // but better safe than sorry.
    if output_path == args.file {
        return MainStatus::Err("Input and output file should be different".to_string());
    }

    if output_path.exists() {
        if let Ok(confirmation) = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Are you sure you want to override {:?}",
                output_path
            ))
            .interact()
        {
            if !confirmation {
                return MainStatus::Err("Operation cancelled!".to_string());
            }
        } else {
            return MainStatus::Err("Unable to get user prompt!".to_string());
        }
    }

    // Allocate output file
    let output = if let Ok(file) = fs::File::create(&output_path) {
        file
    } else {
        return MainStatus::Err(format!("Could not access {:?}", output_path));
    };
    let mut output = io::BufWriter::new(output);

    // Request password from user
    let key = if let Ok(password) = dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
    {
        password
    } else {
        return MainStatus::Err(String::from("Unable to read password!"));
    };

    // Start the encryption/decryption thread
    let progress = Progress::new();
    progress.set_state("Starting".to_string());
    let thread = if decrypt {
        // Decrypt
        thread::spawn({
            let thread_progress = progress.clone();
            move || {
                if let Ok(decrypted) =
                    read_container(&mut file, &mut output, key, Some(thread_progress))
                {
                    if decrypted {
                        MainStatus::Ok
                    } else {
                        MainStatus::Err("Wrong password!".to_string())
                    }
                } else {
                    MainStatus::Err("Container invalid!".to_string())
                }
            }
        })
    } else {
        // Encrypt
        let choices = vec!["Weak", "Default", "Strong", "Custom"];

        let choice = dialoguer::Select::new()
            .with_prompt("Select an encryption level")
            .items(&choices)
            .default(1)
            .interact()
            .unwrap();

        let settings = match choice {
            0 => CryptSettings::default_for_testing(),
            1 => CryptSettings::default(),
            2 => CryptSettings {
                s_cost: 468750 * 10,
                t_cost: 3,
                step_delta: 4,
            },
            3 => {
                let s_cost = if let Ok(val) = dialoguer::Input::<usize>::new()
                    .with_prompt(format!(
                        "s_cost (default: {})",
                        CryptSettings::default().s_cost
                    ))
                    .interact()
                {
                    val
                } else {
                    return MainStatus::Err("Unable to get user prompt!".to_string());
                };
                let t_cost = if let Ok(val) = dialoguer::Input::<usize>::new()
                    .with_prompt(format!(
                        "t_cost (default: {})",
                        CryptSettings::default().t_cost
                    ))
                    .interact()
                {
                    val
                } else {
                    return MainStatus::Err("Unable to get user prompt!".to_string());
                };
                let step_delta = if let Ok(val) = dialoguer::Input::<usize>::new()
                    .with_prompt(format!(
                        "step_delta (default: {})",
                        CryptSettings::default().step_delta
                    ))
                    .interact()
                {
                    val
                } else {
                    return MainStatus::Err("Unable to get user prompt!".to_string());
                };
                CryptSettings {
                    s_cost,
                    t_cost,
                    step_delta,
                }
            }
            _ => {
                return MainStatus::Err("Invalid Choice".to_string());
            }
        };

        thread::spawn({
            let thread_progress = progress.clone();
            move || {
                if create_container(&mut file, &mut output, key, settings, Some(thread_progress))
                    .is_ok()
                {
                    MainStatus::Ok
                } else {
                    MainStatus::Err("Unable to create container!".to_string())
                }
            }
        })
    };

    // Monitor the progress of the thread; printing a progress bar
    let mut out = console::Term::buffered_stderr();
    out.hide_cursor().unwrap();
    while !thread.is_finished() {
        let (h, w) = out.size();
        progress::print_progress_bar(&mut out, h, w, progress.clone()).unwrap();
        // Refresh progress bar ~ 10 times / second
        thread::sleep(Duration::from_millis(1000 / 10));
    }

    if let Ok(thread_status) = thread.join() {
        thread_status
    } else {
        MainStatus::Err(String::from("Unable to join thread!"))
    }
}
