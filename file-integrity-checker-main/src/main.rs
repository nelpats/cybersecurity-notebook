use std::fs::File;
use std::{env, thread};
use std::path::Path;
use std::time::Duration;
use sha2::{Sha256, Digest};
use tokio::{fs, io};
use std::collections::HashMap;
use std::process::exit;

fn help() {
    println!("Usage: ./integrity_checker <DIRECTORY>");
}

async fn get_file_content(file_path: &Path) -> io::Result<Vec<u8>> {
    if file_path.is_file() {
        Ok(fs::read(file_path).await?)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Provided path is not a file",
        ))
    }
}

async fn on_file_modified() {
    println!("A file got tampered with!!");
    exit(1);
}

async fn integrity_routine(files: &mut HashMap<String, String>, path: &Path) {
    let duration = Duration::from_secs(10);


    loop {
        tokio::time::sleep(duration).await;
        println!("Performing integrity check...");

        let mut entries = fs::read_dir(path).await.expect("Error reading directory");

        while let Some(entry) = entries.next_entry().await.expect("Expecting directory") {
            let file_path = entry.path();
            println!("File path: {:?}", file_path);
            let file_content = get_file_content(&file_path).await.unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&file_content);
            let digest = format!("{:x}", hasher.finalize());

            println!("Hash for the file {}: {}", entry.path().display(), digest);
            files
                .entry(file_path.to_string_lossy().to_string())
                .or_insert(digest.clone());

            if files.get(file_path.to_string_lossy().as_ref()).expect("hash digest") != &digest {
                on_file_modified().await;

            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let path: Option<&Path> = parse_arguments(&args);
    let mut files: HashMap<String, String> = HashMap::new();

    match path {
        Some(path) => {
            integrity_routine(&mut files, path).await;
        }
        None => {}
    };
}

fn parse_arguments(args: &Vec<String>) -> Option<&Path> {
    let directory: Option<&Path> = match args.len() {
        2 => {
            let path = Path::new(&args[1]);
            if path.exists() {
                println!("Looking for '{}'", args[1]);
                Some(path)
            } else {
                eprintln!("Path does not exist: '{}'", args[1]);
                None
            }
        }
        _ => {
            help();
            None
        },
    };

    directory
}
