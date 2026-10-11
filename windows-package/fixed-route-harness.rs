#[path = "../src-tauri/src/enhance/claude_guard.rs"]
mod claude_guard;
#[path = "../src-tauri/src/enhance/local_access.rs"]
mod local_access;

fn main() {
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).expect("stdin");
    let mut config = serde_yaml_ng::from_str(&text).expect("input YAML");
    claude_guard::enforce(&mut config);
    print!("{}", serde_yaml_ng::to_string(&config).expect("output YAML"));
}
