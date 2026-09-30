// Negative fixture: no crypto.

fn add(a: u64, b: u64) -> u64 {
    a + b
}

fn main() {
    println!("2 + 3 = {}", add(2, 3));
}
