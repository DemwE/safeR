use rand::Rng;

pub fn generator() -> String
{
    let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let mut rng = rand::thread_rng();
    let available_characters: String = characters.to_string();

    let length = 32;

    let key: String = (0..length)
        .map(|_| available_characters.chars().nth(rng.gen_range(0..available_characters.len())).unwrap())
        .collect();

    key
}