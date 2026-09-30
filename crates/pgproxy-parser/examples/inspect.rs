fn main() {
    for sql in std::env::args().skip(1) {
        let parsed =
            pgproxy_parser::parse(&sql, Default::default(), 65536, 4 * 1024 * 1024).expect("SQL");
        println!("{sql}: {}", parsed.tree());
    }
}
