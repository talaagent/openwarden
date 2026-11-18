//! Bakes the git revision, dirty flag, build date and target into
//! `ow --version --verbose`.

fn main() {
    bpaf_kit_build::emit();
}
