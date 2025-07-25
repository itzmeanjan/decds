use vergen_gix::{BuildBuilder, Emitter, GixBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = BuildBuilder::default().build_date(true).build()?;
    let gitcl = GixBuilder::default().sha(true).build()?;

    Emitter::default().add_instructions(&build)?.add_instructions(&gitcl)?.emit()?;
    Ok(())
}
