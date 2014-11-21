use std::io::Command;
use std::io::fs::PathExtensions;

pub fn rundrcov(cmd:&[&str]) {
	let rioroot = Path::new(&"C:\\dynamorio-package\\");
	let mut drrun = rioroot.clone();
	drrun.push(&"bin32\\drrun.exe");
	let mut drcov = rioroot.clone();
	drcov.push(&"tools\\lib32\\release\\drcov.dll");

	let mut command = Command::new(drrun);
	let mut commandarg = command.arg("-root").arg(rioroot)
			.arg("-c").arg(drcov)
			.arg("--").args(cmd);

	let mut process = match commandarg.spawn(){
  		Ok(p) => p,
  		Err(e) => panic!("failed to execute process: {}", e),
	};

	let output = process.stdout
		.as_mut().unwrap()
		.read_to_string().unwrap();

	println!("{}",output);
}