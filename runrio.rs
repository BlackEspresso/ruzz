use std::io::Command;
use std::io::fs::PathExtensions;

pub fn rundrcov(cmd:&[&str], with_instrumentation:bool) {
	let rioroot = Path::new(&"C:\\dynamorio-package\\");
	let mut drrun = rioroot.clone();
	drrun.push(&"bin32\\drrun.exe");
	let mut drcov = rioroot.clone();
	drcov.push(&"tools\\lib32\\release\\drcov.dll");

	let mut command :Command;
	let mut commandarg :&mut Command;

	if with_instrumentation {
		command = Command::new(drrun);
		commandarg = command.arg("-root").arg(rioroot)
			.arg("-c").arg(drcov)
			.arg("--").args(cmd);	
	} else {
		command = Command::new(cmd[0]);
		commandarg = command.args(cmd.slice(1,cmd.len()));
	}

	let mut process = match commandarg.spawn(){
  		Ok(p) => p,
  		Err(e) => panic!("failed to execute process: {}", e),
	};

	//let output = process.stdout.as_mut();
		//.read_to_string().unwrap();

	//println!("{}",output);
}