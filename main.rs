#![feature(slicing_syntax)]
#![feature(phase)]
#[phase(plugin)]
extern crate regex_macros;
extern crate regex;
extern crate serialize;
extern crate getopts;
extern crate time;
use getopts::{optopt,optflag,getopts,OptGroup};
use std::os;
use std::io::fs;
use std::io::File;
use std::vec;
use std::collections::HashMap;
use std::rand::{task_rng, Rng};
mod readrcov;
mod runrio;

struct AppSettings<'a> {
	dynamorio_root:	String,
	output_file:	String,
	input_dir:		String,
	statistic_file:	String,
	verbose:		bool,
	help:			bool,
	app_args:		&'a [&'a str],
	benchmark:		bool
}

fn print_usage(program: &str, _opts: &[OptGroup]) {
    println!("Usage: {} [options]", program);    
    println!("r\tdynamorioroot\troot directory of DynamoRIO");
	println!("o\toutput\t\toutput fuzzing file");
	println!("i\tinput\t\tinput directory with example files");
	println!("s\tstatistic\toutput file with statistics");
    println!("h\thelp\t\tprint this help menu");
    println!("v\tverbose\t\toutput verbose");
}

fn main(){
	let args = os::args();
	let mut settings = read_arguments(&args);

	if settings.help {
		return;
	}

	let aut = ["C:\\tmp\\7za.exe","e","-y","test.zip"]; // app under test
	settings.app_args = aut.slice(0,aut.len());

	let mut map:HashMap<u32,u16> = HashMap::new();
	let mut i:int = 0;

	let mut inputpath = os::getcwd().unwrap();
	inputpath.push(settings.input_dir.clone());

	let o_path = Path::new(&settings.output_file);

	let mut start = time::get_time();

	let inputfiles = get_files_in_dir(&inputpath);

	if !settings.benchmark {
		// read previously created files and add to blocks to hashmap
		// this enables pause + resume behaviour
		println!("reading input files");
		for input_file in inputfiles.iter() {
			open_mutate_write(&o_path, input_file, mutator_empty);
			fuzzing_step(&settings,&mut map, true);
		}
	}
	
	println!("start fuzzing...");
	loop{
		let actionnumber = i % 4;

		let input_file = pick_file_from_dir(&inputpath);

		if !settings.benchmark {
			match actionnumber {
				0 => open_mutate_write(&o_path, &input_file, mutator_add_random_bit),
				1 => open_mutate_write(&o_path, &input_file, mutator_xor_random_bit),
				2 => open_mutate_write(&o_path, &input_file, mutator_enable_3random_bits),
				3 => open_mutate_write(&o_path, &input_file, mutator_xor_broken_random_bit),
				_ => panic!("not handled action")
			}
		}

		let newBlocksCount = fuzzing_step(&settings,&mut map,!settings.benchmark);
		i += 1;

		if i>1 && newBlocksCount>0 && !settings.benchmark {
			let mut newpath = inputpath.clone();
			let now = time::get_time();
			newpath.push(now.sec.to_string()+"_"+now.nsec.to_string());
			fs::copy(&o_path,&newpath);
		}

		if i%100 == 0 {
			let now = time::get_time();
			let diff = (now.sec-start.sec);
			println!("{} seconds for 100 runs => {} runs per second", diff, 100_f32/diff as f32);
			start = now;
		}
	}
}

// 1. open input file
// 2. mutate with mutator
// 3. write output file
fn open_mutate_write(output_file:&Path, input_file:&Path, mutator:fn(&mut Vec<u8>)){
	let mut content = File::open(input_file).read_to_end().unwrap();
	// run mutator function
	mutator(&mut content);
	
	let mut ofile = match File::create(output_file){
		Err(e) => panic!(e),
		Ok(f) => f,
	};

	match ofile.write(content.as_slice()){
		Err(e) => panic!(e),
		_ =>{}
	};
}

fn mutator_empty(filecontent:&mut Vec<u8>){

}

fn mutator_add_random_bit(filecontent:&mut Vec<u8>){
	let len = filecontent.len();
	let mut rng = task_rng();
	let pos = rng.gen_range(0,len);
	let el:u8 = rng.gen_range(0,255);

	filecontent.insert(pos,el);
}


fn mutator_xor_broken_random_bit(filecontent:&mut Vec<u8>){
	let len = filecontent.len();
	let mut rng = task_rng();
	let n = rng.gen_range(0,len);
	let m = rng.gen_range(0,7);

	filecontent[n] = filecontent[n]^m;
}

fn mutator_xor_random_bit(filecontent:&mut Vec<u8>){
	let len = filecontent.len();
	let mut rng = task_rng();
	let n = rng.gen_range(0,len);
	let m = 1 << rng.gen_range(0,7);

	filecontent[n] = filecontent[n]^m;
}

fn mutator_enable_3random_bits(filecontent:&mut Vec<u8>){
	let len = filecontent.len();
	let mut rng = task_rng();
	let n = rng.gen_range(0,len);
	let m = 0b111 << rng.gen_range(0,5);

	filecontent[n] = filecontent[n]|m;
}

fn get_files_in_dir(dir:&Path) -> Vec<Path>{
	let filenames = fs::readdir(&Path::new(dir)).unwrap();
	let mut files:Vec<Path> = Vec::new();

	for f in filenames.iter() {
		let mut filepath = dir.clone();
		filepath.push(f);
		files.push(filepath.clone());
	}
	
	files
}

fn pick_file_from_dir(dir:&Path) -> Path{
	let files = fs::readdir(&Path::new(dir)).unwrap();
	let file_count = files.len();
	let mut rng = task_rng();
	let n = rng.gen_range(0,file_count);

	let mut filepath = dir.clone();
	filepath.push(files[n].clone());

	filepath
}

fn fuzzing_step(settings:&AppSettings, map:&mut HashMap<u32,u16>, instrumentation:bool)->uint {
	// run drcov
	runrio::rundrcov(settings.app_args,instrumentation);
	let inputpath = find_file_by_filter(".",".proc.log").unwrap();
	// read file and update hashmap
	let maplen = map.len();
	readrcov::convert(&inputpath,map);
	// any new code blocks ?
	let new_blocks:uint = map.len()-maplen;
	fs::unlink(&inputpath);

	new_blocks
}

fn find_file_by_filter(path:&str,filter:&str) -> Option<Path>{
	let paths = fs::readdir(&Path::new(path)).unwrap();

    for path in paths.iter() {
        let filename = path.filename_str().unwrap();
        
        if filename.contains(filter){
        	return Some(path.clone());
        }
    }
    None
}

fn read_arguments(args:&Vec<String>)->AppSettings{
	let program = args[0].clone();

	let opts = [
		optopt("r", "dynamorioroot", "root directory of DynamoRIO",""),
		optopt("o", "output", "output fuzzing file",""),
		optopt("i", "input", "input directory with example files",""),
		optopt("s", "statistic", "output file with statistics",""),
        optflag("h","help", "print this help menu"),
        optflag("v","verbose", "output verbose"),
        optflag("b","benachmark", "benachmark target")
	];

	let mut settings = AppSettings {
		dynamorio_root :"c:\\dynamorio-package\\".to_string(),
		output_file: 	"".to_string(),
		input_dir:		"".to_string(),
		statistic_file:	"".to_string(),
		verbose:		false,
		help:			false,
		app_args:		[].as_slice(),
		benchmark:		false
	};

	// check if arguments, if not => panic
	let matches = match getopts(args.tail(),opts.as_slice()){
		Ok(m)=>{m}
		Err(f)=>{panic!(f.to_string())}
	};

	if matches.opt_present("h") {
		print_usage(program.as_slice(),opts.as_slice());
		settings.help = true;
		return settings;
	}

	if matches.opt_present("v") {
		settings.verbose = true;
	}

	if matches.opt_present("b") {
		settings.benchmark = true;
	}

	let output = matches.opt_str("o");
	if output != None {
		settings.output_file = output.unwrap().to_string();	
	}
	
	let input = matches.opt_str("i");
	if input != None {
		settings.input_dir = input.unwrap().to_string();	
	}

	settings
}
