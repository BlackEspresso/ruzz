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
mod murmur;
mod readrcov;
mod runrio;

struct AppSettings<'a> {
	dynamorio_root:	String,
	output_file:	String,
	input_dir:		String,
	statistic_file:	String,
	verbose:		bool,
	help:			bool,
	app_args:		&'a [&'a str]
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

	let aut = ["C:\\tmp\\7za.exe","l","test.zip"]; // app under test
	settings.app_args = aut.slice(0,aut.len());

	let mut map:HashMap<u32,u16> = HashMap::new();
	let mut i:int = 0;

	let mut inputpath = os::getcwd();
	inputpath.push(settings.input_dir.clone());

	let o_path = Path::new(&settings.output_file);

	loop{
		write_new_file(&o_path,&inputpath);
		let newBlocksCount = fuzzing_step(&settings,&mut map);
		i+=1;

		if i>1 && newBlocksCount>0{
			let mut newpath = inputpath.clone();
			newpath.push(time::precise_time_s().to_string());
			fs::copy(&o_path,&newpath);
		}
	}
}

// 1. pick old file
// 2. mutate old file
// 3. write new file
fn write_new_file(output_file:&Path, inputDir:&Path){

	let file = pick_file_from_dir(inputDir);
	println!("picking {}",file.display());

	let mut content = File::open(&file).read_to_end().unwrap();
	println!("mutating...");
	mutate(&mut content);
	
	println!("creating new file")
	let mut ofile = match File::create(output_file){
		Err(e) => panic!(e),
		Ok(f) => f,
	};

	match ofile.write(content.as_slice()){
		Err(e) => panic!(e),
		_ =>{}
	};
}

fn mutate(filecontent:&mut Vec<u8>){
	let len = filecontent.len();
	let mut rng = task_rng();
	let n = rng.gen_range(0,len);
	let m = rng.gen_range(0,7);

	filecontent[n] = filecontent[n]^m;
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

fn fuzzing_step(settings:&AppSettings, map:&mut HashMap<u32,u16>)->uint {
	// run drcov
	println!("run drcov");
	runrio::rundrcov(settings.app_args);
	println!("find drcovlog file");
	let inputpath = find_file_by_filter(".",".proc.log").unwrap();
	
	// read file and update hashmap
	println!("read file and update hashmap");
	let maplen = map.len();
	readrcov::convert(&inputpath,map);
	// any more blocks ?
	let new_blocks:uint = map.len()-maplen;
	println!("found {} more blocks",new_blocks);
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
        optflag("v","verbose", "output verbose")
	];

	let mut settings = AppSettings {
		dynamorio_root :"c:\\dynamorio-package\\".to_string(),
		output_file: 	"".to_string(),
		input_dir:		"".to_string(),
		statistic_file:	"".to_string(),
		verbose:		false,
		help:			false,
		app_args:		[]
	};

	// check if arguments, if not => panic
	let matches = match getopts(args.tail(),opts){
		Ok(m)=>{m}
		Err(f)=>{panic!(f.to_string())}
	};

	if matches.opt_present("h") {
		print_usage(program.as_slice(),opts);
		settings.help = true;
		return settings;
	}

	if matches.opt_present("v") {
		settings.verbose = true;
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