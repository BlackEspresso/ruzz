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
use std::num::Int;
use std::collections::{HashMap,HashSet};
use std::rand::{task_rng, Rng};
mod readrcov;
mod runrio;

struct AppSettings<'a> {
	dynamorio_root:	String,
	output_file:	Path,
	input_dir:		Path,
	statistic_file:	String,
	verbose:		bool,
	help:			bool,
	app_args:		&'a [&'a str],
	benchmark:		bool,
	module_name: 	String,
	start_time:		time::Timespec,
	iter_count:		u64
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

	let aut = ["C:\\tmp\\7za.exe","e","-y","-pqqq","test.zip"]; // app under test
	settings.module_name = "7za".to_string();
	settings.app_args = aut.as_slice();

	let mut map:HashMap<u32,u16> = HashMap::new();
	let mut heatmap: HashMap<String, HashSet<uint>> = HashMap::new();
	// read previously created files and add to blocks to hashmap
	// this enables pause + resume behaviour
	println!("reading input files");
	cleanup(&settings, &mut map);
	println!("start fuzzing...");

	let mutators_static = [mutator_set_byte_values, mutator_bit_walk_1, mutator_bit_walk_4, mutator_xor];
	let mutators_random = [mutator_random_byte, mutator_add_random_byte];
	let mutators_bruteforce = [mutator_bruteforce_byte];
	
	loop{
		// stage 1 create heat map
		stage1_deterministic(&mut settings, &mutators_static, &mut map, &mut heatmap);
		cleanup(&settings, &mut map);
		// stage 2 fuzz heatmap via bruteforce
		stage2_bruteforce(&mut settings, &mutators_bruteforce, &mut map, &mut heatmap);
		// stage 3 create new files randomly (random concatination, random byte add, radom remove ??)
		//stage3(&mut settings, &mutators_static, &mut map, &mut heatmap);
	}
}

// stage 1 create heat map per file
fn stage1_deterministic(settings:&mut AppSettings,
	mutators:&[fn(&mut Vec<u8>, uint, uint)->uint],
	map:&mut HashMap<u32,u16>,
	heatmap:&mut HashMap<String, HashSet<uint>> )
{
	let input_files = get_files_in_dir(&settings.input_dir);

	for file in input_files.iter() {
		let content_org = File::open(file).read_to_end().unwrap();
		let file_length = content_org.len();
		let filename = String::from_str(file.filename_str().unwrap());
		
		if heatmap.contains_key(&filename){
			continue;
		}

		heatmap.insert(filename.clone(), HashSet::new());

		for pos in range(0, file_length) {
			println!("pos {} of {}", pos,file_length);
			for mutate in mutators.iter() {
				let mut i:uint = 0;

				loop{
					let mut content = content_org.clone();
					let iter_left = (*mutate)(&mut content, pos, i);

					write_content_to(&mut content, &settings.output_file);
					
					let newBlocksCount:uint = run_target(settings, map);

					if newBlocksCount > 0 {
						let mut vec : &mut HashSet<uint> = heatmap.get_mut(&filename).unwrap();
						vec.insert(pos);
						copy_to_input_path(settings);
					}

					if iter_left <= 0 {
						break;
					}

					statistics(settings);

					i+=1;
				}
			}
		}
		write_heatmap(heatmap);
	}
}

fn stage2_bruteforce(settings:&mut AppSettings,
	mutators:&[fn(&mut Vec<u8>, uint, uint)->uint],
	map:&mut HashMap<u32,u16>,
	heatmap:&mut HashMap<String, HashSet<uint>> )
{
	for (filename, hotbytes) in heatmap.iter() {
		let mut input_file = settings.input_dir.clone();
		input_file.push(filename);

		let mut content_org = match File::open(&input_file).read_to_end() {
			Ok(f) => f,
			Err(_) => continue,
		};

		for bytepos in hotbytes.iter() {
			println!("hotbyte pos {}", bytepos);
			
			for mutate in mutators.iter() {
				let mut i:uint = 0;
				loop{
					let mut content = content_org.clone();
					let iter_left = (*mutate)(&mut content, *bytepos, i);

					write_content_to(&mut content, &settings.output_file);
					
					let newBlocksCount:uint = run_target(settings, map);

					if newBlocksCount > 0 {
						//let mut vec : &mut Vec<uint> = heatmap.get_mut(&filename).unwrap();
						//vec.push(newBlocksCount);
						copy_to_input_path(settings);
					}

					if iter_left <= 0 {
						break;
					}

					statistics(settings);

					i+=1;
				}
			}
		}
	}
}


fn statistics(settings: &mut AppSettings){
	settings.iter_count += 1;

	if settings.iter_count % 1000 == 0 {
		let now = time::get_time();
		let diff = (now.sec-settings.start_time.sec) as f32;
		println!("iterations done: {}\n duration (sec): {}\n i/s: {}", settings.iter_count,  diff, 1000f32/diff);
		settings.start_time = time::get_time();
	}
	
}

fn write_heatmap(heatmap:&HashMap<String, HashSet<uint>>){
	for (k,v) in heatmap.iter(){
		let mut f = File::create(&Path::new(format!("./heatmap/{}",k)));
		for b in v.iter(){
			f.write(b.to_string().as_bytes());
			f.write(b",");
		}
	}
}

fn copy_to_input_path(settings:&AppSettings){
	let mut newpath = settings.input_dir.clone();
	let now = time::get_time();

	newpath.push(now.sec.to_string()+"_"+now.nsec.to_string());
	fs::copy(&settings.output_file, &newpath);
}

fn cleanup(settings: &AppSettings, map: &mut HashMap<u32,u16>){
	let inputfiles = get_files_in_dir(&settings.input_dir);
	map.clear();	

	for input_file in inputfiles.iter() {
		let mut content = File::open(input_file).read_to_end().unwrap();
		write_content_to(&mut content, &Path::new(&settings.output_file));
		let new_blocks_count = run_target(settings, map);
		// cleanup input
		if new_blocks_count == 0 {
			fs::unlink(input_file);
		}
	}
}

fn write_content_to(content:&mut Vec<u8>, output_file:&Path){
	let mut ofile = match File::create(output_file){
		Err(e) => panic!(e),
		Ok(f) => f,
	};

	match ofile.write(content.as_slice()){
		Err(e) => panic!(e),
		_ =>{}
	};
}

fn mutator_bruteforce_byte(filecontent:&mut Vec<u8>, pos:uint, iter:uint)->uint{
	filecontent[pos] = iter as u8;
	256-iter-1
}

fn mutator_set_byte_values(filecontent:&mut Vec<u8>, pos:uint, iter:uint)->uint{
	let bytepos = pos/8;
	let vals = [0,1,2,3,4,5,10,125,255-3,255-2,255-1,255];
	
	if iter < vals.len() {
		filecontent[pos]=vals[iter];	
	}

	if iter > vals.len(){
		vals.len()-1-iter-1
	} else {
		0
	}
}

fn mutator_bit_walk_1(filecontent:&mut Vec<u8>, pos:uint, iter:uint)->uint{
	let m = 1 << iter;

	filecontent[pos] = filecontent[pos]|m;

	if iter <= 6 {
		7-iter-1
	} else{
		0
	}
}

fn mutator_bit_walk_4(filecontent:&mut Vec<u8>, pos:uint, iter:uint)->uint{
	let m = 0b00001111 << iter;

	filecontent[pos] = filecontent[pos]|m;
	
	if iter <= 3 {
		4-iter-1
	} else{
		0
	}

}

fn mutator_xor(filecontent:&mut Vec<u8>, pos:uint, iter:uint)->uint{
	filecontent[pos] = filecontent[pos]^filecontent[pos];
	0
}

fn mutator_random_byte(filecontent:&mut Vec<u8>, pos:uint, iter:uint)->uint{
	let mut rng = task_rng();
	let bytevalue:u8 = rng.gen_range(0,255);

	filecontent[pos] = bytevalue;
	1
}

fn mutator_add_random_byte(filecontent:&mut Vec<u8>, pos:uint, iter:uint)->uint{
	let mut rng = task_rng();
	let bytevalue:u8 = rng.gen_range(0,255);

	filecontent.insert(pos, bytevalue);
	1
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

fn run_target(settings:&AppSettings, map:&mut HashMap<u32,u16>)->uint {
	// run drcov
	runrio::rundrcov(settings.app_args, !settings.benchmark);
	
	let mut new_blocks: uint = 0;

	let inputpath = find_file_by_filter(".",".proc.log").unwrap();
	// read file and update hashmap
	let maplen = map.len();
	readrcov::convert(&inputpath, map, settings.module_name.as_slice());
	// any new code blocks ?
	new_blocks = map.len()-maplen;

	// clear all proc.log files
	loop{
		let file = find_file_by_filter(".",".proc.log");
		if file == None {
			break;
		}

		fs::unlink(&(file.unwrap()));
	}

	new_blocks
}

fn find_file_by_filter(path:&str, filter:&str) -> Option<Path>{
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
        optflag("b","benchmark", "benchmark target")
	];

	let mut settings = AppSettings {
		dynamorio_root :"c:\\dynamorio-package\\".to_string(),
		output_file: 	Path::new("/"),
		input_dir:		Path::new("/"),
		statistic_file:	"".to_string(),
		verbose:		false,
		help:			false,
		app_args:		[].as_slice(),
		benchmark:		false,
		module_name:	"".to_string(),
		start_time:		time::get_time(),
		iter_count:		0
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
		let output_file = output.unwrap().to_string();
		settings.output_file = Path::new(output_file);
	}
	
	let input = matches.opt_str("i");
	if input != None {
		let input_path = input.unwrap().to_string();
		settings.input_dir = Path::new(input_path);
	}

	settings
}


#[test]
fn test_mutator_enable_1_bits(){
	let mut content :Vec<u8> = Vec::with_capacity(1);
	let startval = 0b00000001;

	for shift in range(0,8){
		content.insert(0,startval);
		content.insert(1,startval);

		mutator_enable_1_bits(&mut content, shift);	
		assert!(content[0] == (startval |(0b00000001 << shift)),"failed at index {}. returned value: {}",shift,content[0]);
		assert!(content[1] == startval,"failed at index {}. returned value: {}",shift,content[1]);

		content.clear();
	}
}

#[test]
fn test_mutator_enable_4_bits(){
	let mut content :Vec<u8> = Vec::with_capacity(1);
	let startval = 0b00000001;

	for shift in range(0, 8){
		content.insert(0, startval);
		content.insert(1, startval);

		mutator_enable_4_bits(&mut content, shift);	
		assert!(content[0] == startval|(0b00001111 << shift),"failed at index {}. returned value: {} from index 0",shift,content[0]);
		if shift>4{
			assert!(content[1] == startval|(0b00000001 << shift-4),"failed at index {}. returned value: {} from index 1",shift,content[1]);
		}
		content.clear();
	}
}
