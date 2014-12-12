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
	benchmark:		bool,
	module_name: 	String
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

	let aut = ["./php/php.exe","extract.php"]; // app under test
	settings.module_name = "php".to_string();
	settings.app_args = aut.slice(0,aut.len());

	let mut map:HashMap<u32,u16> = HashMap::new();
	let mut i:uint = 0;

	let mut inputpath = os::getcwd().unwrap();
	inputpath.push(settings.input_dir.clone());

	let output_file = Path::new(&settings.output_file);

	let mut start = time::get_time();

	let inputfiles = get_files_in_dir(&inputpath);

	if !settings.benchmark {
		// read previously created files and add to blocks to hashmap
		// this enables pause + resume behaviour
		println!("reading input files");
		cleanup_input_files(&inputfiles,&settings,&mut map);

		println!("start fuzzing...");
	}
	
	let mut rng = task_rng();
	let fuzz_len:uint = 20;
	let fuzz_length_bit :uint = fuzz_len * 8;

	loop { // main loop - loops to infinity

		let input_file = pick_file_from_dir(&inputpath);
		let content_org = File::open(&input_file).read_to_end().unwrap();
		let file_length_bit = (content_org.len()-1)*8;
		let mut file_pos = rng.gen_range(0, file_length_bit - fuzz_length_bit);
		let action_number:u8 = rng.gen_range(0,101);
		let mutator_pos :(int,int) = (0,0);
		let mut iter_count_start = i;

		loop { // position loop - increments file position
			//loop { // iteration loop  - increments iteration count
				let mut content = content_org.clone();
				if !settings.benchmark {
					match action_number {
						0...5 => mutator_add_random_byte(&mut content, &mut file_pos),
						6...10 => mutator_enable_random_byte(&mut content, &mut file_pos),
						11...20 => mutator_enable_1_bits(&mut content,&mut file_pos),
						20...25 => mutator_enable_4_bits(&mut content,&mut file_pos),
						26...35 => mutator_set_value(&mut content,&mut file_pos, 0xFF),
						36...40 => mutator_enable_16_bits(&mut content,&mut file_pos),
						41...45 => mutator_enable_24_bits(&mut content,&mut file_pos),
						46...55 => mutator_enable_32_bits(&mut content,&mut file_pos),
						56...60 => mutator_xor(&mut content, &mut file_pos),
						61...65 => mutator_set_value(&mut content, &mut file_pos, 0x00),
						66...70 => mutator_set_value(&mut content,&mut file_pos, 0x02),
						71...75 => mutator_set_value(&mut content,&mut file_pos, 0x03),
						76...80 => mutator_set_value(&mut content,&mut file_pos, 0x04),
						81...85 => mutator_set_value(&mut content,&mut file_pos, 0x05),
						86...90 => mutator_set_value(&mut content,&mut file_pos, 0x06),
						91...95 => mutator_set_value(&mut content,&mut file_pos, 0x07),
						96...100 => mutator_set_value(&mut content,&mut file_pos, 0x08),
						_ => panic!("not handled action")
					}
				}

				write_content_to(&mut content, &output_file);

				let newBlocksCount = run_target(&settings, &mut map);

				if i > 1 && newBlocksCount > 0 && !settings.benchmark {
					let mut newpath = inputpath.clone();
					let now = time::get_time();
					newpath.push(now.sec.to_string()+"_"+now.nsec.to_string());
					fs::copy(&output_file, &newpath);
				}

				if i % 1000 == 0 && i > 0 {
					let now = time::get_time();
					let diff = now.sec-start.sec;
					println!("{} seconds for 1000 runs => {} runs per second", diff, 1000_f32/diff as f32);
					if i % 3000 == 0{
						println!("cleanup");
						map.clear();
						cleanup_input_files(&get_files_in_dir(&inputpath),&settings, &mut map);
					}

					start = now;
				}

				i += 1;
			//}
			file_pos += 1;

			if file_pos>=content.len(){
				file_pos = 0;
			}

			if i-iter_count_start >= fuzz_len {
				break;
			}
		}
	}
}

fn cleanup_input_files(inputfiles: &Vec<Path>, settings: &AppSettings, map: &mut HashMap<u32,u16>){
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

// 1. open input file
// 2. mutate with mutator
// 3. write output file
fn write_content_to(content:&mut Vec<u8>,output_file:&Path){
	let mut ofile = match File::create(output_file){
		Err(e) => panic!(e),
		Ok(f) => f,
	};

	match ofile.write(content.as_slice()){
		Err(e) => panic!(e),
		_ =>{}
	};
}

fn mutator_add_random_byte(filecontent:&mut Vec<u8>, pos:&mut uint){
	let mut rng = task_rng();
	let bytevalue:u8 = rng.gen_range(0,255);
	let bytepos = *pos/8;

	filecontent.insert(bytepos, bytevalue);
	*pos+=8;
}

fn mutator_set_value(filecontent:&mut Vec<u8>, pos:&mut uint, bytevalue:u8){
	let mut rng = task_rng();
	let bytepos = *pos/8;

	filecontent[bytepos]=bytevalue;
	*pos+=8;
}

fn mutator_enable_random_byte(filecontent:&mut Vec<u8>, pos:&mut uint){
	let mut rng = task_rng();
	let bytevalue:u8 = rng.gen_range(0,255);
	let bytepos = *pos/8;

	filecontent[bytepos] = bytevalue;
	*pos+=8;
}

fn mutator_enable_1_bits(filecontent:&mut Vec<u8>, pos:&mut uint){
	let shift_count :uint = *pos % 8;
	let bytepos = *pos/8;
	let m = 1 << shift_count;

	filecontent[bytepos] = filecontent[bytepos]|m;
	*pos+=8;
}

fn mutator_enable_4_bits(filecontent:&mut Vec<u8>, pos:&mut uint){
	let shift_count :uint = *pos % 8;
	let bytepos = *pos/8;
	let first_byte:u8 = 0b1111 << shift_count;
	let second_byte:u8 = (2i.pow(shift_count-4)) as u8;
	let index_max = filecontent.len()-1;

	filecontent[bytepos] = filecontent[bytepos]|first_byte;
	filecontent[bytepos+1] = filecontent[bytepos+1]|second_byte;
	*pos+=1;
}

fn mutator_enable_16_bits(filecontent:&mut Vec<u8>, pos:&mut uint){
	let shift_count :uint = *pos % 8;
	let bytepos = *pos/8;
	let index_max = filecontent.len()-1;

	filecontent[bytepos] = 0xFF;
	*pos+=8;

	if index_max>bytepos+1 {
		filecontent[bytepos+1] = 0xFF;
		*pos+=8;
	}
}

fn mutator_enable_24_bits(filecontent:&mut Vec<u8>, pos:&mut uint){
	let shift_count :uint = *pos % 8;
	let bytepos = *pos/8;
	let index_max = filecontent.len()-1;

	filecontent[bytepos] = 0xFF;
	*pos+=8;

	if index_max > bytepos+1 {
		filecontent[bytepos+1] = 0xFF;
		*pos+=8;
	}

	if index_max > bytepos+2 {
		filecontent[bytepos+2] = 0xFF;
		*pos+=8;
	}
}

fn mutator_enable_32_bits(filecontent:&mut Vec<u8>, pos:&mut uint){
	let shift_count :uint = *pos % 8;
	let bytepos = *pos/8;
	let index_max = filecontent.len()-1;

	filecontent[bytepos] = 0xFF;
	*pos+=8;

	if(index_max > bytepos+1){
		filecontent[bytepos+1] = 0xFF;
		*pos+=8;
	}

	if(index_max > bytepos+2){
		filecontent[bytepos+2] = 0xFF;
		*pos+=8;
	}

	if(index_max > bytepos+3){
		filecontent[bytepos+3] = 0xFF;
		*pos+=8;
	}
}

fn mutator_xor(filecontent:&mut Vec<u8>, pos:&mut uint){
	let shift_count :uint = *pos % 8;
	let bytepos = *pos/8;

	filecontent[bytepos] = filecontent[bytepos]^filecontent[bytepos];
	*pos+=8;
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

	if !settings.benchmark {
		let inputpath = find_file_by_filter(".",".proc.log").unwrap();
		// read file and update hashmap
		let maplen = map.len();
		readrcov::convert(&inputpath, map, settings.module_name.as_slice());
		// any new code blocks ?
		new_blocks = map.len()-maplen;
		fs::unlink(&inputpath);

		// todo: clear all proc.log;
		loop{
			let file = find_file_by_filter(".",".proc.log");
			if file == None{
				break;
			}
			fs::unlink(&(file.unwrap()));
		}
	}

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
        optflag("b","benchmark", "benchmark target")
	];

	let mut settings = AppSettings {
		dynamorio_root :"c:\\dynamorio-package\\".to_string(),
		output_file: 	"".to_string(),
		input_dir:		"".to_string(),
		statistic_file:	"".to_string(),
		verbose:		false,
		help:			false,
		app_args:		[].as_slice(),
		benchmark:		false,
		module_name:	"".to_string()
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
