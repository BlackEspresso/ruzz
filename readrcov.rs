#![feature(phase)]
#[phase(plugin)]
extern crate regex_macros;
extern crate regex;
extern crate std;
use std::io::BufferedReader;
use std::io::File;
use std::io::IoResult;
use std::collections::HashMap;

pub fn convert(inputpath:&Path, map:&mut HashMap<u32,u16>){
	//let outputpath = Path::new(outputfilepath);

	let mut fileinput = BufferedReader::new(File::open(inputpath));
	//let mut fileoutput = File::create(&outputpath);

	read_file_header(&mut fileinput);
	let module_size = read_module_table_size(&mut fileinput);
	let modules = read_module_table(&mut fileinput, module_size.unwrap());
	let bb_size = read_bb_table_size(&mut fileinput);
	//read_bb_table_and_write(&mut fileinput, &mut fileoutput, bb_size.unwrap());
	read_bb_table_to_hash(&mut fileinput, map, bb_size.unwrap());
}

fn read_file_header(br:&mut BufferedReader<std::io::IoResult<File>>){
	let version_line = br.read_line().unwrap();
	let flavor_line = br.read_line().unwrap();
	//print!("{}",version_line);
	//print!("{}",flavor_line);
}

fn read_module_table_size(br:&mut BufferedReader<std::io::IoResult<File>>)->Option<uint>{
	let table_size_string = br.read_line().unwrap();
	let size_re = regex!(r"Module Table: (\d+)");
	let cap = size_re.captures(table_size_string.as_slice()).unwrap();

	from_str::<uint>(cap.at(1))
}

fn read_bb_table_size(br:&mut BufferedReader<std::io::IoResult<File>>)->Option<uint>{
	let table_size_string = br.read_line().unwrap();
	let size_re = regex!(r"BB Table: (\d+)");
	let cap = size_re.captures(table_size_string.as_slice()).unwrap();

	from_str::<uint>(cap.at(1))
}

fn read_module_table(br:&mut BufferedReader<std::io::IoResult<File>>, size:uint)->Vec<String>{
	let module_info_re = regex!(r"(\d+), (\d+), ([^\n]+)");
	if size > 5000 {
		return Vec::new()
	}

	let mut modules:Vec<String> = Vec::with_capacity(size);

	for _ in range(0,size){
		let line = br.read_line().unwrap();
		let cap = module_info_re.captures(line.as_slice()).unwrap();
		let mod_id:int = from_str(cap.at(1)).unwrap();
		let mod_size:int = from_str(cap.at(2)).unwrap();
		let mod_path:String = from_str(cap.at(3)).unwrap();
		//println!("{}, {}, {}", mod_id,mod_size,mod_path);
		modules.push(mod_path);
	}

	modules
}

fn read_bb_table_and_write(br:&mut BufferedReader<std::io::IoResult<File>>,
	write_to:&mut std::io::IoResult<File>, size:uint){

	for _ in range(0,size){
		let addr:u32 = br.read_le_u32().unwrap();
		let size = br.read_le_u16().unwrap();
		let mod_id :u16 = br.read_le_u16().unwrap();
		
		//if mod_id == 0 {
		write_to.write_str(format!("{:x}, {}\n",addr,mod_id).as_slice());

		//}
		
	}
}

fn read_bb_table_to_hash(br:&mut BufferedReader<std::io::IoResult<File>>, map:&mut HashMap<u32,u16>,size:uint){
	for _ in range(0,size){
		let addr:u32 = br.read_le_u32().unwrap();
		let size = br.read_le_u16().unwrap();
		let mod_id = br.read_le_u16().unwrap();
		
		map.insert(addr, mod_id);
	}
}
