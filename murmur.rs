pub fn murmur3_32(key:&[u8],seed:u32)->u32{
		let c1:u32 = 0xcc9e2d51;
		let c2:u32 = 0x1b873593;
		let r1:uint = 15;
		let r2:uint = 13;
		let m:u32 = 5;
		let n:u32 = 0xe6546b64;

		let mut hash = seed;

		let len = key.len();
		let nblocks:uint = len/4;
		
		for i in range(0,nblocks){
			let start = i * 4;
			let end = start+4;

			let mut k = u32_from_bytes(key[start..end]);
			k *= c1;
			k = (k << r1) | (k >> (32 - r1));
			k *= c2;
			hash ^= k;
			hash = ((hash << r2) | (hash >> (32 - r2))) * m + n ;
		}
		println!("{:u}",hash);

		let mut k1 = 0_u32;
		let rest = len % 4;

		if rest>=3 {
			k1 ^= key[nblocks*4+2] as u32 << 16;
		}
		if rest>=2 {
			k1 ^= key[nblocks*4+1] as u32 << 8;
		}
		if rest>=1 {
			k1 ^= key[nblocks*4] as u32;
			
			k1 *= c1;
			k1 = (k1 << r1) | (k1 >> (32 - r1));
			k1 *= c2;
			hash ^= k1;
		}

		hash ^= len as u32;
		hash ^= hash >> 16;
		hash *= 0x85ebca6b;
		hash ^= hash >> 13;
		hash *= 0xc2b2ae35;
		hash ^= hash >> 16;
		return hash;
	}

	fn u32_from_bytes(b:&[u8])->u32{
		let mut number:u32;
		number = b[0] as u32;
		number |=b[1] as u32 << 8;
		number |= b[2] as u32 << 16;
		number |= b[3] as u32 << 24;
		return number;
	}
