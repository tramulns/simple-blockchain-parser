use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{App, Arg};
use error_chain::error_chain;
use phf::phf_map;
use std::fmt::{self, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        StrError(std::str::Utf8Error);
        IntError(std::num::ParseIntError);
    }
}

const SIGHASH_ALL: i32 = 0x01;

fn parse(mut file: File, blk_no: u32) -> Result<()> {
    let mut continue_parsing = true;
    let mut counter = 0;
    file.seek(SeekFrom::Start(0))?;
    while continue_parsing {
        let block = Block::new(&mut file)?;
        continue_parsing = block.continue_parsing;
        if continue_parsing {
            println!("{}", block);
        }
        counter += 1;
        println!(
            "#################### Block counter No. {} ####################",
            counter
        );
        if counter >= blk_no && blk_no != 0xFF {
            continue_parsing = false;
        }
    }

    println!();
    println!("Reached End of Field");
    println!("Parsed {} blocks", counter);
    Ok(())
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

fn as_u64_le(array: &[u8; 8]) -> u64 {
    ((array[0] as u64) << 0)
        + ((array[1] as u64) << 8)
        + ((array[2] as u64) << 16)
        + ((array[3] as u64) << 24)
        + ((array[4] as u64) << 32)
        + ((array[5] as u64) << 40)
        + ((array[6] as u64) << 48)
        + ((array[7] as u64) << 56)
}

fn as_u16_le(array: &[u8; 2]) -> u16 {
    ((array[0] as u16) << 0) + ((array[1] as u16) << 8)
}

fn read_u8(mut file: &File) -> Result<u8> {
    let mut buf = [0u8; 1];
    file.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16(mut file: &File) -> Result<u16> {
    let mut buf = [0u8; 2];
    file.read_exact(&mut buf)?;
    Ok(as_u16_le(&buf))
}

fn read_u32(mut file: &File) -> Result<u32> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    Ok(as_u32_le(&buf))
}

fn read_u64(mut file: &File) -> Result<u64> {
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)?;
    Ok(as_u64_le(&buf))
}

fn read_var_int(mut file: &File) -> Result<u64> {
    let size = read_u8(&mut file)?;

    let value = if size < 0xfd {
        size as u64
    } else if size == 0xfd {
        read_u16(&mut file)? as u64
    } else if size == 0xfe {
        read_u32(&mut file)? as u64
    } else if size == 0xff {
        read_u64(&mut file)?
    } else {
        0
    };
    Ok(value)
}

fn read_array(mut file: &File, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_hash32(mut file: &File) -> Result<[u8; 32]> {
    let mut buf = [0_u8; 32];
    file.read_exact(&mut buf)?;
    buf.reverse();
    Ok(buf)
}

fn has_length(mut file: &File, size: u64) -> Result<bool> {
    let cur_pos = file.seek(SeekFrom::Current(0))?;

    let file_size = file.seek(SeekFrom::End(0))?;

    file.seek(SeekFrom::Start(cur_pos))?;
    let temp_block_size = file_size - cur_pos;
    Ok(temp_block_size >= size)
}

fn hash_2_str(bytebuffer: &[u8]) -> String {
    bytebuffer
        .iter()
        .map(|d| format!("{:02x}", d))
        .collect::<String>()
}

fn main() -> Result<()> {
    let matches = App::new("block_chain_parser")
        .version("0.1.0")
        .about("Parsing Block Chain block head, transaction etc.")
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .takes_value(true)
                .help("Raw block chain data file"),
        )
        .get_matches();

    let file = matches.value_of("file").unwrap_or("input.txt");
    let file = OpenOptions::new().read(true).open(file)?;
    parse(file, 0xff)?;

    Ok(())
}

struct Block {
    continue_parsing: bool,
    magic_num: u32,
    block_size: u32,
    block_header: Option<Box<BlockHeader>>,
    tx_count: u64,
    txs: Vec<Tx>,
}

impl Block {
    fn new(mut file: &File) -> Result<Block> {
        let mut continue_parsing = true;
        let mut magic_num = 0;
        let mut block_size = 0;
        let mut block_header = None;
        let mut tx_count = 0;
        let mut txs = Vec::new();

        if has_length(&mut file, 8)? {
            magic_num = read_u32(&mut file)?;
            block_size = read_u32(&mut file)?;
        } else {
            continue_parsing = false;
        }

        if has_length(&mut file, block_size as u64)? {
            let b = BlockHeader::new(&mut file)?;
            block_header = Some(Box::new(b));
            tx_count = read_var_int(&mut file)?;
            for i in 0..tx_count {
                let mut tx = Tx::new(&mut file)?;
                tx.seq = i;
                txs.push(tx);
            }
        } else {
            continue_parsing = false;
        }

        Ok(Block {
            continue_parsing,
            magic_num,
            block_size,
            block_header,
            tx_count,
            txs,
        })
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "Magic No: \t{:>8x}", self.magic_num)?;
        writeln!(f, "Blocksize: \t{}", self.block_size)?;
        writeln!(f)?;
        if let Some(header) = &self.block_header {
            writeln!(f, "==================== Block Header ====================")?;
            writeln!(f, "{}", **header)?;
            writeln!(f)?;
        }
        writeln!(f, "##### Tx Count: {}", self.tx_count)?;
        for t in self.txs.iter() {
            writeln!(f, "{}", t)?;
        }
        write!(f, "#### end of all {} transactins", self.tx_count)
    }
}

struct BlockHeader {
    version: u32,
    previous_hash: [u8; 32],
    merkle_hash: [u8; 32],
    time: u32,
    bits: u32,
    nonce: u32,
}

impl BlockHeader {
    fn new(mut file: &File) -> Result<BlockHeader> {
        Ok(BlockHeader {
            version: read_u32(&mut file)?,
            previous_hash: read_hash32(&mut file)?,
            merkle_hash: read_hash32(&mut file)?,
            time: read_u32(&mut file)?,
            bits: read_u32(&mut file)?,
            nonce: read_u32(&mut file)?,
        })
    }

    fn decode_time(&self) -> String {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(self.time as i64, 0), Utc);
        dt.format("%Y-%m-%d %H:%M:%S.%f+00:00 (UTC)").to_string()
    }
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln!(f, "Version:\t {}", self.version)?;
        writeln!(f, "Previous Hash\t {}", hash_2_str(&self.previous_hash))?;
        writeln!(f, "Merkle Root\t {}", hash_2_str(&self.merkle_hash))?;
        writeln!(f, "Time stamp\t {}", self.decode_time())?;
        writeln!(f, "Difficulty\t {}", self.bits)?;
        write!(f, "Nonce\t\t {}", self.nonce)
    }
}

struct Tx {
    version: u32,
    in_count: u64,
    inputs: Vec<TxInput>,
    seq: u64,
    out_count: u64,
    outputs: Vec<TxOutput>,
    lock_time: u32,
}

impl Tx {
    fn new(mut file: &File) -> Result<Tx> {
        let version = read_u32(&mut file)?;
        let in_count = read_var_int(&mut file)?;
        let mut inputs = Vec::new();
        let seq = 1;
        for _ in 0..in_count {
            let input = TxInput::new(&mut file)?;
            inputs.push(input);
        }
        let out_count = read_var_int(&mut file)?;
        let mut outputs = Vec::new();
        for _ in 0..out_count {
            let output = TxOutput::new(&mut file)?;
            outputs.push(output);
        }
        let lock_time = read_u32(&mut file)?;

        Ok(Tx {
            version,
            in_count,
            inputs,
            seq,
            out_count,
            outputs,
            lock_time,
        })
    }
}

impl Display for Tx {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln!(f)?;
        writeln!(
            f,
            "==================== No. {} Transaction ====================",
            self.seq
        )?;
        writeln!(f, "Tx Version:\t {}", self.version)?;
        writeln!(f, "Inputs:\t\t {}", self.in_count)?;
        for i in self.inputs.iter() {
            writeln!(f, "{}", i)?;
        }
        writeln!(f, "Outputs:\t {}", self.out_count)?;
        for o in self.outputs.iter() {
            writeln!(f, "{}", o)?;
        }
        write!(f, "Lock Time:\t {}", self.lock_time)
    }
}

#[derive(Debug)]
struct TxInput {
    prevhash: [u8; 32],
    tx_out_id: u32,
    script_len: usize,
    script_sig: Vec<u8>,
    seq_no: u32,
}

impl TxInput {
    fn new(mut file: &File) -> Result<TxInput> {
        let prevhash = read_hash32(&mut file)?;
        let tx_out_id = read_u32(&mut file)?;
        let script_len = read_var_int(&mut file)? as usize;
        let script_sig = read_array(&mut file, script_len)?;
        let seq_no = read_u32(&mut file)?;

        Ok(TxInput {
            prevhash,
            tx_out_id,
            script_len,
            script_sig,
            seq_no,
        })
    }

    fn decode_out_idx(&self, idx: u32) -> Result<String> {
        let mut result = String::new();
        let mut s = "";
        if idx == 0xffffffff {
            s = " Coinbase with special index";
            result.push_str(&format!(
                "\tCoinbase Text:\t {}",
                hash_2_str(&self.prevhash)
            ));
        } else {
            result.push_str(&format!(
                "\tPrev. Tx Hash:\t {}",
                hash_2_str(&self.prevhash)
            ));
        }
        result.push_str(&format!("\n\tTx Out Index:\t {:>8x}{}", idx, s));

        Ok(result)
    }

    fn decode_script_sig(&self) -> Result<String> {
        let mut result = String::new();
        let hexstr = hash_2_str(&self.script_sig);
        if 0xffffffff == self.tx_out_id {
            return Ok(result);
        }
        let script_len = i32::from_str_radix(&hexstr[0..2], 16)? as usize * 2;
        let script = &hexstr[2..2 + script_len];
        result.push_str(&format!("\tScript:\t\t {}", script));
        if SIGHASH_ALL != i32::from_str_radix(&hexstr[script_len..script_len + 2], 16)? {
            result.push_str("\n\t Script op_code is not SIGHASH_ALL");
            return Ok(result);
        } else {
            let pubkey = if 2 + script_len + 2 + 66 < hexstr.len() {
                &hexstr[2 + script_len + 2..2 + script_len + 2 + 66]
            } else {
                ""
            };
            result.push_str(&format!("\n \tInPubkey:\t {}", pubkey));
        }
        Ok(result)
    }
}

impl Display for TxInput {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln!(f, "{}", self.decode_out_idx(self.tx_out_id).unwrap())?;
        writeln!(f, "\tScript Len:\t {}", self.script_len)?;
        let script = self.decode_script_sig().unwrap();
        if !script.is_empty() {
            writeln!(f, "{}", script)?;
        }
        write!(f, "\tSequence:\t {:>8x}", self.seq_no)
    }
}

struct TxOutput {
    value: u64,
    script_len: usize,
    pubkey: Pubkey,
}

impl TxOutput {
    fn new(mut file: &File) -> Result<TxOutput> {
        let value = read_u64(&mut file)?;
        let script_len = read_var_int(&mut file)? as usize;
        let pubkey = Pubkey::new(&mut file, script_len)?;

        Ok(TxOutput {
            value,
            script_len,
            pubkey,
        })
    }
}

impl Display for TxOutput {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln!(f, "\tValue:\t\t {} Satoshi", self.value)?;
        writeln!(f, "\tScript Len:\t {}", self.script_len)?;
        writeln!(f, "{}", self.pubkey)?;
        write!(f, "\tScriptPubkey:\t {}", hash_2_str(&self.pubkey.value))
    }
}

struct Pubkey {
    value: Vec<u8>,
}

impl Pubkey {
    fn new(mut file: &File, size: usize) -> Result<Pubkey> {
        let value = read_array(&mut file, size)?;
        Ok(Pubkey { value })
    }
}

impl Display for Pubkey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let hexstr = hash_2_str(&self.value);
        let op_idx = i32::from_str_radix(&hexstr[..2], 16).unwrap();
        let op_code1 = OPCODE_NAMES.get(&op_idx);
        if op_code1.is_none() {
            writeln!(
                f,
                " \tOP_CODE {} is probably obselete pay to address",
                op_idx
            )?;
            let keylen = op_idx as usize;
            let op_code_tail = OPCODE_NAMES
                .get(&i32::from_str_radix(&hexstr[2 + keylen * 2..2 + keylen * 2 + 2], 16).unwrap())
                .unwrap();
            writeln!(
                f,
                " \tPubkey OP_CODE:\t None Bytes:{} tail_op_code:{}",
                keylen, op_code_tail
            )?;
            return write!(f, "\tPure Pubkey:\t {}", &hexstr[2..2 + keylen * 2]);
        }
        let op_code1 = op_code1.unwrap();
        if *op_code1 == "OP_DUP" {
            let op_code2 = OPCODE_NAMES
                .get(&i32::from_str_radix(&hexstr[2..4], 16).unwrap())
                .unwrap();
            let keylen = i32::from_str_radix(&hexstr[4..6], 16).unwrap() as usize;
            let op_code_tail2nd = OPCODE_NAMES
                .get(&i32::from_str_radix(&hexstr[6 + keylen * 2..6 + keylen * 2 + 2], 16).unwrap())
                .unwrap();
            let op_code_tail_last = OPCODE_NAMES
                .get(
                    &i32::from_str_radix(&hexstr[6 + keylen * 2 + 2..6 + keylen * 2 + 4], 16)
                        .unwrap(),
                )
                .unwrap();
            write!(
                f,
                " \tPubkey OP_CODE:\t {} {} Bytes:{} tail_op_code: {} {}\tPubkeyHash:\t       {}",
                op_code1,
                op_code2,
                keylen,
                op_code_tail2nd,
                op_code_tail_last,
                &hexstr[6..6 + keylen * 2],
            )
        } else if *op_code1 == "OP_HASH160" {
            let keylen = i32::from_str_radix(&hexstr[2..4], 16).unwrap() as usize;
            let op_code_tail = OPCODE_NAMES
                .get(&i32::from_str_radix(&hexstr[4 + keylen * 2..4 + keylen * 2 + 2], 16).unwrap())
                .unwrap();
            write!(
                f,
                " \tPubkey OP_CODE:\t {}  Bytes:{} tail_op_code:{} \tPure Pubkey:\t     {}",
                op_code1,
                keylen,
                op_code_tail,
                &hexstr[4..4 + keylen * 2]
            )
        } else {
            write!(
                f,
                "\t Need to extend multi-signatuer parsing {:x} {}",
                i32::from_str_radix(&hexstr[0..2], 16).unwrap(),
                op_code1
            )
        }
    }
}

static OPCODE_NAMES: phf::Map<i32, &'static str> = phf_map! {
    0x00_i32 => "OP_0",
    0x4c_i32 => "OP_PUSHDATA1",
    0x4d_i32 => "OP_PUSHDATA2",
    0x4e_i32 => "OP_PUSHDATA4",
    0x4f_i32 => "OP_1NEGATE",
    0x50_i32 => "OP_RESERVED",
    0x51_i32 => "OP_1",
    0x52_i32 => "OP_2",
    0x53_i32 => "OP_3",
    0x54_i32 => "OP_4",
    0x55_i32 => "OP_5",
    0x56_i32 => "OP_6",
    0x57_i32 => "OP_7",
    0x58_i32 => "OP_8",
    0x59_i32 => "OP_9",
    0x5a_i32 => "OP_10",
    0x5b_i32 => "OP_11",
    0x5c_i32 => "OP_12",
    0x5d_i32 => "OP_13",
    0x5e_i32 => "OP_14",
    0x5f_i32 => "OP_15",
    0x60_i32 => "OP_16",
    0x61_i32 => "OP_NOP",
    0x62_i32 => "OP_VER",
    0x63_i32 => "OP_IF",
    0x64_i32 => "OP_NOTIF",
    0x65_i32 => "OP_VERIF",
    0x66_i32 => "OP_VERNOTIF",
    0x67_i32 => "OP_ELSE",
    0x68_i32 => "OP_ENDIF",
    0x69_i32 => "OP_VERIFY",
    0x6a_i32 => "OP_RETURN",
    0x6b_i32 => "OP_TOALTSTACK",
    0x6c_i32 => "OP_FROMALTSTACK",
    0x6d_i32 => "OP_2DROP",
    0x6e_i32 => "OP_2DUP",
    0x6f_i32 => "OP_3DUP",
    0x70_i32 => "OP_2OVER",
    0x71_i32 => "OP_2ROT",
    0x72_i32 => "OP_2SWAP",
    0x73_i32 => "OP_IFDUP",
    0x74_i32 => "OP_DEPTH",
    0x75_i32 => "OP_DROP",
    0x76_i32 => "OP_DUP",
    0x77_i32 => "OP_NIP",
    0x78_i32 => "OP_OVER",
    0x79_i32 => "OP_PICK",
    0x7a_i32 => "OP_ROLL",
    0x7b_i32 => "OP_ROT",
    0x7c_i32 => "OP_SWAP",
    0x7d_i32 => "OP_TUCK",
    0x7e_i32 => "OP_CAT",
    0x7f_i32 => "OP_SUBSTR",
    0x80_i32 => "OP_LEFT",
    0x81_i32 => "OP_RIGHT",
    0x82_i32 => "OP_SIZE",
    0x83_i32 => "OP_INVERT",
    0x84_i32 => "OP_AND",
    0x85_i32 => "OP_OR",
    0x86_i32 => "OP_XOR",
    0x87_i32 => "OP_EQUAL",
    0x88_i32 => "OP_EQUALVERIFY",
    0x89_i32 => "OP_RESERVED1",
    0x8a_i32 => "OP_RESERVED2",
    0x8b_i32 => "OP_1ADD",
    0x8c_i32 => "OP_1SUB",
    0x8d_i32 => "OP_2MUL",
    0x8e_i32 => "OP_2DIV",
    0x8f_i32 => "OP_NEGATE",
    0x90_i32 => "OP_ABS",
    0x91_i32 => "OP_NOT",
    0x92_i32 => "OP_0NOTEQUAL",
    0x93_i32 => "OP_ADD",
    0x94_i32 => "OP_SUB",
    0x95_i32 => "OP_MUL",
    0x96_i32 => "OP_DIV",
    0x97_i32 => "OP_MOD",
    0x98_i32 => "OP_LSHIFT",
    0x99_i32 => "OP_RSHIFT",
    0x9a_i32 => "OP_BOOLAND",
    0x9b_i32 => "OP_BOOLOR",
    0x9c_i32 => "OP_NUMEQUAL",
    0x9d_i32 => "OP_NUMEQUALVERIFY",
    0x9e_i32 => "OP_NUMNOTEQUAL",
    0x9f_i32 => "OP_LESSTHAN",
    0xa0_i32 => "OP_GREATERTHAN",
    0xa1_i32 => "OP_LESSTHANOREQUAL",
    0xa2_i32 => "OP_GREATERTHANOREQUAL",
    0xa3_i32 => "OP_MIN",
    0xa4_i32 => "OP_MAX",
    0xa5_i32 => "OP_WITHIN",
    0xa6_i32 => "OP_RIPEMD160",
    0xa7_i32 => "OP_SHA1",
    0xa8_i32 => "OP_SHA256",
    0xa9_i32 => "OP_HASH160",
    0xaa_i32 => "OP_HASH256",
    0xab_i32 => "OP_CODESEPARATOR",
    0xac_i32 => "OP_CHECKSIG",
    0xad_i32 => "OP_CHECKSIGVERIFY",
    0xae_i32 => "OP_CHECKMULTISIG",
    0xaf_i32 => "OP_CHECKMULTISIGVERIFY",
    0xb0_i32 => "OP_NOP1",
    0xb1_i32 => "OP_NOP2",
    0xb2_i32 => "OP_NOP3",
    0xb3_i32 => "OP_NOP4",
    0xb4_i32 => "OP_NOP5",
    0xb5_i32 => "OP_NOP6",
    0xb6_i32 => "OP_NOP7",
    0xb7_i32 => "OP_NOP8",
    0xb8_i32 => "OP_NOP9",
    0xb9_i32 => "OP_NOP10",
    0xfa_i32 => "OP_SMALLINTEGER",
    0xfb_i32 => "OP_PUBKEYS",
    0xfd_i32 => "OP_PUBKEYHASH",
    0xfe_i32 => "OP_PUBKEY",
    0xff_i32 => "OP_INVALIDOPCODE",
};
