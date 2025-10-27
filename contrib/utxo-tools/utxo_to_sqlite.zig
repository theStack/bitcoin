const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const s = @cImport({
    @cInclude("sqlite3.h");
});

const UTXO_DUMP_MAGIC: [5]u8 = .{'u','t','x','o',0xff};
const UTXO_DUMP_VERSION: u16 = 2;

const NetworkEntry = struct {
    net_magic: [4]u8,
    description: []const u8,
};
const NETWORKS = [_]NetworkEntry {
    .{ .net_magic = .{0xf9,0xbe,0xb4,0xd9}, .description = "Mainnet" },
    .{ .net_magic = .{0x0a,0x03,0xcf,0x40}, .description = "Signet" },
    .{ .net_magic = .{0x0b,0x11,0x09,0x07}, .description = "Testnet3" },
    .{ .net_magic = .{0x1c,0x16,0x3f,0x28}, .description = "Testnet4" },
    .{ .net_magic = .{0xfa,0xbf,0xb5,0xda}, .description = "Regtest" },
};

// Equivalent of `ReadVarInt()` (see serialization module).
fn readVarInt(r: *io.Reader) !u64 {
    var n: u64 = 0;
    while (true) {
        const dat = (try r.takeArray(1))[0];
        n = (n << 7) | (dat & 0x7f);
        if ((dat & 0x80) > 0) {
            n += 1;
        } else {
            return n;
        }
    }
}

// Equivalent of `ReadCompactSize()` (see serialization module).
fn readCompactSize(r: *io.Reader) !u64 {
    const n = (try r.takeArray(1))[0];
    if (n == 253) { // TODO: use switch/case?
        return mem.readInt(u16, try r.takeArray(2), .little);
    } else if (n == 254) {
        return mem.readInt(u32, try r.takeArray(4), .little);
    } else if (n == 255) {
        return mem.readInt(u64, try r.takeArray(8), .little);
    }
    return n;
}

// Equivalent of `DecompressAmount()` (see compressor module).
fn decompressAmount(in: u64) u64 {
    if (in == 0) {
        return 0;
    }
    var x = in - 1;
    var e = x % 10;
    x = x / 10;
    var n: u64 = 0;
    if (e < 9) {
        const d = (x % 9) + 1;
        x = x / 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    while (e > 0) {
        n *= 10;
        e -= 1;
    }
    return n;
}

fn decompressScript(r: *io.Reader, fba: mem.Allocator) ![]u8 {
    const id = try readVarInt(r);
    if (id == 0) {  // P2PKH
        var script = try fba.alloc(u8, 25);
        @memcpy(script[0..3], &[_]u8{ 0x76, 0xa9, 20 });
        @memcpy(script[3..23], try r.takeArray(20));
        @memcpy(script[23..25], &[_]u8{ 0x88, 0xac});
        return script;
    } else if (id == 1) {  // P2SH
        var script = try fba.alloc(u8, 23);
        @memcpy(script[0..2], &[_]u8{ 0xa9, 20 });
        @memcpy(script[2..22], try r.takeArray(20));
        @memcpy(script[22..23], &[_]u8{ 0x87 });
        return script;
    } else if (id == 2 or id == 3) {  // P2PK (compressed)
        var script = try fba.alloc(u8, 35);
        @memcpy(script[0..2], &[_]u8{ 33, @intCast(id) });
        @memcpy(script[2..34], try r.takeArray(32));
        @memcpy(script[34..35], &[_]u8{ 0xac });
        return script;
    } else if (id == 4 or id == 5) {  // P2PK (uncompressed)
        var script = try fba.alloc(u8, 67);
        var compressed_pubkey: [33]u8 = undefined;
        const prefix_byte: u8 = @intCast(id - 2);
        compressed_pubkey[0] = prefix_byte;
        @memcpy(compressed_pubkey[1..], try r.takeArray(32));
        const full_pubkey = decompressPubkey(&compressed_pubkey);
        @memcpy(script[0..1], &[_]u8{ 65 });
        @memcpy(script[1..66], &full_pubkey);
        @memcpy(script[66..67], &[_]u8{ 0xac });
        return script;
    } else {  // others (bare multisig, segwit etc.)
        const size = id - 6;
        std.debug.assert(size <= 10000); // TODO: return appropriate error here
        var script = try fba.alloc(u8, size);
        @memcpy(script[0..], try r.take(size));
        return script;
    }
}

const SECP256K1_P: u256 = (1<<256) - (1<<32) - 977;

pub fn fastExpMod(base: u256, exponent: u256) u256 {
    var result: u256 = 1;
    var a_i: u256 = base; // squaring for next loop iteration (a_i = base ^ (2^i))
    for (0..256) |_i| {
        const i: u8 = @intCast(_i);
        if ((exponent & (@as(u256, 1) << i)) != 0) {
            result = @intCast((@as(u512, result) * a_i) % SECP256K1_P);
        }
        a_i = @intCast((@as(u512, a_i) * a_i) % SECP256K1_P);
    }
    return result;
}

// Decompress pubkey by calculating y = sqrt(x^3 + 7) % p
// (see functions `secp256k1_eckey_pubkey_parse` and `secp256k1_ge_set_xo_var`).
fn decompressPubkey(compressed_pubkey: []u8) [65]u8 {
    std.debug.assert(compressed_pubkey.len == 33);
    std.debug.assert(compressed_pubkey[0] == 2 or compressed_pubkey[0] == 3);
    const x = mem.readInt(u256, compressed_pubkey[1..33], .big);
    const rhs: u256 = @intCast((@as(u257, fastExpMod(x, 3)) + 7) % SECP256K1_P);
    var y = fastExpMod(rhs, (SECP256K1_P+1)/4); // get sqrt using Tonelli-Shanks algorithm (for p % 4 = 3)
    std.debug.assert(fastExpMod(y, 2) == rhs); // TODO: throw error if this happens?
    const tag_is_odd = compressed_pubkey[0] == 3;
    const y_is_odd = (y & 1) == 1;
    if (tag_is_odd != y_is_odd) { // fix parity (even/odd) if necessary
        y = SECP256K1_P - y;
    }
    var result: [65]u8 = undefined;
    result[0] = 4;
    @memcpy(result[1..33], compressed_pubkey[1..33]);
    mem.writeInt(u256, result[33..65], y, .big);
    return result;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3) {
        std.debug.print("Usage: {s} <infile> <outfile>\n", .{args[0]});
        std.process.exit(1);
    }
    const infile_path = args[1];
    const infile = fs.cwd().openFile(infile_path, .{ .mode = .read_only }) catch {
        std.debug.print("Error: provided input file '{s}' doesn't exist.\n", .{infile_path});
        std.process.exit(2);
    };
    defer infile.close();
    const outfile_path = args[2];
    // TODO: error if outfile *does* already exist

    // create database table
    var db: ?*s.sqlite3 = null;
    if (s.sqlite3_open_v2(outfile_path, &db, s.SQLITE_OPEN_READWRITE | s.SQLITE_OPEN_CREATE, null) != s.SQLITE_OK) {
        std.debug.print("Couldn't create SQLite3 database file \"{s}\".\n", .{outfile_path});
        std.process.exit(3);
    }
    defer _ = s.sqlite3_close(db);

    if (s.sqlite3_exec(db,
        "CREATE TABLE utxos(txid TEXT, vout INT, value INT, coinbase INT, height INT, scriptpubkey TEXT)",
        null, null, null) != s.SQLITE_OK) {
        std.debug.print("Couldn't create database table \"utxos\".\n", .{});
        std.process.exit(4);
    }

    // prepare file reading
    var io_buf: [64 * 1024]u8 = undefined;
    var infile_reader = infile.reader(&io_buf);
    var reader = &infile_reader.interface;

    // read in metadata (magic bytes, version, network magic, block hash, UTXO count)
    const magic_bytes = try reader.takeArray(5);
    const version = mem.readInt(u16, try reader.takeArray(2), .little);
    const network_magic = try reader.takeArray(4);
    const block_hash = try reader.takeArray(32);
    const num_utxos = mem.readInt(u64, try reader.takeArray(8), .little);
    if (!mem.eql(u8, magic_bytes, &UTXO_DUMP_MAGIC)) {
        std.debug.print("Error: provided input file '{s}' is not an UTXO dump.\n", .{infile_path});
        std.process.exit(5);
    }
    if (version != UTXO_DUMP_VERSION) {
        std.debug.print("Error: provided input file '{s}' has unknown UTXO dump version {d} " ++
            "(only version {d} supported)\n" , .{infile_path, version, UTXO_DUMP_VERSION});
        std.process.exit(5);
    }
    var network_name: []const u8 = "unknown network"; // TODO: include magic bytes in string if unknown
    for (0..NETWORKS.len) |i| {
        if (std.mem.eql(u8, network_magic, &NETWORKS[i].net_magic)) {
            network_name = NETWORKS[i].description;
            break;
        }
    }
    var block_hash_reverse = block_hash;
    std.mem.reverse(u8, block_hash_reverse);
    std.debug.print("UTXO Snapshot for {s} at block hash {x}..., contains {d} coins\n",
        .{network_name, block_hash_reverse[0..16], num_utxos});

    const start_time = std.time.nanoTimestamp();
    var coins_per_hash_left: u64 = 0;
    var prevout_hash: [32]u8 = undefined;
    var max_height: u64 = 0;
    var inserts_in_batch: u64 = 0;

    var script_buf: [10000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&script_buf);
    const alloc = fba.allocator();
    var insert_stmt: ?*s.sqlite3_stmt = null;
    if (s.sqlite3_prepare_v2(db, "INSERT INTO utxos VALUES(?, ?, ?, ?, ?, ?)", -1, &insert_stmt, null) != s.SQLITE_OK) {
        std.debug.print("Couldn't prepare SQLite3 insert statement.\n", .{});
        std.process.exit(6);
    }
    defer _ = s.sqlite3_finalize(insert_stmt);

    for (1..num_utxos+1) |coin_idx| {
        // read key (COutPoint)
        if (coins_per_hash_left == 0) { // read next prevout hash
            try reader.readSliceAll(&prevout_hash);
            coins_per_hash_left = try readCompactSize(reader);
        }
        const prevout_index = try readCompactSize(reader);
        // read value (Coin)
        const code = try readVarInt(reader);
        const height = code >> 1;
        const is_coinbase = (code & 1) == 1;
        const amount = decompressAmount(try readVarInt(reader));
        fba.reset();
        const scriptpubkey = try decompressScript(reader, alloc);
        // TODO: add to writing batch
        if (height > max_height) {
            max_height = height;
        }
        coins_per_hash_left -= 1;

        var ret: c_int = undefined;
        if (inserts_in_batch == 0) {
            ret = s.sqlite3_exec(db, "BEGIN TRANSACTION", null, null, null);
            std.debug.assert(ret == s.SQLITE_OK);
        }
        ret = s.sqlite3_reset(insert_stmt);
        std.debug.assert(ret == s.SQLITE_OK);
        // ret = s.sqlite3_clear_bindings(insert_stmt);
        // std.debug.assert(ret == s.SQLITE_OK);
        ret = s.sqlite3_bind_blob(insert_stmt, 1, (&prevout_hash).ptr, (&prevout_hash).len, s.SQLITE_STATIC);
        std.debug.assert(ret == s.SQLITE_OK);
        ret = s.sqlite3_bind_int(insert_stmt, 2, @intCast(prevout_index));
        std.debug.assert(ret == s.SQLITE_OK);
        ret = s.sqlite3_bind_int64(insert_stmt, 3, @intCast(amount));
        std.debug.assert(ret == s.SQLITE_OK);
        ret = s.sqlite3_bind_int(insert_stmt, 4, if (is_coinbase) 1 else 0);
        std.debug.assert(ret == s.SQLITE_OK);
        ret = s.sqlite3_bind_int(insert_stmt, 5, @intCast(height));
        std.debug.assert(ret == s.SQLITE_OK);
        ret = s.sqlite3_bind_blob(insert_stmt, 6, scriptpubkey.ptr, @intCast(scriptpubkey.len), s.SQLITE_STATIC);
        std.debug.assert(ret == s.SQLITE_OK);
        if (s.sqlite3_step(insert_stmt) != s.SQLITE_DONE) {
            std.debug.print("Error: INSERT failed.\n", .{});
            std.process.exit(7);
        }
        if (inserts_in_batch == 500 or coin_idx == num_utxos) {
            ret = s.sqlite3_exec(db, "COMMIT", null, null, null);
            std.debug.assert(ret == s.SQLITE_OK);
            inserts_in_batch = 0;
        }
        if (coin_idx % (1024*1024) == 0) {
            const elapsed_s = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time))/1_000_000_000.0;
            std.debug.print("{d} coins converted [{d:.2}%], {d:.3}s passed since start\n",
                .{coin_idx, @as(f64, @floatFromInt(coin_idx))/@as(f64, @floatFromInt(num_utxos))*100.0, elapsed_s});
        }
    }
    std.debug.print("TOTAL: {d} coins written to {s}, snapshot height is {d}.\n", .{num_utxos, outfile_path, max_height});
    // TODO: write warning if EOF is not reached yet from input file
}
