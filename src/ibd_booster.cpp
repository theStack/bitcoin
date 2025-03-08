// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <exception>
#include <ibd_booster.h>
#include <logging.h>
#include <streams.h>
#include <string>
#include <util/fs.h>

void IBDBoosterHints::Load(const std::string& filename)
{
    FILE* file = fsbridge::fopen(fs::u8path(filename), "rb");
    AutoFile hints_file(file);
    int block_height = 0;

    while (true) {
        uint16_t num_bits;
        hints_file >> num_bits;
        if (num_bits == 0) break; // end-marker

        std::vector<bool> bitmap;
        uint8_t byte;
        // read full bytes
        for (int i = 0; i < num_bits / 8; i++) {
            hints_file >> byte;
            for (int bit = 0; bit < 8; bit++) {
                bitmap.push_back((byte & (1 << bit)) != 0);
            }
        }
        // read remaining bits, if there are any
        int remaining_bits = num_bits % 8;
        if (remaining_bits > 0) {
            hints_file >> byte;
            for (int bit = 0; bit < remaining_bits; bit++) {
                bitmap.push_back((byte & (1 << bit)) != 0);
            }
        }
        block_outputs_bitmap[block_height] = bitmap;
        block_height++;
        if (block_height % 20000 == 0) {
            LogInfo("IBD Booster hints bitmap: %d blocks loaded...\n", block_height);
        }
    }

    final_block_height = block_height-1;
    is_loaded = true;
}

void IBDBoosterHints::SetCurrentBlockHeight(int block_height)
{
    // TODO: don't crash is hints for certain height are not available
    assert(block_outputs_bitmap.contains(block_height));
    current_bitmap = &block_outputs_bitmap[block_height];
    next_bit_pos = 0;
}

bool IBDBoosterHints::GetNextBit()
{
    bool result = current_bitmap->at(next_bit_pos);
    next_bit_pos++;
    return result;
}
