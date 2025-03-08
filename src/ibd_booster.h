// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IBD_BOOSTER_H
#define BITCOIN_IBD_BOOSTER_H

#include <map>
#include <string>
#include <vector>

class IBDBoosterHints
{
public:
    void Load(const std::string &filename);
    bool IsLoaded() const { return is_loaded; }
    int  GetFinalBlockHeight() const { return final_block_height; }
    void SetCurrentBlockHeight(int block_height);
    bool GetNextBit();
    int  GetNextBitPos() { return next_bit_pos; }

private:
    bool is_loaded{false};
    int final_block_height;
    std::vector<bool> *current_bitmap;
    int next_bit_pos;
    std::map<int, std::vector<bool>> block_outputs_bitmap;
};

#endif
