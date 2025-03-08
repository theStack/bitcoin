// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWIFTSYNC_H
#define BITCOIN_SWIFTSYNC_H

#include <map>
#include <string>
#include <vector>

class SwiftSyncHints
{
public:
    void Load(const std::string &filename);
    bool IsLoaded() const { return is_loaded; }
    int  GetTerminalBlockHeight() const { return terminal_block_height; }
    void SetCurrentBlockHeight(int block_height);
    bool GetNextBit();
    int  GetNextBitPos() { return next_bit_pos; }

private:
    bool is_loaded{false};
    int terminal_block_height;
    std::vector<bool> *current_bitmap;
    int next_bit_pos;
    std::map<int, std::vector<bool>> block_outputs_bitmap;
};

#endif
