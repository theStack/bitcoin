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
    void SetCurrentBlockHeight(int block_height);
    bool GetNextBit();

private:
    bool is_loaded{false};
    std::vector<bool> *current_bitmap;
    int next_bit_pos;
    std::map<int, std::vector<bool>> block_outputs_bitmap;
};

#endif
