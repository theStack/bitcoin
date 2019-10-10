// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>

#include <bench/bench.h>
#include <bloom.h>
#include <util/strencodings.h>

static void RollingBloom(benchmark::State& state)
{
    CRollingBloomFilter filter(120000, 0.000001);
    std::vector<unsigned char> data(32);
    uint32_t count = 0;
    while (state.KeepRunning()) {
        count++;
        data[0] = count;
        data[1] = count >> 8;
        data[2] = count >> 16;
        data[3] = count >> 24;
        filter.insert(data);

        data[0] = count >> 24;
        data[1] = count >> 16;
        data[2] = count >> 8;
        data[3] = count;
        filter.contains(data);
    }
}

static void RollingBloomReset(benchmark::State& state)
{
    CRollingBloomFilter filter(120000, 0.000001);
    while (state.KeepRunning()) {
        filter.reset();
    }
}

// TODO: move this into separate file bloom.cpp
static CBloomFilter CreateFullBloomFilter()
{
    CBloomFilter filter(10, 0.01, 0, BLOOM_UPDATE_ALL);
    for (int i = 0; i < 200; i++)
        filter.insert(std::vector<unsigned char>(1, i));
    return filter;
}

static void BloomFull_Regular_Contains(benchmark::State& state)
{
    CBloomFilter filter = CreateFullBloomFilter();
    std::vector<unsigned char> element = ParseHex("affe1234");

    while (state.KeepRunning()) {
        filter.contains(element);
    }
}

static void BloomFull_Regular_Insert(benchmark::State& state)
{
    CBloomFilter filter = CreateFullBloomFilter();
    std::vector<unsigned char> element = ParseHex("affe1234");

    while (state.KeepRunning()) {
        filter.insert(element);
    }
}

static void BloomFull_UpdateEmptyFull_Contains(benchmark::State& state)
{
    CBloomFilter filter = CreateFullBloomFilter();
    std::vector<unsigned char> element = ParseHex("affe1234");
    filter.UpdateEmptyFull();

    while (state.KeepRunning()) {
        filter.contains(element);
    }
}

static void BloomFull_UpdateEmptyFull_Insert(benchmark::State& state)
{
    CBloomFilter filter = CreateFullBloomFilter();
    std::vector<unsigned char> element = ParseHex("affe1234");
    filter.UpdateEmptyFull();

    while (state.KeepRunning()) {
        filter.insert(element);
    }
}

BENCHMARK(RollingBloom, 1500 * 1000);
BENCHMARK(RollingBloomReset, 20000);
BENCHMARK(BloomFull_Regular_Contains, 21 * 1000000);
BENCHMARK(BloomFull_Regular_Insert, 21 * 1000000);
BENCHMARK(BloomFull_UpdateEmptyFull_Contains, 21 * 1000000);
BENCHMARK(BloomFull_UpdateEmptyFull_Insert, 21 * 1000000);
