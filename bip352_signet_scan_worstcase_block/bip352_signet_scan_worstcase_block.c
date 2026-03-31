#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bitcoinkernel.h"
#include "secp256k1.h"
#include "secp256k1_silentpayments.h"

// 1-in-23230-out P2TR transaction exercising the targeted "worst-case scanning" attack:
// https://mempool.space/signet/block/00000002f010f4f0dcc89bb3cf951e70d59d8be04fa6fd2d281842c0ba6e02a2
// https://mempool.space/signet/tx/e429ec8858d0b34d7e05f1ce178ada4ae197fa7186830613a304c59f9687a80e
#define SP_WORST_CASE_ATTACK_BLOCK_HEIGHT 297894
#define SP_LABEL_INTEGER_M 0

static unsigned char scan_secret_key[32] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
};
static unsigned char spend_secret_key[32] = {
    0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
    0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
};

void print_bytes_rev(uint8_t* data, size_t size) { for (int i = size-1; i >= 0; i--) printf("%02x", data[i]); }

struct span_t {
    unsigned char* data;
    size_t size;
};

int write_bytes_callback(const void* bytes, size_t size, void* userdata)
{
    /* TODO: optimize this by over-allocating in order to avoid the need of frequent reallocations */
    struct span_t* wbc = userdata;
    if (wbc->size == 0) { /* initial memory allocation */
        assert(wbc->data == NULL);
        wbc->data = malloc(size);
        if (wbc->data == NULL) return 1;
    } else { /* reallocation */
        assert(wbc->data != NULL);
        wbc->data = realloc(wbc->data, wbc->size + size);
        if (wbc->data == NULL) return 1;
    }
    memcpy(wbc->data + wbc->size, bytes, size);
    wbc->size += size;
    return 0;
}

void get_xonly_pubkey_from_output(secp256k1_xonly_pubkey* xpk, unsigned char* xpk_bytes, const btck_TransactionOutput* tx_output)
{
    const btck_ScriptPubkey* spk = btck_transaction_output_get_script_pubkey(tx_output);
    assert(spk != NULL);
    struct span_t spk_ser = {0};
    int ret = btck_script_pubkey_to_bytes(spk, write_bytes_callback, &spk_ser);
    assert(ret == 0);
    /* check that outputs are P2TR */
    assert(spk_ser.size == 34 && spk_ser.data[0] == 0x51 && spk_ser.data[1] == 0x20);
    if (xpk_bytes != NULL) memcpy(xpk_bytes, spk_ser.data+2, 32);
    if (xpk != NULL) {
        ret = secp256k1_xonly_pubkey_parse(secp256k1_context_static, xpk, spk_ser.data+2);
        assert(ret == 1);
    }
}

struct label_cache_entry {
    unsigned char label[33];
    unsigned char label_tweak[32];
};

struct labels_cache {
    size_t entries_used;
    struct label_cache_entry entries[5];
};

const unsigned char* label_lookup(const unsigned char* label33, const void* cache_ptr)
{
    const struct labels_cache* cache = (const struct labels_cache*)cache_ptr;
    size_t i;
    for (i = 0; i < cache->entries_used; i++) {
        if (memcmp(cache->entries[i].label, label33, 33) == 0) {
            return cache->entries[i].label_tweak;
        }
    }
    return NULL;
}

struct scanning_data {
    secp256k1_context *ctx;
    secp256k1_pubkey spend_public_key;
    secp256k1_silentpayments_label label;
    unsigned char label_tweak[32];
    struct label_cache_entry label_cache_entry;
    struct labels_cache labels_cache;

    unsigned char smallest_outpoint[36];
    size_t num_outs;
    secp256k1_xonly_pubkey outputs[40000];
    const secp256k1_xonly_pubkey* outputs_ptrs_original_order[40000];
    const secp256k1_xonly_pubkey* outputs_ptrs[40000];
    secp256k1_silentpayments_found_output found_outputs[40000];
    secp256k1_silentpayments_found_output* found_outputs_ptrs[40000];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
};

void perform_scanning_benchmark(const char* desc, struct scanning_data* sd, int disable_k_max, int shuffle_outputs)
{
    struct timespec start, end;
    int i;

    secp256k1_silentpayments_disable_k_max_limit(sd->ctx, disable_k_max);
    for (i = 0; i < sd->num_outs; i++) { /* restore original (worst-case) outputs order */
        sd->outputs_ptrs[i] = sd->outputs_ptrs_original_order[i];
    }
    if (shuffle_outputs) { /* randomize outputs using fisher-yates shuffle */
        for (i = sd->num_outs - 1; i > 0; i--) {
            int j = rand() % (i + 1);
            const secp256k1_xonly_pubkey* tmp = sd->outputs_ptrs[i];
            sd->outputs_ptrs[i] = sd->outputs_ptrs[j];
            sd->outputs_ptrs[j] = tmp;
        }
    }

    printf("-> %s: ", desc); fflush(stdout);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    uint32_t n_found_outputs = 0;
    int ret = secp256k1_silentpayments_recipient_scan_outputs(sd->ctx, sd->found_outputs_ptrs, &n_found_outputs,
        sd->outputs_ptrs, sd->num_outs, scan_secret_key, &sd->prevouts_summary, &sd->spend_public_key,
        label_lookup, &sd->labels_cache);
    assert(ret == 1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    double elapsed_ns = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);
    printf("scanning took %.3f seconds (%3d outputs found)\n", elapsed_ns/1000000000, n_found_outputs);
}

int main()
{
    int ret;
    unsigned char datadir[1024];
    unsigned char blocksdir[1024];
    const char* homedir = getenv("HOME");
    assert(homedir != NULL);
    snprintf(datadir, sizeof(datadir), "%s/.bitcoin/signet", homedir);
    snprintf(blocksdir, sizeof(blocksdir), "%s/.bitcoin/signet/blocks", homedir);

    printf("Create signet chainstate manager with datadir \"%s\"...\n", datadir);
    btck_ChainParameters* chain_params = btck_chain_parameters_create(btck_ChainType_SIGNET);
    assert(chain_params != NULL);
    btck_ContextOptions* context_options = btck_context_options_create();
    assert(context_options != NULL);
    btck_context_options_set_chainparams(context_options, chain_params);
    btck_Context* context = btck_context_create(context_options);
    assert(context != NULL);
    btck_ChainstateManagerOptions* chainman_options = btck_chainstate_manager_options_create(
        context, datadir, strlen(datadir), blocksdir, strlen(blocksdir));
    assert(chainman_options != NULL);
    btck_ChainstateManager* chainman = btck_chainstate_manager_create(chainman_options);
    assert(chainman != NULL);
    const btck_Chain* chain = btck_chainstate_manager_get_active_chain(chainman);
    assert(chain != NULL);

    printf("Load SP worst-case scanning demo block at height %d...\n\n", SP_WORST_CASE_ATTACK_BLOCK_HEIGHT);
    const btck_BlockTreeEntry* entry = btck_chain_get_by_height(chain, SP_WORST_CASE_ATTACK_BLOCK_HEIGHT);
    assert(entry != NULL);
    btck_Block* block = btck_block_read(chainman, entry);
    assert(block != NULL);
    btck_BlockSpentOutputs* block_undo = btck_block_spent_outputs_read(chainman, entry);
    assert(block_undo != NULL);

    size_t num_txs = btck_block_count_transactions(block);
    assert(num_txs == 2);
    const btck_Transaction* tx_worstcase = btck_block_get_transaction_at(block, 1);
    assert(tx_worstcase != NULL);
    const btck_Txid* txid_worstcase = btck_transaction_get_txid(tx_worstcase);
    assert(txid_worstcase != NULL);
    unsigned char txid_worstcase_bytes[32];
    btck_txid_to_bytes(txid_worstcase, &txid_worstcase_bytes[0]);
    size_t num_undo_txs = btck_block_spent_outputs_count(block_undo);
    assert(num_undo_txs == 1);
    const btck_TransactionSpentOutputs* tx_worstcase_prevouts = btck_block_spent_outputs_get_transaction_spent_outputs_at(block_undo, 0);
    assert(tx_worstcase_prevouts != NULL);

    /* fetch tx input */
    static struct scanning_data sd;
    size_t num_tx_worstcase_prevouts = btck_transaction_spent_outputs_count(tx_worstcase_prevouts);
    assert(num_tx_worstcase_prevouts == 1);
    const btck_Coin* prevout_coin = btck_transaction_spent_outputs_get_coin_at(tx_worstcase_prevouts, 0);
    assert(prevout_coin != NULL);
    const btck_TransactionOutput* prevout_output = btck_coin_get_output(prevout_coin);
    assert(prevout_output != NULL);
    secp256k1_xonly_pubkey input_pubkey;
    get_xonly_pubkey_from_output(&input_pubkey, NULL, prevout_output);
    const secp256k1_xonly_pubkey* input_pubkey_ptr = &input_pubkey;

    size_t num_ins = btck_transaction_count_inputs(tx_worstcase);
    assert(num_ins == 1);
    const btck_TransactionInput* prevout_input = btck_transaction_get_input_at(tx_worstcase, 0);
    assert(prevout_input != NULL);
    const btck_TransactionOutPoint* outpoint = btck_transaction_input_get_out_point(prevout_input);
    assert(outpoint != NULL);
    const btck_Txid* outpoint_txid = btck_transaction_out_point_get_txid(outpoint);
    assert(outpoint_txid != NULL);
    uint32_t outpoint_index = btck_transaction_out_point_get_index(outpoint);
    btck_txid_to_bytes(outpoint_txid, &sd.smallest_outpoint[0]);
    sd.smallest_outpoint[32] = outpoint_index;
    sd.smallest_outpoint[33] = outpoint_index >> 8;
    sd.smallest_outpoint[34] = outpoint_index >> 16;
    sd.smallest_outpoint[35] = outpoint_index >> 24;

    /* fetch tx outputs */
    sd.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(sd.ctx != NULL);
    sd.num_outs = btck_transaction_count_outputs(tx_worstcase);
    printf("Scanning %ld-in-%ld-out tx ", num_ins, sd.num_outs); print_bytes_rev(txid_worstcase_bytes, 32); printf("...\n");
    for (int i = 0; i < sd.num_outs; i++) {
        const btck_TransactionOutput* tx_output = btck_transaction_get_output_at(tx_worstcase, i);
        assert(tx_output != NULL);
        unsigned char xpk_ser[32];
        get_xonly_pubkey_from_output(&sd.outputs[i], xpk_ser, tx_output);
        sd.outputs_ptrs_original_order[i] = &sd.outputs[i];
        sd.found_outputs_ptrs[i] = &sd.found_outputs[i];
    }

    /* create Silent Payments key and label material */
    ret = secp256k1_ec_pubkey_create(sd.ctx, &sd.spend_public_key, spend_secret_key);
    assert(ret == 1);
    ret = secp256k1_silentpayments_recipient_label_create(sd.ctx, &sd.label, sd.label_tweak, scan_secret_key, SP_LABEL_INTEGER_M);
    assert(ret == 1);
    ret = secp256k1_silentpayments_recipient_label_serialize(sd.ctx, sd.label_cache_entry.label, &sd.label);
    assert(ret == 1);
    memcpy(sd.label_cache_entry.label_tweak, sd.label_tweak, 32);
    sd.labels_cache.entries_used = 1;
    sd.labels_cache.entries[0] = sd.label_cache_entry;

    /* scan transaction */
    ret = secp256k1_silentpayments_recipient_prevouts_summary_create(sd.ctx, &sd.prevouts_summary, sd.smallest_outpoint,
        &input_pubkey_ptr, 1, NULL, 0);
    assert(ret == 1);

    perform_scanning_benchmark("Uncapped K [worst-case order]", &sd, /*disable_k_max=*/1, /*shuffle_outputs=*/0);
    perform_scanning_benchmark("Uncapped K [shuffled outputs]", &sd, /*disable_k_max=*/1, /*shuffle_outputs=*/1);
    perform_scanning_benchmark("K_max=2323 [worst-case order]", &sd, /*disable_k_max=*/0, /*shuffle_outputs=*/0);
    perform_scanning_benchmark("K_max=2323 [shuffled outputs]", &sd, /*disable_k_max=*/0, /*shuffle_outputs=*/1);

    secp256k1_context_destroy(sd.ctx);
    btck_block_spent_outputs_destroy(block_undo);
    btck_block_destroy(block);
    btck_chain_parameters_destroy(chain_params);
    btck_context_options_destroy(context_options);
    btck_context_destroy(context);
    btck_chainstate_manager_options_destroy(chainman_options);
    btck_chainstate_manager_destroy(chainman);

    return 0;
}
