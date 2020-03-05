/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define CONSENSUS_BRANCH_ID_OVERWINTER 0x5ba81b19
#define CONSENSUS_BRANCH_ID_SAPLING 0x76b809bb
#define CONSENSUS_BRANCH_ID_ZCLASSIC 0x930b540d

#define DEBUG_LONG "%d"

void check_transaction_available(unsigned char x) {
    if (btchip_context_D.transactionDataRemaining < x) {
        //PRINTF("Check transaction available failed %d < %d\n", btchip_context_D.transactionDataRemaining, x);
        THROW(EXCEPTION);
    }
    ////PRINTF("Check transaction available succeeded: %d > %d\n", btchip_context_D.transactionDataRemaining, x);
}

#define OP_HASH160 0xA9
#define OP_EQUAL 0x87
#define OP_CHECKMULTISIG 0xAE

unsigned char transaction_amount_add_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char carry = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short val = a[8 - 1 - i] + b[8 - 1 - i] + (carry ? 1 : 0);
        carry = (val > 255);
        target[8 - 1 - i] = (val & 255);
    }
    return carry;
}

unsigned char transaction_amount_sub_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char borrow = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short tmpA = a[8 - 1 - i];
        unsigned short tmpB = b[8 - 1 - i];
        if (borrow) {
            if (tmpA <= tmpB) {
                tmpA += (255 + 1) - 1;
            } else {
                borrow = 0;
                tmpA--;
            }
        }
        if (tmpA < tmpB) {
            borrow = 1;
            tmpA += 255 + 1;
        }
        target[8 - 1 - i] = (unsigned char)(tmpA - tmpB);
    }

    return borrow;
}

void transaction_offset(unsigned char value) {
    if ((btchip_context_D.transactionHashOption & TRANSACTION_HASH_FULL) != 0) {
        //////PRINTF("Add to hash full\n%.*H\n",value,btchip_context_D.transactionBufferPointer);
        if (btchip_context_D.usingOverwinter) {
            cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.transactionBufferPointer, value, NULL, 0);
        }
        else {
            cx_hash(&btchip_context_D.transactionHashFull.sha256.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0);
        }
    }
    if ((btchip_context_D.transactionHashOption &
         TRANSACTION_HASH_AUTHORIZATION) != 0) {
        cx_hash(&btchip_context_D.transactionHashAuthorization.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0);
    }
}

void transaction_offset_increase(unsigned char value) {
    transaction_offset(value);
    btchip_context_D.transactionBufferPointer += value;
    btchip_context_D.transactionDataRemaining -= value;
}

unsigned long int transaction_get_varint(void) {
    ////PRINTF("transaction_get_varint - reading first byte\n");
    unsigned char firstByte;
    check_transaction_available(1);
    firstByte = *btchip_context_D.transactionBufferPointer;
    ////PRINTF("transaction_get_varint - read first byte\n");
    if (firstByte < 0xFD) {
        ////PRINTF("transaction_get_varint - 1 byte\n");
        transaction_offset_increase(1);
        return firstByte;
    } else if (firstByte == 0xFD) {
        ////PRINTF("transaction_get_varint - 2 bytes\n");
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(2);
        result =
            (unsigned long int)(*btchip_context_D.transactionBufferPointer) |
            ((unsigned long int)(*(btchip_context_D.transactionBufferPointer +
                                   1))
             << 8);
        transaction_offset_increase(2);
        return result;
    } else if (firstByte == 0xFE) {
        ////PRINTF("transaction_get_varint - 4 bytes\n");
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(4);
        result =
            btchip_read_u32(btchip_context_D.transactionBufferPointer, 0, 0);
        transaction_offset_increase(4);
        return result;
    } else {
        //PRINTF("Varint parsing failed\n");
        THROW(INVALID_PARAMETER);
        return 0;
    }
}

void transaction_parse(unsigned char parseMode) {
    unsigned char optionP2SHSkip2FA =
        ((N_btchip.bkp.config.options & BTCHIP_OPTION_SKIP_2FA_P2SH) != 0);
    btchip_set_check_internal_structure_integrity(0);
    BEGIN_TRY {
        TRY {
            for (;;) {
                switch (btchip_context_D.transactionContext.transactionState) {
                case BTCHIP_TRANSACTION_NONE: {
                    // Reset transaction state
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs = 0;
                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;
                    btchip_context_D.transactionContext.scriptRemaining = 0;
                    os_memset(
                        btchip_context_D.transactionContext.transactionAmount,
                        0, sizeof(btchip_context_D.transactionContext
                                      .transactionAmount));
                    // TODO : transactionControlFid
                    // Reset hashes
		    ////PRINTF("Reset hashes...\n");
                    if (btchip_context_D.usingOverwinter) {
		      ////PRINTF("Using overwinter...\n");
                        if (btchip_context_D.segwitParsedOnce) {
                            uint8_t parameters[16];
                            os_memmove(parameters, OVERWINTER_PARAM_SIGHASH, 16);
                            if (G_coin_config->kind == COIN_KIND_ZCLASSIC) {
                                btchip_write_u32_le(parameters + 12, CONSENSUS_BRANCH_ID_ZCLASSIC);
                            }
                            else {
                                btchip_write_u32_le(parameters + 12,
                                    btchip_context_D.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING ?
                                    (G_coin_config->zcash_consensus_branch_id != 0 ? G_coin_config->zcash_consensus_branch_id : CONSENSUS_BRANCH_ID_SAPLING) : CONSENSUS_BRANCH_ID_OVERWINTER);
                            }
                            cx_blake2b_init2(&btchip_context_D.transactionHashFull.blake2b, 256, NULL, 0, parameters, 16);
                        }
                    }
                    else {
		      ////PRINTF("Not using overwinter...\n");
                        cx_sha256_init(&btchip_context_D.transactionHashFull.sha256);
                    }
                    cx_sha256_init(
                        &btchip_context_D.transactionHashAuthorization);
                    if (btchip_context_D.usingSegwit) {
		      ////PRINTF("Using segwit...\n");
                        btchip_context_D.transactionHashOption = 0;
                        if (!btchip_context_D.segwitParsedOnce) {
                            if (btchip_context_D.usingOverwinter) {
                                cx_blake2b_init2(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, 256, NULL, 0, OVERWINTER_PARAM_PREVOUTS, 16);
                                cx_blake2b_init2(&btchip_context_D.transactionHashFull.blake2b, 256, NULL, 0, OVERWINTER_PARAM_SEQUENCE, 16);
                            }
                            else {
                                cx_sha256_init(
                                    &btchip_context_D.segwit.hash.hashPrevouts.sha256);
                            }
                        } else {
                            ////PRINTF("Resume SegWit hash\n");
                            ////PRINTF("SEGWIT Version\n%.*H\n",sizeof(btchip_context_D.transactionVersion),btchip_context_D.transactionVersion);
                            ////PRINTF("SEGWIT HashedPrevouts\n%.*H\n",sizeof(btchip_context_D.segwit.cache.hashedPrevouts),btchip_context_D.segwit.cache.hashedPrevouts);
                            ////PRINTF("SEGWIT HashedSequence\n%.*H\n",sizeof(btchip_context_D.segwit.cache.hashedSequence),btchip_context_D.segwit.cache.hashedSequence);
                            if (btchip_context_D.usingOverwinter) {
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.transactionVersion, sizeof(btchip_context_D.transactionVersion), NULL, 0);
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.nVersionGroupId, sizeof(btchip_context_D.nVersionGroupId), NULL, 0);
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.segwit.cache.hashedPrevouts, sizeof(btchip_context_D.segwit.cache.hashedPrevouts), NULL, 0);
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.segwit.cache.hashedSequence, sizeof(btchip_context_D.segwit.cache.hashedSequence), NULL, 0);
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.segwit.cache.hashedOutputs, sizeof(btchip_context_D.segwit.cache.hashedOutputs), NULL, 0);
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0);
                                if (btchip_context_D.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING) {
                                    cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0); // sapling hashShieldedSpends
                                    cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0); // sapling hashShieldedOutputs
                                }
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.nLockTime, sizeof(btchip_context_D.nLockTime), NULL, 0);
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.nExpiryHeight, sizeof(btchip_context_D.nExpiryHeight), NULL, 0);
                                if (btchip_context_D.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING) {
                                    unsigned char valueBalance[8];
                                    os_memset(valueBalance, 0, sizeof(valueBalance));
                                    cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, valueBalance, sizeof(valueBalance), NULL, 0); // sapling valueBalance
                                }
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.sigHashType, sizeof(btchip_context_D.sigHashType), NULL, 0);
                            }
                            else {
                                cx_hash(
                                    &btchip_context_D.transactionHashFull.sha256.header, 0,
                                    btchip_context_D.transactionVersion,
                                    sizeof(btchip_context_D.transactionVersion),
                                    NULL, 0);
                                cx_hash(
                                    &btchip_context_D.transactionHashFull.sha256.header, 0,
                                    btchip_context_D.segwit.cache.hashedPrevouts,
                                    sizeof(btchip_context_D.segwit.cache
                                           .hashedPrevouts),
                                    NULL, 0);
                                cx_hash(
                                    &btchip_context_D.transactionHashFull.sha256.header, 0,
                                    btchip_context_D.segwit.cache.hashedSequence,
                                    sizeof(btchip_context_D.segwit.cache
                                           .hashedSequence),
                                    NULL, 0);
                                cx_hash(&btchip_context_D
                                         .transactionHashAuthorization.header,
                                    0,
                                    (unsigned char *)&btchip_context_D
                                        .segwit.cache,
                                    sizeof(btchip_context_D.segwit.cache),
                                    NULL, 0);
                            }
                        }
                    }

/*
    DGLD Transaction sample - header
    02000000    version
    01          flag

    01          # of vins
 */
		    
                    // Parse the beginning of the transaction
                    // Version
		    ////PRINTF("Parse beginning of transaction - check transaction available...\n");
                    check_transaction_available(4);
		    ////PRINTF("Getting version...\n");
                    os_memmove(btchip_context_D.transactionVersion,
                               btchip_context_D.transactionBufferPointer, 4);
                    transaction_offset_increase(4);

                    if (btchip_context_D.usingOverwinter) {
                        // nVersionGroupId
                        check_transaction_available(4);
                        os_memmove(btchip_context_D.nVersionGroupId,
                               btchip_context_D.transactionBufferPointer, 4);
                        transaction_offset_increase(4);
                    }

                    if (G_coin_config->flags & FLAG_PEERCOIN_SUPPORT) {
                        if ((btchip_context_D.coinFamily ==
                            BTCHIP_FAMILY_PEERCOIN) || 
                            ((btchip_context_D.coinFamily == BTCHIP_FAMILY_STEALTH) && 
                            (btchip_context_D.transactionVersion[0] < 2))) {
                            // Timestamp
                            check_transaction_available(4);
                            transaction_offset_increase(4);
                        }
                    }

		    //If using DGLD, the next byte to read in will be a 'flag'.
                    if(G_coin_config->kind == COIN_KIND_DGLD){
		      ////PRINTF("Coin kind DGLD - reading flag...\n");
                        //Flag
		      ////PRINTF("Checking transaction available...\n");
                        check_transaction_available(1);
			////PRINTF("Copying flag data...\n");
			btchip_context_D.transactionContext.transactionFlag =
			  *btchip_context_D.transactionBufferPointer;
			////PRINTF("Increasing transaction offset...\n");
                        transaction_offset_increase(1);
                    }

                    // Number of inputs
		    ////PRINTF("Reading number of inputs...\n");
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    ////PRINTF("Number of inputs : " DEBUG_LONG "\n",btchip_context_D.transactionContext.transactionRemainingInputsOutputs);
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;

                    // no break is intentional
                }

/*
    DGLD transaction sample - inputs

    0000000000000000000000000000000000000000000000000000000000000000    vin prevhash
    ffffffff    vin prev_idx
    03  530101  script
    ffffffff    sequence
        - issuance example (if prev_idx & TxInputDGLD.OUTPOINT_ISSUANCE_FLAG)
        0000000000000000000000000000000000000000000000000000000000000000    nonce 32bytes
        0000000000000000000000000000000000000000000000000000000000000000    entropy 32bytes
        01  00038d7ea4c68000  amount (confidential value)
        00                    inflation (confidential value)


*/
		  
                case BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT: {
                    unsigned char trustedInputFlag = 1;
                    ////PRINTF("Process input\n");
                    if (btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more inputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_INPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Proceed with the next input
                    if (parseMode == PARSE_MODE_TRUSTED_INPUT) {
		        ////PRINTF("Parse mode: trusted input\n");
                        check_transaction_available(
                            36); // prevout : 32 hash + 4 index
                        transaction_offset_increase(36);
                    }
                    if (parseMode == PARSE_MODE_SIGNATURE) {
		        ////PRINTF("Parse mode: signature\n");
                        unsigned char trustedInputLength;
                        unsigned char trustedInput[0x38];
                        unsigned char amount[8];
                        unsigned char *savePointer;

                        // Expect the trusted input flag and trusted input
                        // length
                        check_transaction_available(2);
                        switch (*btchip_context_D.transactionBufferPointer) {
                        case 0:
                            if (btchip_context_D.usingSegwit) {
			        ////PRINTF("Non trusted input used in segwit mode");
                                goto fail;
                            }
                            trustedInputFlag = 0;
                            break;
                        case 1:
                            if (btchip_context_D.usingSegwit) {
                                ////PRINTF("Trusted input used in segwit mode");
                                goto fail;
                            }
                            trustedInputFlag = 1;
                            break;
                        case 2:
                            if (!btchip_context_D.usingSegwit) {
                                ////PRINTF("Segwit input not used in segwit mode");
                                goto fail;
                            }
                            break;
                        default:
                            //PRINTF("Invalid trusted input flag\n");
                            goto fail;
                        }
                        /*
                        trustedInputLength =
                        *(btchip_context_D.transactionBufferPointer + 1);
                        if (trustedInputLength > sizeof(trustedInput)) {
                          //PRINTF("Trusted input too long\n");
                          goto fail;
                        }
                        */
                        if (btchip_context_D.usingSegwit) {
                            transaction_offset_increase(1);
                            check_transaction_available(
                                36); // prevout : 32 hash + 4 index
                            if (!btchip_context_D.segwitParsedOnce) {
                                if (btchip_context_D.usingOverwinter) {
                                    cx_hash(&btchip_context_D.segwit.hash.hashPrevouts.blake2b.header, 0, btchip_context_D.transactionBufferPointer, 36, NULL, 0);
                                }
                                else {
                                    cx_hash(
                                        &btchip_context_D.segwit.hash.hashPrevouts
                                         .sha256.header,
                                        0,
                                        btchip_context_D.transactionBufferPointer,
                                        36, NULL, 0);
                                }
                                transaction_offset_increase(36);
                                check_transaction_available(8); // update amount
                                btchip_swap_bytes(
                                    amount,
                                    btchip_context_D.transactionBufferPointer,
                                    8);
                                if (transaction_amount_add_be(
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                        amount)) {
                                    //PRINTF("Overflow\n");
                                    goto fail;
                                }
                                ////PRINTF("Adding amount\n%.*H\n",8,btchip_context_D.transactionBufferPointer);
                                ////PRINTF("New amount\n%.*H\n",8,btchip_context_D.transactionContext.transactionAmount);
                                transaction_offset_increase(8);
                            } else {
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                                transaction_offset_increase(36);
                                btchip_context_D.transactionHashOption = 0;
                                check_transaction_available(8); // save amount
                                os_memmove(
                                    btchip_context_D.inputValue,
                                    btchip_context_D.transactionBufferPointer,
                                    8);
                                transaction_offset_increase(8);
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                            }
                        } else if (!trustedInputFlag) {
                            // Only authorized in relaxed wallet and server
                            // modes
                            SB_CHECK(N_btchip.bkp.config.operationMode);
                            switch (SB_GET(N_btchip.bkp.config.operationMode)) {
                            case BTCHIP_MODE_WALLET:
                                if (!optionP2SHSkip2FA) {
                                    //PRINTF("Untrusted input not authorized\n");
                                    goto fail;
                                }
                                break;
                            case BTCHIP_MODE_RELAXED_WALLET:
                            case BTCHIP_MODE_SERVER:
                                break;
                            default:
                                //PRINTF("Untrusted input not authorized\n");
                                goto fail;
                            }
                            btchip_context_D.transactionBufferPointer++;
                            btchip_context_D.transactionDataRemaining--;
                            check_transaction_available(
                                36); // prevout : 32 hash + 4 index
                            transaction_offset_increase(36);
                            ////PRINTF("Marking relaxed input\n");
                            btchip_context_D.transactionContext.relaxed = 1;
                            /*
                            ////PRINTF("Clearing P2SH consumption\n");
                            btchip_context_D.transactionContext.consumeP2SH = 0;
                            */
                        } else {
                            trustedInputLength = *(
                                btchip_context_D.transactionBufferPointer + 1);
                            if ((trustedInputLength > sizeof(trustedInput)) ||
                                (trustedInputLength < 8)) {
			        //PRINTF("Invalid trusted input size: %d - expected < %d, > %d\n", trustedInputLength, sizeof(trustedInput), 8);
                                goto fail;
                            }

                            check_transaction_available(2 + trustedInputLength);
                            cx_hmac_sha256(
                                N_btchip.bkp.trustedinput_key,
                                sizeof(N_btchip.bkp.trustedinput_key),
                                btchip_context_D.transactionBufferPointer + 2,
                                trustedInputLength - 8, trustedInput, trustedInputLength);
                            if (btchip_secure_memcmp(
                                    trustedInput,
                                    btchip_context_D.transactionBufferPointer +
                                        2 + trustedInputLength - 8,
                                    8) != 0) {
                                //PRINTF("Invalid signature\n");
                                goto fail;
                            }
                            os_memmove(
                                trustedInput,
                                btchip_context_D.transactionBufferPointer + 2,
                                trustedInputLength - 8);
                            if (trustedInput[0] != MAGIC_TRUSTED_INPUT) {
                                //PRINTF("Failed to verify trusted input signature\n");
                                goto fail;
                            }
                            // Update the hash with prevout data
                            savePointer =
                                btchip_context_D.transactionBufferPointer;
                            /*
                            // Check if a P2SH script is used
                            if ((trustedInput[1] & FLAG_TRUSTED_INPUT_P2SH) ==
                            0) {
                              ////PRINTF("Clearing P2SH consumption\n");
                              btchip_context_D.transactionContext.consumeP2SH =
                            0;
                            }
                            */
                            btchip_context_D.transactionBufferPointer =
                                trustedInput + 4;
                            ////PRINTF("Trusted input hash\n%.*H\n",36,btchip_context_D.transactionBufferPointer);
                            transaction_offset(36);

                            btchip_context_D.transactionBufferPointer =
                                savePointer + (2 + trustedInputLength);
                            btchip_context_D.transactionDataRemaining -=
                                (2 + trustedInputLength);

                            // Update the amount

                            btchip_swap_bytes(amount, trustedInput + 40, 8);
                            if (transaction_amount_add_be(
                                    btchip_context_D.transactionContext
                                        .transactionAmount,
                                    btchip_context_D.transactionContext
                                        .transactionAmount,
                                    amount)) {
                                //PRINTF("Overflow\n");
                                goto fail;
                            }

                            ////PRINTF("Adding amount\n%.*H\n",8,(trustedInput + 40));
                            ////PRINTF("New amount\n%.*H\n",8,btchip_context_D.transactionContext.transactionAmount);
                        }

                        if (!btchip_context_D.usingSegwit) {
                            // Do not include the input script length + value in
                            // the authentication hash
                            btchip_context_D.transactionHashOption =
                                TRANSACTION_HASH_FULL;
                        }
                    }
                    // Read the script length
                    btchip_context_D.transactionContext.scriptRemaining =
                        transaction_get_varint();
                    ////PRINTF("Script to read " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);

                    if ((parseMode == PARSE_MODE_SIGNATURE) &&
                        !trustedInputFlag && !btchip_context_D.usingSegwit) {
                        // Only proceeds if this is not to be signed - so length
                        // should be null
                        if (btchip_context_D.transactionContext
                                .scriptRemaining != 0) {
                            ////PRINTF("Request to sign relaxed input\n");
                            if (!optionP2SHSkip2FA) {
                                goto fail;
                            }
                        }
                    }
                    // Move on
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;

                    // no break is intentional
                }
                case BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    ////PRINTF("Process input script, remaining " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Scan for P2SH consumption - huge shortcut, but fine
                    // enough
                    // Also usable in SegWit mode
                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        1) {
                        if (*btchip_context_D.transactionBufferPointer ==
                            OP_CHECKMULTISIG) {
                            if (optionP2SHSkip2FA) {
                                ////PRINTF("Marking P2SH consumption\n");
                                btchip_context_D.transactionContext
                                    .consumeP2SH = 1;
                            }
                        } else {
                            // When using the P2SH shortcut, all inputs must use
                            // P2SH
                            ////PRINTF("Disabling P2SH consumption\n");
                            btchip_context_D.transactionContext.consumeP2SH = 0;
                        }
                        transaction_offset_increase(1);
                        btchip_context_D.transactionContext.scriptRemaining--;
                    }

                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        if (parseMode == PARSE_MODE_SIGNATURE) {
                            if (!btchip_context_D.usingSegwit) {
                                // Restore dual hash for signature +
                                // authentication
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_BOTH;
                            } else {
                                if (btchip_context_D.segwitParsedOnce) {
                                    // Append the saved value
                                    ////PRINTF("SEGWIT Add value\n%.*H\n",8,btchip_context_D.inputValue);
                                    if (btchip_context_D.usingOverwinter) {
                                        cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.inputValue, 8, NULL, 0);
                                    }
                                    else {
                                        cx_hash(&btchip_context_D
                                                 .transactionHashFull.sha256.header,
                                            0, btchip_context_D.inputValue, 8,
                                            NULL, 0);
                                    }
                                }
                            }
                        }
                        // Sequence
                        check_transaction_available(4);
                        if (btchip_context_D.usingSegwit &&
                            !btchip_context_D.segwitParsedOnce) {
                            if (btchip_context_D.usingOverwinter) {
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.transactionBufferPointer, 4, NULL, 0);
                            }
                            else {
                                cx_hash(&btchip_context_D.transactionHashFull
                                         .sha256.header,
                                    0,
                                    btchip_context_D.transactionBufferPointer,
                                    4, NULL, 0);
                            }
                        }
                        transaction_offset_increase(4);

			//Additional "issuance" data to be read here if this is an DGLD
                        //issuance transaction - TODO 
			
                        // Move to next input
                        btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs--;
                        btchip_context_D.transactionContext
                            .transactionCurrentInputOutput++;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;
                        continue;
                    }
                    // Save the last script byte for the P2SH check
                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                         .scriptRemaining -
                                     1
                             ? btchip_context_D.transactionContext
                                       .scriptRemaining -
                                   1
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }

/*
    DGLD transaction sample - outputs

    02          # of vouts

    01  8f9390e4c7b981e355aed3c5690e17c2e13bb263246a55d8039813cac670c2f1    asset (confidential asset)
    01  000000000000de80    value (confidential value)
    00                      nonce (confidential nonce)
    01  51                  script

    01  8f9390e4c7b981e355aed3c5690e17c2e13bb263246a55d8039813cac670c2f1
    01  0000000000000000
    00
    26  6a24aa21a9ed2127440070600b5e8482e5df5815cc15b8262acf7533136c501f3cb4801faaf6

   */

		  
                case BTCHIP_TRANSACTION_INPUT_HASHING_DONE: {
                    ////PRINTF("Input hashing done\n");
                    if (parseMode == PARSE_MODE_SIGNATURE) {
                        // inputs have been prepared, stop the parsing here
                        if (btchip_context_D.usingSegwit &&
                            !btchip_context_D.segwitParsedOnce) {
                            unsigned char hashedPrevouts[32];
                            unsigned char hashedSequence[32];
                            // Flush the cache
                            if (btchip_context_D.usingOverwinter) {
                                cx_hash(&btchip_context_D.segwit.hash.hashPrevouts.blake2b.header, CX_LAST, hashedPrevouts, 0, hashedPrevouts, 32);
                                cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, CX_LAST, hashedSequence, 0, hashedSequence, 32);
                            }
                            else {
                                cx_hash(&btchip_context_D.segwit.hash.hashPrevouts
                                         .sha256.header,
                                    CX_LAST, hashedPrevouts, 0, hashedPrevouts, 32);
                                cx_sha256_init(
                                    &btchip_context_D.segwit.hash.hashPrevouts.sha256);
                                cx_hash(&btchip_context_D.segwit.hash.hashPrevouts
                                         .sha256.header,
                                    CX_LAST, hashedPrevouts,
                                    sizeof(hashedPrevouts), hashedPrevouts, 32);
                                cx_hash(&btchip_context_D.transactionHashFull
                                         .sha256.header,
                                    CX_LAST, hashedSequence, 0, hashedSequence, 32);
                                cx_sha256_init(
                                    &btchip_context_D.transactionHashFull.sha256);
                                cx_hash(&btchip_context_D.transactionHashFull
                                         .sha256.header,
                                    CX_LAST, hashedSequence,
                                    sizeof(hashedSequence), hashedSequence, 32);

                            }
                            os_memmove(
                                btchip_context_D.segwit.cache.hashedPrevouts,
                                hashedPrevouts, sizeof(hashedPrevouts));
                            os_memmove(
                                btchip_context_D.segwit.cache.hashedSequence,
                                hashedSequence, sizeof(hashedSequence));
                            ////PRINTF("hashPrevout\n%.*H\n",32,btchip_context_D.segwit.cache.hashedPrevouts);
                            ////PRINTF("hashSequence\n%.*H\n",32,btchip_context_D.segwit.cache.hashedSequence);
                        }
                        if (btchip_context_D.usingSegwit &&
                            btchip_context_D.segwitParsedOnce) {
                            if (!btchip_context_D.usingOverwinter) {
                                ////PRINTF("SEGWIT hashedOutputs\n%.*H\n",sizeof(btchip_context_D.segwit.cache.hashedOutputs),btchip_context_D.segwit.cache.hashedOutputs);
                                cx_hash(
                                    &btchip_context_D.transactionHashFull.sha256.header, 0,
                                    btchip_context_D.segwit.cache.hashedOutputs,
                                    sizeof(btchip_context_D.segwit.cache
                                           .hashedOutputs),
                                    NULL, 0);
                            }
                            btchip_context_D.transactionContext
                                .transactionState =
                                BTCHIP_TRANSACTION_SIGN_READY;
                        } else {
                            btchip_context_D.transactionContext
                                .transactionState =
                                BTCHIP_TRANSACTION_PRESIGN_READY;
                            if (btchip_context_D.usingOverwinter) {
                                cx_blake2b_init2(&btchip_context_D.transactionHashFull.blake2b, 256, NULL, 0, OVERWINTER_PARAM_OUTPUTS, 16);
                            }
                            else
                            if (btchip_context_D.usingSegwit) {
                                cx_sha256_init(&btchip_context_D.transactionHashFull.sha256);
                            }
                        }
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    } 
                    // Number of outputs
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;
                    ////PRINTF("Number of outputs : " DEBUG_LONG "\n", btchip_context_D.transactionContext                                     .transactionRemainingInputsOutputs);
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;

                    // no break is intentional
                }
                case BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT: {
                    if (btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more outputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }

		    if(!G_coin_config->kind == COIN_KIND_DGLD){
		      // Amount
		      check_transaction_available(8);
		      if ((parseMode == PARSE_MODE_TRUSTED_INPUT) &&
			  (btchip_context_D.transactionContext
			   .transactionCurrentInputOutput ==
			   btchip_context_D.transactionTargetInput)) {
                        // Save the amount
			os_memmove(btchip_context_D.transactionContext.transactionAmount,
                                   btchip_context_D.transactionBufferPointer,
                                   8);
                        btchip_context_D.trustedInputProcessed = 1;
			transaction_offset_increase(8);
		      }
		    } else {
		      //DGLD asset, value: for each of these fields,
                      //the first byte read determines the version number,
                      //which dictates the number of bytes to read.
                                      
                      //Temp variables
                      unsigned char version=0;
                      unsigned int varSizeBytes=1;
                      
                      //asset -- will be 1 + n bytes (version + data)
                      check_transaction_available(varSizeBytes);
		      version = *btchip_context_D.transactionBufferPointer;
		      if(version == 1 || version == 0xff || version==10 || version==11){
                        varSizeBytes+=32;
                        check_transaction_available(varSizeBytes);
                        if ((parseMode == PARSE_MODE_TRUSTED_INPUT) &&
                            (btchip_context_D.transactionContext
                             .transactionCurrentInputOutput ==
                             btchip_context_D.transactionTargetInput)) {
                          // Save the asset ID
                          os_memmove(btchip_context_D.transactionContext.transactionAsset,
                                     btchip_context_D.transactionBufferPointer,
                                     varSizeBytes);
                        }
		      } else {
			//PRINTF("Transaction output: unknown asset version");
			goto fail;
		      }
		      transaction_offset_increase(varSizeBytes);
					      
		      
		      //value
		      varSizeBytes=1;
		      version=0;
		      check_transaction_available(varSizeBytes);
		      version = *btchip_context_D.transactionBufferPointer;
		      
		      if(version == 1 || version == 0xff){
			varSizeBytes+=8;
		      } else if (version==8 || version==9){
			varSizeBytes+=32;
		      } else {
			//PRINTF("Transaction output: unknown value version");
			goto fail;
		      }
		      
		      check_transaction_available(varSizeBytes);
		      if ((parseMode == PARSE_MODE_TRUSTED_INPUT) &&
			  (btchip_context_D.transactionContext
			   .transactionCurrentInputOutput ==
			   btchip_context_D.transactionTargetInput)) {
			btchip_swap_bytes(btchip_context_D.transactionContext
				   .transactionAmount,
				   btchip_context_D.transactionBufferPointer,
				   varSizeBytes);
		      }
		      transaction_offset_increase(varSizeBytes);
		      
		      //nonce
		      check_transaction_available(1);
		      if ((parseMode == PARSE_MODE_TRUSTED_INPUT) &&
			  (btchip_context_D.transactionContext
			   .transactionCurrentInputOutput ==
			   btchip_context_D.transactionTargetInput)) {
			// Save the output nonce
			btchip_context_D.transactionContext.transactionOutputNonce =
			  *btchip_context_D.transactionBufferPointer;
			btchip_context_D.trustedInputProcessed = 1;
		      }
		      transaction_offset_increase(1);
		    }

		    // Read the script length
		    btchip_context_D.transactionContext.scriptRemaining =
		      transaction_get_varint();
		    
		    ////PRINTF("Script to read " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
		    // Move on
		    btchip_context_D.transactionContext.transactionState =
		      BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;
		    
		  // no break is intentional
                }
	    case BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT: {
	      unsigned char dataAvailable;
	      ////PRINTF("Process output script, remaining " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
	      /*
	      // Special check if consuming a P2SH script
	      if (parseMode == PARSE_MODE_TRUSTED_INPUT) {
	      // Assume the full input script is sent in a single APDU,
	      then do the ghetto validation
	      if ((btchip_context_D.transactionBufferPointer[0] ==
	      OP_HASH160) &&
	      (btchip_context_D.transactionBufferPointer[btchip_context_D.transactionDataRemaining
	      - 1] == OP_EQUAL)) {
	      ////PRINTF("Marking P2SH output\n");
	      btchip_context_D.transactionContext.consumeP2SH = 1;
	      }
	      }
	      */
	      if (btchip_context_D.transactionDataRemaining < 1) {
		// No more data to read, ok
		goto ok;
	      }
	      if (btchip_context_D.transactionContext.scriptRemaining ==
		  0) {
		// Move to next output
		btchip_context_D.transactionContext
		  .transactionRemainingInputsOutputs--;
		btchip_context_D.transactionContext
		  .transactionCurrentInputOutput++;
		btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;
                        continue;
	      }
	      dataAvailable =
		(btchip_context_D.transactionDataRemaining >
		 btchip_context_D.transactionContext
		 .scriptRemaining
		 ? btchip_context_D.transactionContext
		 .scriptRemaining
		 : btchip_context_D.transactionDataRemaining);
	      if (dataAvailable == 0) {
		goto ok;
	      }
	      transaction_offset_increase(dataAvailable);
	      btchip_context_D.transactionContext.scriptRemaining -=
		dataAvailable;
	      break;
	    }

		case BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE: {
		  ////PRINTF("Output hashing done\n");
 		  if (btchip_context_D.transactionDataRemaining < 1) {
		    // No more data to read, ok
		    goto ok;
		  }
		  // Locktime
		  check_transaction_available(4);
		  transaction_offset_increase(4);
 
		  if (btchip_context_D.transactionDataRemaining == 0) {
		    btchip_context_D.transactionContext.transactionState =
		      BTCHIP_TRANSACTION_PARSED;
		    ////PRINTF("Transaction parsed\n");		  
		    continue;
		  } else {
		    btchip_context_D.transactionHashOption = 0;
		    btchip_context_D.transactionContext.scriptRemaining =
		      transaction_get_varint();
		    btchip_context_D.transactionHashOption =
		      TRANSACTION_HASH_FULL;
		    btchip_context_D.transactionContext.transactionState =
		      BTCHIP_TRANSACTION_PROCESS_EXTRA;
		    ////PRINTF("Transaction process extra\n");		  
		    continue;
		  }
                }

/*
    DGLD transaction sample = extra data

    00000000 locktime

    # for each vin - CTxInWitness
    00  issuance amount range proof
    00  inflation range proof
    01  num of script witnesses
    20 0000000000000000000000000000000000000000000000000000000000000000 script witness
    00  num of pegin witnesses

    # for each vout - CTxOutWitness
    00  surjection proof
    00  range proof
    00  surjection proof
    00  range proof
    */
		  
                case BTCHIP_TRANSACTION_PROCESS_EXTRA: {
		  ////PRINTF("Process extra\n");
                    unsigned char dataAvailable;

                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PARSED;
                        continue;
                    }

                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }

                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                     .scriptRemaining
                             ? btchip_context_D.transactionContext
                                   .scriptRemaining
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }

                case BTCHIP_TRANSACTION_PARSED: {
		  ////PRINTF("Transaction parsed\n");
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PRESIGN_READY: {
                    ////PRINTF("Presign ready\n");
                    goto ok;
                }

                case BTCHIP_TRANSACTION_SIGN_READY: {
                    ////PRINTF("Sign ready\n");
                    goto ok;
                }
                
		}

	    }

        fail:
            //PRINTF("Transaction parse - fail\n");
            THROW(EXCEPTION);
        ok : {}
        }
        CATCH_OTHER(e) {
            //PRINTF("Transaction parse - surprise fail\n");
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
            btchip_set_check_internal_structure_integrity(1);
            THROW(e);
        }
        // before the finally to restore the surrounding context if an exception
        // is raised during finally
        FINALLY {
            btchip_set_check_internal_structure_integrity(1);
        }
    }
    END_TRY;
}
