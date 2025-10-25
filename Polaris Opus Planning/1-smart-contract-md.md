# Smart Contract - Polaris Music Registry

## Overview
This smart contract handles on-chain anchoring of music data events, voting with Fractally Respect weights, and stake management. Groups are first-class entities representing bands and ensembles.

## Contract Implementation

```cpp
// File: contracts/polaris.music/polaris.music.cpp
// Antelope smart contract for the Polaris music registry
// Integrates with Fractally for Respect-based voting weights

#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/singleton.hpp>

using namespace eosio;

CONTRACT polaris : public contract {
public:
    using contract::contract;
    
    // ============ CORE ANCHORING ACTIONS ============
    
    /**
     * Anchor an off-chain event on-chain
     * This is the main entry point for all data submissions
     * 
     * @param author - The blockchain account submitting the event
     * @param type - Event type enum:
     *   21 = CREATE_RELEASE_BUNDLE (full release with groups, tracks, etc.)
     *   22 = CREATE_GROUP (standalone group/band creation)
     *   23 = ADD_MEMBER (add person to existing group)
     *   24 = REMOVE_MEMBER (mark member as departed from group)
     *   30 = ADD_CLAIM (add data to existing entity)
     *   31 = EDIT_CLAIM (modify existing data)
     *   40 = VOTE (vote on a submission)
     *   41 = LIKE (like a node in the graph)
     *   42 = DISCUSS (comment on an entity)
     *   50 = FINALIZE (finalize voting and distribute rewards)
     *   60 = MERGE_NODE (deduplicate entities)
     * @param hash - SHA256 hash of the canonical off-chain event body
     * @param parent - Optional parent event hash for threading discussions
     * @param ts - Unix timestamp when event was created
     * @param tags - Searchable tags like ["group", "rock", "1970s"]
     */
    ACTION put(name author, uint8_t type, checksum256 hash,
               std::optional<checksum256> parent, uint32_t ts,
               std::vector<name> tags) {
        require_auth(author);
        
        // Validate inputs
        check(type > 0 && type < 100, "Invalid event type");
        check(ts > 0, "Invalid timestamp");
        check(tags.size() <= 10, "Too many tags (max 10)");
        
        // Get current blockchain time for expiry calculation
        uint32_t current_time = current_time_point().sec_since_epoch();
        check(ts <= current_time + 300, "Timestamp too far in future"); // Max 5 min future
        
        // Calculate voting window based on event type
        uint32_t vote_window = get_vote_window(type);
        uint32_t expires_at = current_time + vote_window;
        
        // Store the anchor on-chain
        anchors_table anchors(get_self(), get_self().value);
        uint64_t anchor_id = anchors.available_primary_key();
        
        anchors.emplace(author, [&](auto& a) {
            a.id = anchor_id;
            a.author = author;
            a.type = type;
            a.hash = hash;
            a.parent = parent;
            a.ts = ts;
            a.tags = tags;
            a.expires_at = expires_at;
            a.finalized = false;
        });
        
        // Increment global submission counter for emission calculations
        globals_singleton globals(get_self(), get_self().value);
        auto g = globals.get_or_default();
        
        // Only increment for content submissions, not votes or likes
        if (type >= 20 && type < 40) {
            g.x += 1; // Global submission number
        }
        
        globals.set(g, get_self());
        
        // Log event for off-chain indexers
        emit_anchor_event(author, type, hash, anchor_id, g.x);
    }
    
    /**
     * Attest to the validity of an anchored event
     * Used by trusted attestors to verify high-value submissions
     * 
     * @param attestor - Account doing the attestation (must be authorized)
     * @param tx_hash - Hash of the event being attested
     * @param type - The event type being attested (must match anchor)
     */
    ACTION attest(name attestor, checksum256 tx_hash, uint8_t type) {
        require_auth(attestor);
        
        // Verify attestor is authorized
        check(is_authorized_attestor(attestor), "Not an authorized attestor");
        
        // Verify the anchor exists and matches type
        anchors_table anchors(get_self(), get_self().value);
        auto idx = anchors.get_index<"byhash"_n>();
        auto itr = idx.find(tx_hash);
        check(itr != idx.end(), "Anchor not found");
        check(itr->type == type, "Type mismatch");
        
        // Store attestation
        attestations_table attestations(get_self(), get_self().value);
        attestations.emplace(attestor, [&](auto& a) {
            a.id = attestations.available_primary_key();
            a.tx_hash = tx_hash;
            a.attestor = attestor;
            a.type = type;
            a.ts = current_time_point();
        });
    }
    
    // ============ FRACTALLY INTEGRATION ============
    
    /**
     * Update Respect values from Fractally elections
     * Called weekly by Fractally oracle or designated multisig
     * Respect values determine voting weight in the system
     * 
     * @param respect_data - Array of account:respect pairs from latest election
     * @param election_round - Fractally round number for verification
     */
    ACTION updaterespect(std::vector<std::pair<name, uint32_t>> respect_data,
                         uint64_t election_round) {
        // Only Fractally contract or designated oracle can update
        require_auth(get_fractally_oracle());
        
        respect_table respect(get_self(), get_self().value);
        
        for(const auto& [account, respect_value] : respect_data) {
            auto itr = respect.find(account.value);
            
            if(itr == respect.end()) {
                // New member getting Respect
                respect.emplace(get_self(), [&](auto& r) {
                    r.account = account;
                    r.respect = respect_value;
                    r.round = election_round;
                    r.updated_at = current_time_point();
                });
            } else {
                // Update existing Respect
                respect.modify(itr, get_self(), [&](auto& r) {
                    r.respect = respect_value;
                    r.round = election_round;
                    r.updated_at = current_time_point();
                });
            }
        }
        
        // Log the update for transparency
        print("Updated Respect for ", respect_data.size(), " accounts in round ", election_round);
    }
    
    // ============ VOTING WITH RESPECT WEIGHTS ============
    
    /**
     * Vote on an anchored event with Respect-weighted influence
     * Votes determine if submissions are accepted and receive rewards
     * 
     * @param voter - Account casting the vote
     * @param tx_hash - Hash of the event being voted on
     * @param val - Vote value: +1 (approve), -1 (reject), 0 (unvote/neutral)
     */
    ACTION vote(name voter, checksum256 tx_hash, int8_t val) {
        require_auth(voter);
        check(val >= -1 && val <= 1, "Invalid vote value");
        
        // Verify the anchor exists and voting window is still open
        anchors_table anchors(get_self(), get_self().value);
        auto idx = anchors.get_index<"byhash"_n>();
        auto itr = idx.find(tx_hash);
        check(itr != idx.end(), "Anchor not found");
        check(!itr->finalized, "Already finalized");
        check(current_time_point().sec_since_epoch() < itr->expires_at, 
              "Voting window has closed");
        
        // Get voter's Respect for weight calculation
        respect_table respect(get_self(), get_self().value);
        auto respect_itr = respect.find(voter.value);
        uint32_t voter_respect = 1; // Default weight if no Respect
        
        if(respect_itr != respect.end()) {
            voter_respect = respect_itr->respect;
            // Cap maximum individual influence
            if(voter_respect > 100) voter_respect = 100;
        }
        
        // Store or update vote
        votes_table votes(get_self(), get_self().value);
        auto vote_idx = votes.get_index<"byvoterhash"_n>();
        uint128_t composite_key = combine_keys(voter.value, tx_hash);
        auto vote_itr = vote_idx.find(composite_key);
        
        if(vote_itr == vote_idx.end()) {
            // New vote
            votes.emplace(voter, [&](auto& v) {
                v.id = votes.available_primary_key();
                v.tx_hash = tx_hash;
                v.voter = voter;
                v.val = val;
                v.weight = voter_respect;
                v.ts = current_time_point();
            });
        } else {
            // Update existing vote
            vote_idx.modify(vote_itr, voter, [&](auto& v) {
                v.val = val;
                v.weight = voter_respect;
                v.ts = current_time_point();
            });
        }
    }
    
    /**
     * Finalize voting and distribute rewards after window closes
     * Uses logarithmic emission curve: g(x) = m * ln(x) / x
     * 
     * @param tx_hash - Hash of the event to finalize
     */
    ACTION finalize(checksum256 tx_hash) {
        // Anyone can call finalize after voting window
        
        anchors_table anchors(get_self(), get_self().value);
        auto idx = anchors.get_index<"byhash"_n>();
        auto itr = idx.find(tx_hash);
        check(itr != idx.end(), "Anchor not found");
        check(!itr->finalized, "Already finalized");
        check(current_time_point().sec_since_epoch() >= itr->expires_at,
              "Voting window still open");
        
        // Check attestation requirement for high-value submissions
        if(requires_attestation(itr->type)) {
            attestations_table attestations(get_self(), get_self().value);
            auto att_idx = attestations.get_index<"byhash"_n>();
            auto att_itr = att_idx.find(tx_hash);
            check(att_itr != att_idx.end(), "Attestation required but not found");
        }
        
        // Calculate weighted vote totals
        auto [up_votes, down_votes] = calculate_weighted_votes(tx_hash);
        uint64_t total_votes = up_votes + down_votes;
        double approval = total_votes > 0 ? 
                         static_cast<double>(up_votes) / total_votes : 0.0;
        
        // Get emission parameters
        globals_singleton globals(get_self(), get_self().value);
        auto g = globals.get_or_default();
        
        uint64_t multiplier = get_multiplier(itr->type);
        double x = static_cast<double>(g.x);
        
        // Calculate emission using logarithmic curve
        // g(x) = m * ln(x) / x
        double g_raw = multiplier * std::log(x) / x;
        uint64_t mint = static_cast<uint64_t>(g_raw + g.carry);
        g.carry = (g_raw + g.carry) - mint;
        
        // Determine payout distribution based on approval
        if(approval >= 0.90) {
            // Accepted: 50% to submitter, 50% to voters
            distribute_rewards(itr->author, tx_hash, mint, true);
        } else {
            // Rejected: 50% to voters, 50% to stakers
            distribute_rewards(itr->author, tx_hash, mint, false);
        }
        
        // Mark as finalized
        idx.modify(itr, same_payer, [&](auto& a) {
            a.finalized = true;
        });
        
        // Update global state
        globals.set(g, get_self());
        
        // Log finalization
        print("Finalized ", to_hex(tx_hash), " with ", approval * 100, "% approval");
    }
    
    // ============ STAKING ON GROUPS/PERSONS/NODES ============
    
    /**
     * Stake tokens on a Group, Person, or other node to show support
     * Affects home node selection and reward distribution for rejected submissions
     * 
     * @param account - Account doing the staking
     * @param node_id - SHA256 identifier of entity being staked on
     * @param quantity - Amount of tokens to stake
     */
    ACTION stake(name account, checksum256 node_id, asset quantity) {
        require_auth(account);
        check(quantity.symbol == symbol("MUS", 4), "Invalid token symbol");
        check(quantity.amount > 0, "Must stake positive amount");
        
        // Update individual stake record (for user's portfolio view)
        stakes_table stakes(get_self(), account.value);
        auto itr = stakes.find(node_id);
        
        if(itr == stakes.end()) {
            stakes.emplace(account, [&](auto& s) {
                s.node_id = node_id;
                s.amount = quantity;
                s.staked_at = current_time_point();
            });
        } else {
            stakes.modify(itr, account, [&](auto& s) {
                s.amount += quantity;
                s.last_updated = current_time_point();
            });
        }
        
        // Update aggregate for the node (used for voting power and rewards)
        nodeagg_table aggregates(get_self(), get_self().value);
        auto agg_itr = aggregates.find(node_id);
        
        if(agg_itr == aggregates.end()) {
            aggregates.emplace(account, [&](auto& a) {
                a.node_id = node_id;
                a.total = quantity;
                a.staker_count = 1;
            });
        } else {
            aggregates.modify(agg_itr, account, [&](auto& a) {
                a.total += quantity;
                if(itr == stakes.end()) {
                    a.staker_count += 1;
                }
            });
        }
        
        // Transfer tokens to contract
        transfer_tokens(account, get_self(), quantity, 
                       "Stake on node " + to_hex(node_id));
    }
    
    /**
     * Remove stake from a node
     * 
     * @param account - Account removing stake
     * @param node_id - Node to unstake from
     * @param quantity - Amount to unstake
     */
    ACTION unstake(name account, checksum256 node_id, asset quantity) {
        require_auth(account);
        check(quantity.amount > 0, "Must unstake positive amount");
        
        // Update individual stake
        stakes_table stakes(get_self(), account.value);
        auto itr = stakes.require_find(node_id, "No stake found");
        check(itr->amount >= quantity, "Insufficient stake");
        
        if(itr->amount == quantity) {
            stakes.erase(itr);
        } else {
            stakes.modify(itr, account, [&](auto& s) {
                s.amount -= quantity;
                s.last_updated = current_time_point();
            });
        }
        
        // Update aggregate
        nodeagg_table aggregates(get_self(), get_self().value);
        auto agg_itr = aggregates.require_find(node_id, "Aggregate not found");
        
        aggregates.modify(agg_itr, account, [&](auto& a) {
            a.total -= quantity;
            if(itr->amount == quantity) {
                a.staker_count -= 1;
            }
        });
        
        // Transfer tokens back to account
        transfer_tokens(get_self(), account, quantity, "Unstake from node");
    }

private:
    // ============ DATA STRUCTURES ============
    
    // Anchored events table
    TABLE anchor {
        uint64_t    id;              // Auto-incrementing primary key
        name        author;          // Account that submitted
        uint8_t     type;           // Event type code
        checksum256 hash;           // SHA256 of canonical event
        std::optional<checksum256> parent; // Parent for threading
        uint32_t    ts;             // Original timestamp
        std::vector<name> tags;     // Searchable tags
        uint32_t    expires_at;     // When voting closes
        bool        finalized;      // Rewards distributed?
        
        uint64_t primary_key() const { return id; }
        checksum256 by_hash() const { return hash; }
        uint64_t by_author() const { return author.value; }
        
        EOSLIB_SERIALIZE(anchor, (id)(author)(type)(hash)(parent)
                                 (ts)(tags)(expires_at)(finalized))
    };
    
    // Vote records with Respect weights
    TABLE vote_record {
        uint64_t    id;             // Primary key
        checksum256 tx_hash;        // Event being voted on
        name        voter;          // Who voted
        int8_t      val;           // Vote: +1, 0, -1
        uint32_t    weight;        // Respect weight at vote time
        time_point  ts;            // When voted
        
        uint64_t primary_key() const { return id; }
        uint128_t by_voter_hash() const { 
            return combine_keys(voter.value, tx_hash);
        }
        checksum256 by_hash() const { return tx_hash; }
        
        EOSLIB_SERIALIZE(vote_record, (id)(tx_hash)(voter)(val)(weight)(ts))
    };
    
    // Fractally Respect values
    TABLE respect_record {
        name        account;        // Account with Respect
        uint32_t    respect;       // Current Respect value
        uint64_t    round;         // Election round number
        time_point  updated_at;    // Last update time
        
        uint64_t primary_key() const { return account.value; }
        
        EOSLIB_SERIALIZE(respect_record, (account)(respect)(round)(updated_at))
    };
    
    // Individual stake records
    TABLE stake_record {
        checksum256 node_id;        // What's being staked on
        asset       amount;         // Amount staked
        time_point  staked_at;      // When first staked
        time_point  last_updated;   // Last change
        
        checksum256 primary_key() const { return node_id; }
        
        EOSLIB_SERIALIZE(stake_record, (node_id)(amount)(staked_at)(last_updated))
    };
    
    // Aggregated stakes by node
    TABLE node_aggregate {
        checksum256 node_id;        // Node identifier
        asset       total;          // Total staked
        uint32_t    staker_count;   // Number of stakers
        
        checksum256 primary_key() const { return node_id; }
        
        EOSLIB_SERIALIZE(node_aggregate, (node_id)(total)(staker_count))
    };
    
    // Attestation records
    TABLE attestation {
        uint64_t    id;
        checksum256 tx_hash;        // Event attested
        name        attestor;       // Who attested
        uint8_t     type;          // Event type confirmed
        time_point  ts;            // When attested
        
        uint64_t primary_key() const { return id; }
        checksum256 by_hash() const { return tx_hash; }
        
        EOSLIB_SERIALIZE(attestation, (id)(tx_hash)(attestor)(type)(ts))
    };
    
    // Global state
    TABLE global_state {
        uint64_t    x;              // Global submission counter
        double      carry;          // Fractional emission accumulator
        uint64_t    round;          // Current round
        name        fractally_oracle; // Who can update Respect
        
        EOSLIB_SERIALIZE(global_state, (x)(carry)(round)(fractally_oracle))
    };
    
    // Table type definitions
    typedef eosio::multi_index<"anchors"_n, anchor,
        indexed_by<"byhash"_n, const_mem_fun<anchor, checksum256, &anchor::by_hash>>,
        indexed_by<"byauthor"_n, const_mem_fun<anchor, uint64_t, &anchor::by_author>>
    > anchors_table;
    
    typedef eosio::multi_index<"votes"_n, vote_record,
        indexed_by<"byvoterhash"_n, const_mem_fun<vote_record, uint128_t, &vote_record::by_voter_hash>>,
        indexed_by<"byhash"_n, const_mem_fun<vote_record, checksum256, &vote_record::by_hash>>
    > votes_table;
    
    typedef eosio::multi_index<"respect"_n, respect_record> respect_table;
    typedef eosio::multi_index<"stakes"_n, stake_record> stakes_table;
    typedef eosio::multi_index<"nodeagg"_n, node_aggregate> nodeagg_table;
    typedef eosio::multi_index<"attestations"_n, attestation,
        indexed_by<"byhash"_n, const_mem_fun<attestation, checksum256, &attestation::by_hash>>
    > attestations_table;
    typedef eosio::singleton<"globals"_n, global_state> globals_singleton;
    
    // ============ HELPER FUNCTIONS ============
    
    /**
     * Get voting window duration based on event type
     */
    uint32_t get_vote_window(uint8_t type) {
        if(type == 21 || type == 22) return 7 * 24 * 60 * 60; // 7 days for releases/groups
        if(type == 30 || type == 31) return 3 * 24 * 60 * 60; // 3 days for claims
        return 24 * 60 * 60; // 1 day default
    }
    
    /**
     * Get emission multiplier for event type
     */
    uint64_t get_multiplier(uint8_t type) {
        switch(type) {
            case 21: return 1000000;  // CREATE_RELEASE_BUNDLE
            case 22: return 500000;   // CREATE_GROUP
            case 23: return 100000;   // ADD_MEMBER
            case 30: return 50000;    // ADD_CLAIM
            case 31: return 1000;     // EDIT_CLAIM
            default: return 0;        // No emission
        }
    }
    
    /**
     * Check if event type requires attestation
     */
    bool requires_attestation(uint8_t type) {
        return type == 21 || type == 22; // Releases and groups
    }
    
    /**
     * Create composite key for indexes
     */
    static uint128_t combine_keys(uint64_t a, const checksum256& b) {
        return (uint128_t(a) << 64) | uint128_t(*reinterpret_cast<const uint64_t*>(&b));
    }
    
    /**
     * Get authorized Fractally oracle account
     */
    name get_fractally_oracle() {
        globals_singleton globals(get_self(), get_self().value);
        auto g = globals.get_or_default();
        return g.fractally_oracle;
    }
    
    /**
     * Check if account is authorized attestor
     */
    bool is_authorized_attestor(name account) {
        // In production, check against a table or multisig
        return account == name("council.pol") || account == get_fractally_oracle();
    }
    
    /**
     * Calculate weighted vote totals
     */
    std::pair<uint64_t, uint64_t> calculate_weighted_votes(const checksum256& tx_hash) {
        votes_table votes(get_self(), get_self().value);
        auto idx = votes.get_index<"byhash"_n>();
        
        uint64_t up_votes = 0;
        uint64_t down_votes = 0;
        
        auto itr = idx.lower_bound(tx_hash);
        while(itr != idx.end() && itr->tx_hash == tx_hash) {
            if(itr->val == 1) {
                up_votes += itr->weight;
            } else if(itr->val == -1) {
                down_votes += itr->weight;
            }
            ++itr;
        }
        
        return {up_votes, down_votes};
    }
    
    /**
     * Distribute rewards based on voting outcome
     */
    void distribute_rewards(name submitter, const checksum256& tx_hash, 
                           uint64_t total_amount, bool accepted) {
        if(accepted) {
            // 50% to submitter
            uint64_t submitter_share = total_amount / 2;
            // TODO: Issue tokens to submitter
            
            // 50% to voters (weighted by Respect)
            uint64_t voter_share = total_amount - submitter_share;
            distribute_to_voters(tx_hash, voter_share);
        } else {
            // 50% to voters
            uint64_t voter_share = total_amount / 2;
            distribute_to_voters(tx_hash, voter_share);
            
            // 50% to stakers
            uint64_t staker_share = total_amount - voter_share;
            distribute_to_stakers(staker_share);
        }
    }
    
    void distribute_to_voters(const checksum256& tx_hash, uint64_t amount) {
        // Implementation would distribute proportionally to vote weights
    }
    
    void distribute_to_stakers(uint64_t amount) {
        // Implementation would distribute proportionally to stake amounts
    }
    
    void transfer_tokens(name from, name to, asset quantity, const std::string& memo) {
        // Implementation would call token contract
    }
    
    void emit_anchor_event(name author, uint8_t type, const checksum256& hash, 
                          uint64_t id, uint64_t x) {
        // Emit event for indexers
    }
    
    std::string to_hex(const checksum256& hash) {
        // Convert hash to hex string for display
        return ""; // Implementation omitted
    }
};
```

## Testing
1. Deploy to testnet first
2. Test all event types with sample data
3. Verify Respect weight calculations
4. Test stake aggregation
5. Verify emission calculations
6. Test finalization and reward distribution