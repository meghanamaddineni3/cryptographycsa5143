#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Constants for SHA-3
#define STATE_SIZE 1600 // Total state size in bits (5x5x64 bits)
#define LANE_SIZE 64    // Lane size in bits
#define NUM_LANES (STATE_SIZE / LANE_SIZE) // Number of lanes

// Function to initialize the state with given capacity and message block
void initializeState(uint64_t state[NUM_LANES], uint64_t messageBlock[NUM_LANES]);

// Function to check if all lanes have at least one nonzero bit
bool allLanesNonzero(uint64_t state[NUM_LANES]);

int main() {
    // Initialize the state matrix and message block
    uint64_t state[NUM_LANES] = {0};
    uint64_t messageBlock[NUM_LANES];

    // Assume that each lane in the first message block has at least one nonzero bit
    for (int i = 0; i < NUM_LANES; ++i) {
        messageBlock[i] = (uint64_t)rand() << 32 | rand(); // Random nonzero value
    }

    // Initialize the state with the message block
    initializeState(state, messageBlock);

    // Count the iterations until all lanes have at least one nonzero bit
    int iterations = 0;
    while (!allLanesNonzero(state)) {
        // Update the state with new message blocks (simulation)
        for (int i = 0; i < NUM_LANES; ++i) {
            messageBlock[i] = (uint64_t)rand() << 32 | rand(); // Random nonzero value
        }
        initializeState(state, messageBlock);
        ++iterations;
    }

    printf("Iterations until all lanes have at least one nonzero bit: %d\n", iterations);

    return 0;
}

// Function to initialize the state with given capacity and message block
void initializeState(uint64_t state[NUM_LANES], uint64_t messageBlock[NUM_LANES]) {
    for (int i = 0; i < NUM_LANES; ++i) {
        state[i] ^= messageBlock[i];
    }
}

// Function to check if all lanes have at least one nonzero bit
bool allLanesNonzero(uint64_t state[NUM_LANES]) {
    for (int i = 0; i < NUM_LANES; ++i) {
        if (state[i] == 0) {
            return false;
        }
    }
    return true;
}

