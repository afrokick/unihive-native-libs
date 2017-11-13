#pragma once

#include "executor.h"
#include "minethd.h"

extern "C"{
    bool Initialize(ErrorCallback onError,
                    HashFoundCallback onHashFound,
                    VerifiedCallback onVerifiedCallback,
                    int threads);
    void StartMiner();
    void ReceiveJob(char*blob, char*target);
    void Verify(char*blob);
    void StopMiner();
    double GetHashesPerSecond();
    int GetNumThreads();
    float GetThrottle();
}
