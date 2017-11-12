#include "unihivelib.h"

bool Initialize(ErrorCallback onError, HashFoundCallback onHashFound,VerifiedCallback onVerifiedCallback, int threads)
{
    if (!minethd::self_test())
    {
        return false;
    }
    
    executor::inst()->errorCallback = onError;
    executor::inst()->hashFoundCallback = onHashFound;
    executor::inst()->verifiedCallback = onVerifiedCallback;
    executor::inst()->threadsCount = threads;
    
    return true;
}

void StartMiner()
{
    executor::inst()->start();
}

void ReceiveJob(char*blob,char*target)
{
    executor::inst()->process_pool_job(blob, target);
}

void Verify(char*blob)
{
    executor::inst()->process_verify_job(blob);
}

void StopMiner()
{
    executor::inst()->stop();
}

double GetHashesPerSecond()
{
    return executor::inst()->calcHPS();
}

int GetNumThreads()
{
    return executor::threadsCount;
}

float GetThrottle()
{
    return 1.5F;
}
