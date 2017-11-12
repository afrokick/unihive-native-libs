#include <thread>
#include <string>
#include <cmath>
#include <algorithm>
#include <assert.h>
#include <time.h>
#include "executor.h"
#include "minethd.h"
#include "jconf.h"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif // _WIN32

inline static uint64_t t32_to_t64(uint32_t t) { return 0xFFFFFFFFFFFFFFFFULL / (0xFFFFFFFFULL / ((uint64_t)t)); }

inline unsigned char hf_hex2bin(char c, bool &err)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 0xA;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 0xA;
    
    err = true;
    return 0;
}

bool hex2bin(const char* in, unsigned int len, unsigned char* out)
{
    bool error = false;
    for (unsigned int i = 0; i < len; i += 2)
    {
        out[i / 2] = (hf_hex2bin(in[i], error) << 4) | hf_hex2bin(in[i + 1], error);
        if (error) return false;
    }
    return true;
}

inline char hf_bin2hex(unsigned char c)
{
    if (c <= 0x9)
        return '0' + c;
    else
        return 'a' - 0xA + c;
}

void bin2hex(const unsigned char* in, unsigned int len, char* out)
{
    for (unsigned int i = 0; i < len; i++)
    {
        out[i * 2] = hf_bin2hex((in[i] & 0xF0) >> 4);
        out[i * 2 + 1] = hf_bin2hex(in[i] & 0x0F);
    }
}

void executor::cmd_submit(const char* sJobId, uint32_t iNonce, const uint8_t* bResult)
{
    char sNonce[9];
    char sResult[65];
    
    bin2hex((unsigned char*)&iNonce, 4, sNonce);
    sNonce[8] = '\0';
    
    bin2hex(bResult, 32, sResult);
    sResult[64] = '\0';
    
    executor::hashFoundCallback(sResult,sNonce);
}

executor* executor::oInst = NULL;
ErrorCallback executor::errorCallback;
HashFoundCallback executor::hashFoundCallback;
VerifiedCallback executor::verifiedCallback;
int executor::threadsCount = 1;

executor::executor()
{
}

void executor::start()
{
    threadsShouldClose.store(false);
    
    std::thread(&executor::ex_main, this).detach();
    
    minethd::miner_work oWork = minethd::miner_work();
    pvThreads = minethd::thread_starter(oWork, executor::threadsCount);
    telem = new telemetry(pvThreads->size());
}

void executor::stop()
{
    threadsShouldClose.store(true);
    
    push_event(ex_event());
    
    pvThreads = NULL;
}

bool executor::process_pool_job(const char*blob, const char*target)
{
    uint32_t iWorkLn = strlen(blob) / 2;
    
    pool_job oPoolJob;
    if (!hex2bin(blob, iWorkLn * 2, oPoolJob.bWorkBlob))
        return false;

    oPoolJob.iWorkLen = iWorkLn;
    memset(oPoolJob.sJobID, 0, sizeof(pool_job::sJobID));
    
    size_t target_slen = strlen(target);
    
    if(target_slen <= 8)
    {
        uint32_t iTempInt = 0;
        char sTempStr[] = "00000000"; // Little-endian CPU FTW
        memcpy(sTempStr, target, target_slen);
        if(!hex2bin(sTempStr, 8, (unsigned char*)&iTempInt) || iTempInt == 0)
            return false;

        oPoolJob.iTarget = t32_to_t64(iTempInt);
    }
    else if(target_slen <= 16)
    {
        oPoolJob.iTarget = 0;
        char sTempStr[] = "0000000000000000";
        memcpy(sTempStr, target, target_slen);
        if(!hex2bin(sTempStr, 16, (unsigned char*)&oPoolJob.iTarget) || oPoolJob.iTarget == 0)
            return false;
    }

    push_event(ex_event(oPoolJob));
    
    return true;
}

bool executor::process_verify_job(const char*blob)
{
    uint32_t iWorkLn = strlen(blob) / 2;
    
    pool_job oPoolJob;
    if (!hex2bin(blob, iWorkLn * 2, oPoolJob.bWorkBlob))
        return false;
    
    oPoolJob.iWorkLen = iWorkLn;
    
    minethd::verify(oPoolJob);
    
    return true;
}

void executor::on_pool_have_job(pool_job& oPoolJob)
{
    if(pvThreads == NULL || threadsShouldClose.load())
        return;
    
	minethd::miner_work oWork(oPoolJob.sJobID, oPoolJob.bWorkBlob,
		oPoolJob.iWorkLen, oPoolJob.iResumeCnt, oPoolJob.iTarget, false);

	minethd::switch_work(oWork);
}

void executor::on_miner_result(job_result& oResult)
{
	cmd_submit(oResult.sJobID, oResult.iNonce, oResult.bResult);
}

void executor::on_verify_result(verify_result& oResult)
{
    char sResult[65];
    
    bin2hex(oResult.bResult, 32, sResult);
    sResult[64] = '\0';
    
    executor::verifiedCallback(sResult);
}

void executor::ex_main()
{
	ex_event ev;
    
    while (!threadsShouldClose.load())
	{
		ev = oEventQ.pop();
        
        if(threadsShouldClose.load())
            return;
        
		switch (ev.iName)
		{
            case EV_POOL_HAVE_JOB:
                on_pool_have_job(ev.oPoolJob);
                break;
            case EV_MINER_HAVE_RESULT:
                on_miner_result(ev.oJobResult);
                break;
            case EV_VERIFY_RESULT:
                on_verify_result(ev.oVerifyResult);
                break;
            case EV_HPS:
                for (int i = 0; i < executor::threadsCount; i++)
                    telem->push_perf_value(i, pvThreads->at(i)->iHashCount.load(std::memory_order_relaxed),
                                           pvThreads->at(i)->iTimestamp.load(std::memory_order_relaxed));
                break;
            default:
                return;
		}
	}
}

double executor::calcHPS()
{
    double fHps = 0.0;
    double fTelem;
    bool normal = true;
    
    for (int i = 0; i < executor::threadsCount; i++)
    {
        fTelem = telem->calc_telemetry_data(10000,i);
        if(std::isnormal(fTelem))
        {
            fHps += fTelem;
        }
        else
        {
            normal = false;
            break;
        }
    }
    
    if(!normal)
        return 0.0;
    
    return fHps;
}
