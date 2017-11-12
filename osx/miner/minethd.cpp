#include <assert.h>
#include <cmath>
#include <chrono>
#include <cstring>
#include <thread>
#include <bitset>

#ifdef _WIN32
#include <windows.h>

void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
	SetThreadAffinityMask(h, 1ULL << cpu_id);
}
#else
#include <pthread.h>

#if defined(__APPLE__)
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#endif


void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
#if defined(__APPLE__)
	thread_port_t mach_thread;
	thread_affinity_policy_data_t policy = { static_cast<integer_t>(cpu_id) };
	mach_thread = pthread_mach_thread_np(h);
	thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1);
#elif defined(__FreeBSD__)
	cpuset_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	pthread_setaffinity_np(h, sizeof(cpuset_t), &mn);
#else
	cpu_set_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	pthread_setaffinity_np(h, sizeof(cpu_set_t), &mn);
#endif
}
#endif // _WIN32

#include "executor.h"
#include "minethd.h"
#include "jconf.h"
#include "crypto/cryptonight_aesni.h"

telemetry::telemetry(size_t iThd)
{
    ppHashCounts = new uint64_t*[iThd];
    ppTimestamps = new uint64_t*[iThd];
    iBucketTop = new uint32_t[iThd];
    
    for (size_t i = 0; i < iThd; i++)
    {
        ppHashCounts[i] = new uint64_t[iBucketSize];
        ppTimestamps[i] = new uint64_t[iBucketSize];
        iBucketTop[i] = 0;
        memset(ppHashCounts[0], 0, sizeof(uint64_t) * iBucketSize);
        memset(ppTimestamps[0], 0, sizeof(uint64_t) * iBucketSize);
    }
}

double telemetry::calc_telemetry_data(size_t iLastMilisec, size_t iThread)
{
    using namespace std::chrono;
    uint64_t iTimeNow = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();
    
    uint64_t iEarliestHashCnt = 0;
    uint64_t iEarliestStamp = 0;
    uint64_t iLastestStamp = 0;
    uint64_t iLastestHashCnt = 0;
    bool bHaveFullSet = false;
    
    //Start at 1, buckettop points to next empty
    for (size_t i = 1; i < iBucketSize; i++)
    {
        size_t idx = (iBucketTop[iThread] - i) & iBucketMask; //overflow expected here
        
        if (ppTimestamps[iThread][idx] == 0)
            break; //That means we don't have the data yet
        
        if (iLastestStamp == 0)
        {
            iLastestStamp = ppTimestamps[iThread][idx];
            iLastestHashCnt = ppHashCounts[iThread][idx];
        }
        
        if (iTimeNow - ppTimestamps[iThread][idx] > iLastMilisec)
        {
            bHaveFullSet = true;
            break; //We are out of the requested time period
        }
        
        iEarliestStamp = ppTimestamps[iThread][idx];
        iEarliestHashCnt = ppHashCounts[iThread][idx];
    }
    
    if (!bHaveFullSet || iEarliestStamp == 0 || iLastestStamp == 0)
        return nan("");
    
    //Don't think that can happen, but just in case
    if (iLastestStamp - iEarliestStamp == 0)
        return nan("");
    
    double fHashes, fTime;
    fHashes = iLastestHashCnt - iEarliestHashCnt;
    fTime = iLastestStamp - iEarliestStamp;
    fTime /= 1000.0;
    
    return fHashes / fTime;
}

void telemetry::push_perf_value(size_t iThd, uint64_t iHashCount, uint64_t iTimestamp)
{
    size_t iTop = iBucketTop[iThd];
    ppHashCounts[iThd][iTop] = iHashCount;
    ppTimestamps[iThd][iTop] = iTimestamp;
    
    iBucketTop[iThd] = (iTop + 1) & iBucketMask;
}

minethd::minethd(miner_work& pWork, size_t iNo, bool double_work, bool no_prefetch, int64_t affinity)
{
	oWork = pWork;
	iThreadNo = (uint8_t)iNo;
	iJobNo = 0;
	bNoPrefetch = no_prefetch;
	this->affinity = affinity;

	oWorkThd = std::thread(&minethd::work_main, this);
}

std::atomic<uint64_t> minethd::iGlobalJobNo;
std::atomic<uint64_t> minethd::iConsumeCnt; //Threads get jobs as they are initialized
minethd::miner_work minethd::oGlobalWork;
uint64_t minethd::iThreadCount = 0;

cryptonight_ctx* minethd_alloc_ctx()
{
	cryptonight_ctx* ctx;
	alloc_msg msg = { 0 };
    
    ctx = cryptonight_alloc_ctx(1, 1, &msg);
    if (ctx == NULL)
        ctx = cryptonight_alloc_ctx(0, 0, NULL);
    return ctx;
}

bool minethd::self_test()
{
	alloc_msg msg = { 0 };
	size_t res;
	bool fatal = false;

	
    res = cryptonight_init(1, 1, &msg);

	if(res == 0 && fatal)
		return false;

	cryptonight_ctx *ctx0;
	if((ctx0 = minethd_alloc_ctx()) == nullptr)
		return false;

	unsigned char out[64];
	bool bResult;

	cn_hash_fun hashf;

	hashf = func_selector(jconf::inst()->HaveHardwareAes(), false);
	hashf("This is a test", 14, out, ctx0);
	bResult = memcmp(out, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;

	hashf = func_selector(jconf::inst()->HaveHardwareAes(), true);
	hashf("This is a test", 14, out, ctx0);
	bResult &= memcmp(out, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;

	cryptonight_free_ctx(ctx0);

	return bResult;
}

std::vector<minethd*>* minethd::thread_starter(miner_work& pWork, int count)
{
	iGlobalJobNo = 0;
	iConsumeCnt = 0;
	std::vector<minethd*>* pvThreads = new std::vector<minethd*>;

	//Launch the requested number of single and double threads, to distribute
	//load evenly we need to alternate single and double threads
	size_t i, n = count;
	pvThreads->reserve(n);

	for (i = 0; i < n; i++)
	{
		minethd* thd = new minethd(pWork, i, false, true, 0);
		pvThreads->push_back(thd);
	}

	iThreadCount = n;
	return pvThreads;
}

void minethd::switch_work(miner_work& pWork)
{
	// iConsumeCnt is a basic lock-like polling mechanism just in case we happen to push work
	// faster than threads can consume them. This should never happen in real life.
	// Pool cant physically send jobs faster than every 250ms or so due to net latency.

	while (iConsumeCnt.load(std::memory_order_seq_cst) < iThreadCount)
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

	oGlobalWork = pWork;
	iConsumeCnt.store(0, std::memory_order_seq_cst);
	iGlobalJobNo++;
}

void minethd::consume_work()
{
	memcpy(&oWork, &oGlobalWork, sizeof(miner_work));
	iJobNo++;
	iConsumeCnt++;
}

minethd::cn_hash_fun minethd::func_selector(bool bHaveAes, bool bNoPrefetch)
{
	// We have two independent flag bits in the functions
	// therefore we will build a binary digit and select the
	// function as a two digit binary
	// Digit order SOFT_AES, NO_PREFETCH

	static const cn_hash_fun func_table[4] = {
		cryptonight_hash<0x80000, MEMORY, false, false>,
		cryptonight_hash<0x80000, MEMORY, false, true>,
		cryptonight_hash<0x80000, MEMORY, true, false>,
		cryptonight_hash<0x80000, MEMORY, true, true>
	};

	std::bitset<2> digit;
	digit.set(0, !bNoPrefetch);
	digit.set(1, !bHaveAes);

	return func_table[digit.to_ulong()];
}

void minethd::pin_thd_affinity()
{
	thd_setaffinity(oWorkThd.native_handle(), affinity);
}

void minethd::work_main()
{
	if(affinity >= 0) //-1 means no affinity
		pin_thd_affinity();

	cn_hash_fun hash_fun;
	cryptonight_ctx* ctx;
	uint64_t iCount = 0;
	uint64_t* piHashVal;
	uint32_t* piNonce;
	job_result result;

	hash_fun = func_selector(jconf::inst()->HaveHardwareAes(), bNoPrefetch);
	ctx = minethd_alloc_ctx();

	piHashVal = (uint64_t*)(result.bResult + 24);
	piNonce = (uint32_t*)(oWork.bWorkBlob + 39);
	iConsumeCnt++;

    while (!executor::inst()->threadsShouldClose.load())
	{
		if (oWork.bStall)
		{
			/*  We are stalled here because the executor didn't find a job for us yet,
			    either because of network latency, or a socket problem. Since we are
			    raison d'etre of this software it us sensible to just wait until we have something*/

			while (iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo
                   && !executor::inst()->threadsShouldClose.load())
				std::this_thread::sleep_for(std::chrono::milliseconds(100));

            if(executor::inst()->threadsShouldClose.load())
                break;
            
			consume_work();
			continue;
		}

        result.iNonce = calc_start_nonce(oWork.iResumeCnt);

		assert(sizeof(job_result::sJobID) == sizeof(pool_job::sJobID));
		memcpy(result.sJobID, oWork.sJobID, sizeof(job_result::sJobID));

		while(iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo
              && !executor::inst()->threadsShouldClose.load())
		{
            if ((iCount & 0xF) == 0) //Store stats every 16 hashes
            {
                using namespace std::chrono;
                uint64_t iStamp = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();
                iHashCount.store(iCount, std::memory_order_relaxed);
                iTimestamp.store(iStamp, std::memory_order_relaxed);
                executor::inst()->push_event(ex_event(EV_HPS));
            }
			iCount++;

			*piNonce = ++result.iNonce;

			hash_fun(oWork.bWorkBlob, oWork.iWorkSize, result.bResult, ctx);

			if (*piHashVal < oWork.iTarget)
				executor::inst()->push_event(ex_event(result));

			std::this_thread::yield();
		}

        if(executor::inst()->threadsShouldClose.load())
            break;
        
		consume_work();
	}

	cryptonight_free_ctx(ctx);
}

void minethd::verify(pool_job& oPoolJob)
{
    cn_hash_fun hash_fun;
    cryptonight_ctx* ctx;
    verify_result result;
    
    hash_fun = func_selector(jconf::inst()->HaveHardwareAes(), false);
    ctx = minethd_alloc_ctx();
    
    hash_fun(oPoolJob.bWorkBlob, oPoolJob.iWorkLen, result.bResult, ctx);
    
    executor::inst()->push_event(ex_event(result));
    
    cryptonight_free_ctx(ctx);
}
