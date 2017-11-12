#pragma once
#include "thdq.hpp"
#include "msgstruct.h"
#include <atomic>
#include <array>
#include <list>
#include <future>

class minethd;
class telemetry;

typedef void (*ErrorCallback)(char* error);
typedef void (*HashFoundCallback)(char* result, char*nonce);
typedef void (*VerifiedCallback)(char*result);

class executor
{
public:
	static executor* inst()
	{
		if (oInst == nullptr) oInst = new executor;
		return oInst;
	};
    
    std::atomic<bool> threadsShouldClose;
    
    void start();
    void stop();
    double calcHPS();
    
    bool process_pool_job(const char*blob, const char*target);
    bool process_verify_job(const char*blob);
    
	inline void push_event(ex_event&& ev) { oEventQ.push(std::move(ev)); }
    
    static ErrorCallback errorCallback;
    static HashFoundCallback hashFoundCallback;
    static VerifiedCallback verifiedCallback;
    static int threadsCount;
    
private:

	thdq<ex_event> oEventQ;
    
	std::vector<minethd*>* pvThreads;
    
	executor();
    
	static executor* oInst;

    telemetry* telem;
	void ex_main();

	void on_pool_have_job(pool_job& oPoolJob);
	void on_miner_result(job_result& oResult);
    void on_verify_result(verify_result& oResult);
    void cmd_submit(const char* sJobId, uint32_t iNonce, const uint8_t* bResult);
};
