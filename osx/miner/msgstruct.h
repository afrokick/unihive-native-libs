#pragma once
#include <string>
#include <string.h>
#include <assert.h>

// Structures that we use to pass info between threads constructors are here just to make
// the stack allocation take up less space, heap is a shared resouce that needs locks too of course

struct pool_job
{
	char		sJobID[64];
	uint8_t		bWorkBlob[112];
	uint64_t	iTarget;
	uint32_t	iWorkLen;
	uint32_t	iResumeCnt;

	pool_job() : iWorkLen(0), iResumeCnt(0) {}
	pool_job(const char* sJobID, uint64_t iTarget, const uint8_t* bWorkBlob, uint32_t iWorkLen) :
		iTarget(iTarget), iWorkLen(iWorkLen), iResumeCnt(0)
	{
		assert(iWorkLen <= sizeof(pool_job::bWorkBlob));
		memcpy(this->sJobID, sJobID, sizeof(pool_job::sJobID));
		memcpy(this->bWorkBlob, bWorkBlob, iWorkLen);
	}
};

struct job_result
{
	uint8_t		bResult[32];
	char		sJobID[64];
	uint32_t	iNonce;

	job_result() {}
	job_result(const char* sJobID, uint32_t iNonce, const uint8_t* bResult) : iNonce(iNonce)
	{
		memcpy(this->sJobID, sJobID, sizeof(job_result::sJobID));
		memcpy(this->bResult, bResult, sizeof(job_result::bResult));
	}
};

struct verify_result
{
    uint8_t        bResult[32];
    
    verify_result() {}
    verify_result(const uint8_t* bResult)
    {
        memcpy(this->bResult, bResult, sizeof(verify_result::bResult));
    }
};

enum ex_event_name { EV_POOL_HAVE_JOB, EV_MINER_HAVE_RESULT, EV_VERIFY_RESULT, EV_HPS };

/*
   This is how I learned to stop worrying and love c++11 =).
   Ghosts of endless heap allocations have finally been exorcised. Thanks
   to the nifty magic of move semantics, string will only be allocated
   once on the heap. Considering that it makes a jorney across stack,
   heap alloced queue, to another stack before being finally processed
   I think it is kind of nifty, don't you?
   Also note that for non-arg events we only copy two qwords
*/

struct ex_event
{
	ex_event_name iName;

	union
	{
		pool_job oPoolJob;
		job_result oJobResult;
        verify_result oVerifyResult;
	};
    ex_event(){}
	ex_event(job_result dat) : iName(EV_MINER_HAVE_RESULT),  oJobResult(dat) {}
    ex_event(verify_result dat) : iName(EV_VERIFY_RESULT),  oVerifyResult(dat) {}
	ex_event(pool_job dat) : iName(EV_POOL_HAVE_JOB),  oPoolJob(dat) {}
	ex_event(ex_event_name ev) : iName(ev){}

	// Delete the copy operators to make sure we are moving only what is needed
	ex_event(ex_event const&) = delete;
	ex_event& operator=(ex_event const&) = delete;

	ex_event(ex_event&& from)
	{
		iName = from.iName;

		switch(iName)
		{
		case EV_MINER_HAVE_RESULT:
			oJobResult = from.oJobResult;
			break;
		case EV_POOL_HAVE_JOB:
			oPoolJob = from.oPoolJob;
			break;
        case EV_VERIFY_RESULT:
            oVerifyResult = from.oVerifyResult;
            break;
		default:
			break;
		}
	}

	ex_event& operator=(ex_event&& from)
	{
		assert(this != &from);

		iName = from.iName;

		switch(iName)
		{
		case EV_MINER_HAVE_RESULT:
			oJobResult = from.oJobResult;
			break;
		case EV_POOL_HAVE_JOB:
			oPoolJob = from.oPoolJob;
			break;
        case EV_VERIFY_RESULT:
            oVerifyResult = from.oVerifyResult;
            break;
		default:
			break;
		}

		return *this;
	}
};
