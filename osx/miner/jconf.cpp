#include "jconf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unihivelib.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#include <intrin.h>
#endif
#if defined __arm__

#else
#include <cpuid.h>
#endif

jconf* jconf::oInst = nullptr;

jconf::jconf()
{
}



void jconf::cpuid(uint32_t eax, int32_t ecx, int32_t val[4])
{
	memset(val, 0, sizeof(int32_t)*4);

#ifdef _WIN32
	__cpuidex(val, eax, ecx);
#endif
#if defined __arm__
    val[2] = 0;
    val[3] = 0;
#else
	__cpuid_count(eax, ecx, val[0], val[1], val[2], val[3]);
#endif
}

bool jconf::check_cpu_features()
{
	constexpr int AESNI_BIT = 1 << 25;
	constexpr int SSE2_BIT = 1 << 26;
	int32_t cpu_info[4];
	bool bHaveSse2;

	cpuid(1, 0, cpu_info);

	bHaveAes = (cpu_info[2] & AESNI_BIT) != 0;
	bHaveSse2 = (cpu_info[3] & SSE2_BIT) != 0;

	return bHaveSse2;
}
