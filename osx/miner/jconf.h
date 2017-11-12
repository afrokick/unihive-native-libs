#pragma once
#include <stdlib.h>
#include <string>

class jconf
{
public:
	static jconf* inst()
	{
		if (oInst == nullptr) oInst = new jconf;
		return oInst;
	};
    
	inline bool HaveHardwareAes() { return bHaveAes; }
    
private:
	jconf();
	static jconf* oInst;
    static void cpuid(uint32_t eax, int32_t ecx, int32_t val[4]);
	bool check_cpu_features();
	struct opaque_private;
	opaque_private* prv;

	bool bHaveAes;
};
