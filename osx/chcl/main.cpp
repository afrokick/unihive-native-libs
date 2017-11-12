//
//  main.cpp
//  chcl
//
//  Created by Alexander Sosnovskiy on 10/24/17.
//  Copyright © 2017 Alexander Sosnovskiy. All rights reserved.
//

#include <iostream>
#include <assert.h>
#include <stdio.h>
#include "unihivelib.h"

void onError(char*error)
{
    std::cout << error << "\n\n";
}

void onHashFounded(char*blob, char*target)
{
    std::cout <<"blob:" << blob << ", target:" << target << "\n";
    std::cout << "hps:" << GetHashesPerSecond() << "\n\n";
}

void onVerified(char*result)
{
    std::cout <<"verified:" << result << "\n";
}

int main(int argc, const char * argv[]) {

    bool initialized = Initialize(&onError,&onHashFounded,&onVerified,3);
    
    if(!initialized){
        std::cout << "not initialized!";
    }
    
    StartMiner();
//    Verify("06069dc38ecf0509132046857788cfdc02664333c550d3042467febe0c11a4cc151e1b2ba951dbfffa62aad07caca6deb2b845897397f5e86fc0eba91baae1eeeb3ae141a21f4c88693bae08");
    ReceiveJob("0606aec28ecf05b9bad631e92fc601050de11fa14fd636d3a1672ea4064e5bf17c7ea7edacb681000000000ce0e1e7b4fc71ae6b7691b9e10c30f1adb5084bac9dc144fa084df6a8ace3100a", "ffffff00");
    int i;
    while(true){
        i=0;
    std::cin >> i;
        
        if(i==100)
            StopMiner();
        if(i==99)
            StartMiner();
    }
    
    return 0;
}
