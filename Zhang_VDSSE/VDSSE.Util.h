/* 
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 * 
 */

#ifndef VDSSE_UTIL_H
#define VDSSE_UTIL_H

#include <random>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cassert>
#include <memory>
#include <string>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <stdexcept>
#include <csignal>
#include <unordered_set>
#include <unistd.h>

#include <sys/time.h>

#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>

#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>

#define AES128_KEY_LEN 16

namespace VDSSE {

    class Util {

    public:
        static std::string H1(const std::string message);

        static std::string H2(const std::string message);

        static std::string Xor(const std::string s1, const std::string s2);

        static double getCurrentTime();
    };

}// namespace VDSSE

#endif //VDSSE_UTIL_H
