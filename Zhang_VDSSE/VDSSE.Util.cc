#include "VDSSE.Util.h"

using namespace CryptoPP;


namespace VDSSE {

    std::string Util::H1(const std::string message) {
        byte buf[SHA256::DIGESTSIZE];
        std::string salt = "01";
        SHA256().CalculateDigest(buf, (byte * )((message + salt).c_str()), message.length() + salt.length());
        return std::string((const char *) buf, (size_t) SHA256::DIGESTSIZE);
    }

    std::string Util::H2(const std::string message) {
        byte buf[SHA256::DIGESTSIZE];
        std::string salt = "02";
        SHA256().CalculateDigest(buf, (byte * )((message + salt).c_str()), message.length() + salt.length());
        return std::string((const char *) buf, (size_t) SHA256::DIGESTSIZE);
    }

    std::string Util::Xor(const std::string s1, const std::string s2) {
        // std::cout<< "in len = "<< s1.length()<<", s1 = "<<s1<<std::endl;
        std::string result = s1;
        if (s1.length() > s2.length()) {
            //ERROR
            std::cout << "not sufficient size: " << s1.length() << ", " << s2.length() << std::endl;
            return "";
        }

        for (int i = 0; i < result.length(); i++) {
            result[i] ^= s2[i];
        }
        return result;
    }

    double Util::getCurrentTime(){
	    double res = 0;
	    struct timeval tv;
	    gettimeofday(&tv, NULL);
	    res += tv.tv_sec;
	    res += (tv.tv_usec/1000000.0);
	    return res;
    }


}// namespace VDSSE
