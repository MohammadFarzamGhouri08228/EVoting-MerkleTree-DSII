#pragma once
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>

namespace _sha256_impl {
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
inline uint32_t rotr(uint32_t x,uint32_t n){return(x>>n)|(x<<(32-n));}
inline uint32_t ch(uint32_t e,uint32_t f,uint32_t g){return(e&f)^(~e&g);}
inline uint32_t maj(uint32_t a,uint32_t b,uint32_t c){return(a&b)^(a&c)^(b&c);}
inline uint32_t sig0(uint32_t a){return rotr(a,2)^rotr(a,13)^rotr(a,22);}
inline uint32_t sig1(uint32_t e){return rotr(e,6)^rotr(e,11)^rotr(e,25);}
inline uint32_t gam0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
inline uint32_t gam1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}
inline std::string compute(const std::string& input){
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::string msg=input;
    uint64_t bitLen=(uint64_t)input.size()*8;
    msg+='\x80';
    while(msg.size()%64!=56)msg+='\x00';
    for(int i=7;i>=0;i--)msg+=(char)((bitLen>>(i*8))&0xff);
    for(size_t i=0;i<msg.size();i+=64){
        uint32_t w[64];
        for(int j=0;j<16;j++){
            w[j]=((uint8_t)msg[i+j*4+0])<<24;
            w[j]|=((uint8_t)msg[i+j*4+1])<<16;
            w[j]|=((uint8_t)msg[i+j*4+2])<<8;
            w[j]|=((uint8_t)msg[i+j*4+3]);
        }
        for(int j=16;j<64;j++)
            w[j]=gam1(w[j-2])+w[j-7]+gam0(w[j-15])+w[j-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int j=0;j<64;j++){
            uint32_t t1=hh+sig1(e)+ch(e,f,g)+K[j]+w[j];
            uint32_t t2=sig0(a)+maj(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
        h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    std::ostringstream oss;
    for(int i=0;i<8;i++)oss<<std::hex<<std::setw(8)<<std::setfill('0')<<h[i];
    return oss.str();
}
} // namespace

inline std::string sha256(const std::string& input){
    return _sha256_impl::compute(input);
}
inline std::string generateSalt(size_t len=16){
    static const char cs[]="0123456789abcdef";
    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<size_t> dist(0,sizeof(cs)-2);
    std::string s; s.reserve(len);
    for(size_t i=0;i<len;i++)s+=cs[dist(rng)];
    return s;
}
inline std::string generateReceiptId(){return generateSalt(32);}
inline std::string currentTimestamp(){
    auto now=std::chrono::system_clock::now();
    auto t=std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss; oss<<t; return oss.str();
}
