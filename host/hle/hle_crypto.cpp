#include "hle_common.hpp"

#include <array>
#include <cstdint>
#include <cstring>

namespace portablekit {
namespace {

constexpr std::array<std::uint32_t, 64> kShift = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};
constexpr std::array<std::uint32_t, 64> kTable = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

std::uint32_t rotl(std::uint32_t x, std::uint32_t n) { return (x << n) | (x >> (32u - n)); }

struct Md5 {
    std::uint32_t h[4]{0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u};
    std::uint64_t total{};
    std::uint8_t buffer[64]{};
};

void transform(Md5 &m, const std::uint8_t *block) {
    std::uint32_t words[16];
    for (unsigned i=0;i<16;++i)
        words[i]=std::uint32_t(block[i*4])|(std::uint32_t(block[i*4+1])<<8)|
                 (std::uint32_t(block[i*4+2])<<16)|(std::uint32_t(block[i*4+3])<<24);
    auto a=m.h[0], b=m.h[1], c=m.h[2], d=m.h[3];
    for (unsigned i=0;i<64;++i) {
        std::uint32_t f{},g{};
        if(i<16){f=(b&c)|(~b&d);g=i;}
        else if(i<32){f=(d&b)|(~d&c);g=(5*i+1)%16;}
        else if(i<48){f=b^c^d;g=(3*i+5)%16;}
        else{f=c^(b|~d);g=(7*i)%16;}
        const auto next=d; d=c; c=b;
        b += rotl(a+f+kTable[i]+words[g],kShift[i]); a=next;
    }
    m.h[0]+=a;m.h[1]+=b;m.h[2]+=c;m.h[3]+=d;
}

void update(Md5 &m,const std::uint8_t *data,std::size_t len) {
    std::size_t used=static_cast<std::size_t>(m.total&63u);
    m.total+=len;
    if(used){const auto take=std::min(len,64u-used);std::memcpy(m.buffer+used,data,take);used+=take;data+=take;len-=take;if(used==64)transform(m,m.buffer);}
    while(len>=64){transform(m,data);data+=64;len-=64;}
    if(len)std::memcpy(m.buffer,data,len);
}

void finish(Md5 m,std::uint8_t out[16]) {
    const auto bits=m.total*8u;
    std::uint8_t tail[128]{0x80};
    const std::size_t pad=(m.total&63u)<56u?56u-static_cast<std::size_t>(m.total&63u):120u-static_cast<std::size_t>(m.total&63u);
    for(unsigned i=0;i<8;++i)tail[pad+i]=static_cast<std::uint8_t>(bits>>(i*8));
    update(m,tail,pad+8);
    for(unsigned i=0;i<4;++i)for(unsigned j=0;j<4;++j)out[i*4+j]=static_cast<std::uint8_t>(m.h[i]>>(j*8));
}

bool read_context(psprecomp::GuestMemory &mem,std::uint32_t addr,Md5 &m) {
    if(addr==0||!mem.contains(addr,96))return false;
    for(unsigned i=0;i<4;++i)m.h[i]=mem.load32(addr+i*4);
    m.total=std::uint64_t(mem.load32(addr+24))|(std::uint64_t(mem.load32(addr+28))<<32);
    for(unsigned i=0;i<64;++i)m.buffer[i]=mem.load8(addr+32+i);
    return true;
}
void write_context(psprecomp::GuestMemory &mem,std::uint32_t addr,const Md5 &m) {
    for(unsigned i=0;i<4;++i)mem.store32(addr+i*4,m.h[i]);
    mem.store16(addr+20,static_cast<std::uint16_t>(m.total&63u));
    mem.store16(addr+22,0);
    mem.store32(addr+24,static_cast<std::uint32_t>(m.total));
    mem.store32(addr+28,static_cast<std::uint32_t>(m.total>>32));
    for(unsigned i=0;i<64;++i)mem.store8(addr+32+i,m.buffer[i]);
}
}

void register_crypto(HleRegistrar &hle) {
    hle.try_add("sceMd5","sceMd5BlockInit",[](Runtime &rt,AllegrexContext &ctx){
        auto &mem=rt.memory();const auto a=arg(ctx,0);
        if(a==0||!mem.contains(a,96)){kernel().finish(ctx,0xFFFFFFFFu);return;}
        Md5 m;for(unsigned i=0;i<4;++i)mem.store32(a+i*4,m.h[i]);
        mem.store16(a+20,0);mem.store16(a+22,0);mem.store32(a+24,0);mem.store32(a+28,0);
        kernel().finish(ctx,0u);
    });
    hle.try_add("sceMd5","sceMd5BlockUpdate",[](Runtime &rt,AllegrexContext &ctx){
        auto &mem=rt.memory();const auto a=arg(ctx,0),p=arg(ctx,1),n=arg(ctx,2);
        if(!read_context(mem,a,*new Md5{} ) || !mem.contains(p,n)){kernel().finish(ctx,0xFFFFFFFFu);return;}
        Md5 m;read_context(mem,a,m);
        std::array<std::uint8_t,4096> chunk{};
        std::uint32_t done=0;
        while(done<n){const auto count=std::min<std::uint32_t>(n-done,chunk.size());for(std::uint32_t i=0;i<count;++i)chunk[i]=mem.load8(p+done+i);update(m,chunk.data(),count);done+=count;}
        // Match the PSP's observable 64-byte rolling context buffer.
        if(n){const auto count=std::min<std::uint32_t>(n,64);const auto start=n-count;for(std::uint32_t i=0;i<count;++i)mem.store8(a+32+((m.total-n+start+i)&63u),mem.load8(p+start+i));}
        write_context(mem,a,m);kernel().finish(ctx,0u);
    });
    hle.try_add("sceMd5","sceMd5BlockResult",[](Runtime &rt,AllegrexContext &ctx){
        auto &mem=rt.memory();const auto a=arg(ctx,0),out=arg(ctx,1);Md5 m;
        if(!read_context(mem,a,m)||!mem.contains(out,16)){kernel().finish(ctx,0xFFFFFFFFu);return;}
        std::uint8_t digest[16];finish(m,digest);for(unsigned i=0;i<16;++i)mem.store8(out+i,digest[i]);write_context(mem,a,m);kernel().finish(ctx,0u);
    });
    hle.try_add("sceMd5","sceMd5Digest",[](Runtime &rt,AllegrexContext &ctx){
        auto &mem=rt.memory();const auto p=arg(ctx,0),n=arg(ctx,1),out=arg(ctx,2);
        if(!mem.contains(p,n)||!mem.contains(out,16)){kernel().finish(ctx,0xFFFFFFFFu);return;}
        Md5 m;std::array<std::uint8_t,4096> chunk{};std::uint32_t done=0;
        while(done<n){const auto count=std::min<std::uint32_t>(n-done,chunk.size());for(std::uint32_t i=0;i<count;++i)chunk[i]=mem.load8(p+done+i);update(m,chunk.data(),count);done+=count;}
        std::uint8_t digest[16];finish(m,digest);for(unsigned i=0;i<16;++i)mem.store8(out+i,digest[i]);kernel().finish(ctx,0u);
    });
}
} // namespace portablekit
