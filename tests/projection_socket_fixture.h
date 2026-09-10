#ifndef GT86_PROJECTION_SOCKET_FIXTURE_H
#define GT86_PROJECTION_SOCKET_FIXTURE_H
/* SPDX-License-Identifier: GPL-3.0-only
 * Real Windows LOOPBACK sockets, public synthetic keys, simulated media only.
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <chrono>
#include "projection_services.h"
#include "projection_receiver_fixture.h"
static constexpr uint64_t ms=1000000,sec=1000000000;
static projection_ip loopback(bool v6=false,uint8_t last=1) {
    projection_ip ip{}; ip.family=v6?6:4; if(!v6) ip.bytes[0]=127; ip.bytes[v6?15:3]=last; return ip;
}
static SOCKADDR_STORAGE address(projection_ip ip,uint16_t port,int& n) {
    SOCKADDR_STORAGE out{};
    if(ip.family==4) { auto& a=*reinterpret_cast<SOCKADDR_IN*>(&out); a.sin_family=AF_INET; a.sin_port=htons(port); std::memcpy(&a.sin_addr,ip.bytes,4); n=sizeof(a); }
    else { auto& a=*reinterpret_cast<SOCKADDR_IN6*>(&out); a.sin6_family=AF_INET6; a.sin6_port=htons(port); std::memcpy(&a.sin6_addr,ip.bytes,16); a.sin6_scope_id=ip.scope; n=sizeof(a); }
    return out;
}
struct Winsock {
    Winsock() { WSADATA d{}; CHECK(WSAStartup(MAKEWORD(2,2),&d)==0); }
    ~Winsock() { WSACleanup(); }
};
struct Socket {
    SOCKET value=INVALID_SOCKET; projection_ip ip; uint16_t port=0;
    explicit Socket(int type=SOCK_DGRAM,bool v6=false,uint8_t last=1,uint16_t requested_port=0):ip(loopback(v6,last)) {
        value=socket(v6?AF_INET6:AF_INET,type,0); CHECK(value!=INVALID_SOCKET);
        int n=0; auto a=address(ip,requested_port,n); CHECK(bind(value,reinterpret_cast<SOCKADDR*>(&a),n)==0);
        CHECK(getsockname(value,reinterpret_cast<SOCKADDR*>(&a),&n)==0);
        port=ntohs(v6?reinterpret_cast<SOCKADDR_IN6*>(&a)->sin6_port:reinterpret_cast<SOCKADDR_IN*>(&a)->sin_port);
        u_long one=1; CHECK(ioctlsocket(value,FIONBIO,&one)==0);
    }
    ~Socket() { close(); }
    Socket(const Socket&)=delete; Socket& operator=(const Socket&)=delete;
    void close() { if(value!=INVALID_SOCKET) { closesocket(value); value=INVALID_SOCKET; } }
    bool ready(bool writing=false,long usec=2000000) {
        fd_set f; FD_ZERO(&f); FD_SET(value,&f); timeval t{usec/1000000,usec%1000000};
        int r=select(0,writing?nullptr:&f,writing?&f:nullptr,nullptr,&t); CHECK(r!=SOCKET_ERROR); return r!=0;
    }
    void connect_to(uint16_t p) {
        int n=0; auto a=address(loopback(ip.family==6),p,n); int r=connect(value,reinterpret_cast<SOCKADDR*>(&a),n);
        if(r) { CHECK(WSAGetLastError()==WSAEWOULDBLOCK&&ready(true)); int error=0; n=sizeof(error);
            CHECK(getsockopt(value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&n)==0&&error==0); }
    }
    void datagram(const Bytes& b,uint16_t p) {
        int n=0; auto a=address(loopback(ip.family==6),p,n);
        CHECK(sendto(value,reinterpret_cast<const char*>(b.data()),static_cast<int>(b.size()),0,reinterpret_cast<SOCKADDR*>(&a),n)==static_cast<int>(b.size()));
    }
    Bytes receive_datagram(uint16_t expected_port) {
        CHECK(ready()); std::array<uint8_t,1024> b{}; SOCKADDR_STORAGE a{}; int n=sizeof(a);
        int used=recvfrom(value,reinterpret_cast<char*>(b.data()),static_cast<int>(b.size()),0,reinterpret_cast<SOCKADDR*>(&a),&n); CHECK(used>=0);
        CHECK(ntohs(ip.family==6?reinterpret_cast<SOCKADDR_IN6*>(&a)->sin6_port:reinterpret_cast<SOCKADDR_IN*>(&a)->sin_port)==expected_port);
        return {b.begin(),b.begin()+used};
    }
    void send_bytes(const Bytes& b) {
        size_t offset=0; auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(offset<b.size()) { CHECK(std::chrono::steady_clock::now()<deadline); int n=send(value,reinterpret_cast<const char*>(b.data()+offset),static_cast<int>(b.size()-offset),0);
            if(n==SOCKET_ERROR) { CHECK(WSAGetLastError()==WSAEWOULDBLOCK); Sleep(1); } else { CHECK(n>0); offset+=n; } }
    }
    Bytes receive_bytes(size_t count) {
        Bytes b(count); size_t used=0; auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(used<count) { CHECK(std::chrono::steady_clock::now()<deadline); int n=recv(value,reinterpret_cast<char*>(b.data()+used),static_cast<int>(count-used),0);
            if(n==SOCKET_ERROR) { CHECK(WSAGetLastError()==WSAEWOULDBLOCK); Sleep(1); } else { CHECK(n>0); used+=n; } } return b;
    }
};
#endif
