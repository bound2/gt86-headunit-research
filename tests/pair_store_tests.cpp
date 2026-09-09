/* SPDX-License-Identifier: GPL-3.0-only. PUBLIC synthetic keys only. */
#include "pair_store.h"
#include "monocypher-ed25519.h"
#include "pair_test_support.h"
static pair_store_data initial(const Vectors& v) {
    pair_store_data s{};const auto& id=v.at("own_identifier");
    CHECK(pair_store_init(&s,v.at("own_seed").data(),v.at("own_public").data(),id.data(),id.size())==IAP2_OK);return s;
}
static Bytes encode(const pair_store_data& s) { Bytes b(PAIR_STORE_IMAGE_SIZE);CHECK(pair_store_encode(&s,b.data(),b.size())==IAP2_OK);return b; }
static void rehash(Bytes& b) { crypto_sha512(b.data()+PAIR_STORE_HASH_OFFSET,b.data(),PAIR_STORE_HASH_OFFSET); }
static void rejected(const Bytes& b) { pair_store_data s{};std::memset(&s,0xa5,sizeof(s));auto saved=s;
    CHECK(pair_store_decode(&s,b.data(),b.size())==PAIR_STORE_CORRUPT&&std::memcmp(&s,&saved,sizeof(s))==0); }
static void codec(const Vectors& v) {
    auto s=initial(v);auto b=encode(s);CHECK(b.size()==1888&&std::string(b.begin(),b.begin()+8)=="GT86PS01"&&b[8]==1&&b[16]==s.identity.identifier_size);
    CHECK(equal(b.data()+24,v.at("own_seed"))&&equal(b.data()+56,v.at("own_public"))&&zeroed(b.data()+152,1672));
    pair_store_data d{};CHECK(pair_store_decode(&d,b.data(),b.size())==IAP2_OK&&encode(d)==b);
    std::array<uint8_t,64> sig1{},sig2{};auto message=bytes("persistent identity");
    CHECK(pair_identity_sign(&s.identity,message.data(),message.size(),sig1.data())==IAP2_OK);
    CHECK(pair_identity_sign(&d.identity,message.data(),message.size(),sig2.data())==IAP2_OK&&sig1==sig2);
    for(size_t i=0;i<b.size();++i) { auto bad=b;bad[i]^=1;rejected(bad); }
    for(size_t n=0;n<b.size();++n) rejected(Bytes(b.begin(),b.begin()+n));auto extra=b;extra.push_back(0);rejected(extra);
    // Correct checksum cannot legitimize noncanonical fields or wrong identity.
    for(size_t offset:{size_t(0),size_t(8),size_t(15),size_t(16),size_t(17),size_t(23),size_t(24),size_t(56),size_t(151),size_t(152),size_t(156),size_t(160),size_t(1823)}) {
        auto bad=b;bad[offset]^=1;rehash(bad);rejected(bad);
    }
    for(unsigned n:{0u,65u,255u}) { auto bad=b;bad[16]=static_cast<uint8_t>(n);rehash(bad);rejected(bad); }
    auto saved=b;CHECK(pair_store_encode(&s,b.data(),b.size()-1)==IAP2_NO_SPACE&&b==saved);
    s.identity.secret[0]^=1;CHECK(pair_store_encode(&s,b.data(),b.size())==IAP2_AUTH_FAILED&&b==saved);
    pair_store_clear(&s);pair_store_clear(&d);CHECK(zeroed(&s,sizeof(s))&&zeroed(&d,sizeof(d)));
}
static void mappings(const Vectors& v) {
    auto s=initial(v),before=s;const auto& id=v.at("ctrl_identifier");const auto& pk=v.at("ctrl_public");std::array<uint8_t,32> found{};
    CHECK(pair_store_lookup(&s,id.data(),id.size(),found.data())==IAP2_END&&zeroed(found.data(),32));
    CHECK(pair_store_add(&s,id.data(),id.size(),pk.data())==IAP2_OK&&s.count==1&&s.revision==2);
    CHECK(pair_store_successor(&before,&s)==IAP2_OK);auto b=encode(s);auto saved=s;
    CHECK(pair_store_add(&s,id.data(),id.size(),pk.data())==IAP2_END&&std::memcmp(&s,&saved,sizeof(s))==0);
    CHECK(pair_store_add(&s,id.data(),id.size(),v.at("own_public").data())==PAIR_STORE_CONFLICT&&std::memcmp(&s,&saved,sizeof(s))==0);
    CHECK(pair_store_lookup(&s,id.data(),id.size(),found.data())==IAP2_OK&&equal(found.data(),pk));
    for(const auto& bad:std::vector<Bytes>{{},{'A',0},{32},Bytes(65,'A'),{127}}) {
        CHECK(pair_store_add(&s,bad.data(),bad.size(),pk.data())==IAP2_ARGUMENT&&std::memcmp(&s,&saved,sizeof(s))==0);
        CHECK(pair_store_lookup(&s,bad.data(),bad.size(),found.data())==IAP2_ARGUMENT&&zeroed(found.data(),32));
    }
    for(size_t offset:{size_t(161),size_t(167),size_t(231),size_t(264)}) { auto bad=b;bad[offset]=1;rehash(bad);rejected(bad); }
    for(unsigned n:{0u,65u,255u}) { auto bad=b;bad[160]=static_cast<uint8_t>(n);rehash(bad);rejected(bad); }
    // Duplicate identifier with a valid hash and valid count/revision is invalid.
    auto duplicate=b;duplicate[8]=3;duplicate[152]=2;std::copy(b.begin()+160,b.begin()+264,duplicate.begin()+264);rehash(duplicate);rejected(duplicate);
    for(unsigned i=1;i<PAIR_STORE_MAX_CONTROLLERS;++i) { auto name=bytes("controller-"+std::to_string(i));auto previous=s;
        CHECK(pair_store_add(&s,name.data(),name.size(),pk.data())==IAP2_OK&&pair_store_successor(&previous,&s)==IAP2_OK);pair_store_clear(&previous); }
    auto full=encode(s);pair_store_data decoded{};CHECK(pair_store_decode(&decoded,full.data(),full.size())==IAP2_OK&&encode(decoded)==full);
    auto extra=bytes("excess");CHECK(pair_store_add(&s,extra.data(),extra.size(),pk.data())==IAP2_NO_SPACE&&encode(s)==full);
    CHECK(pair_store_add(&s,id.data(),id.size(),pk.data())==IAP2_END&&encode(s)==full); // Idempotence even when full.
    CHECK(pair_store_successor(&s,&saved)==PAIR_STORE_CORRUPT&&pair_store_successor(&before,&s)==PAIR_STORE_CORRUPT);
    auto next=saved;auto second=bytes("second");CHECK(pair_store_add(&next,second.data(),second.size(),pk.data())==IAP2_OK);
    next.controllers[0].public_key[0]^=1;CHECK(pair_store_successor(&saved,&next)==PAIR_STORE_CORRUPT);
    next=saved;CHECK(pair_store_add(&next,second.data(),second.size(),pk.data())==IAP2_OK);next.seed[0]^=1;CHECK(pair_store_successor(&saved,&next)==PAIR_STORE_CORRUPT);
    pair_store_clear(&s);pair_store_clear(&before);pair_store_clear(&saved);pair_store_clear(&decoded);pair_store_clear(&next);
}
struct Rng { Bytes seed;int calls=0;bool fail=false;static int read(void* p,uint8_t* out,size_t n) { auto& r=*static_cast<Rng*>(p);CHECK(n==32);++r.calls;std::copy(r.seed.begin(),r.seed.end(),out);return r.fail?-1:0; } };
static void explicit_creation(const Vectors& v) {
    auto s=initial(v),saved=s;auto id=v.at("own_identifier");Rng rng{v.at("own_seed")};
    CHECK(pair_store_generate(&s,nullptr,&rng,id.data(),id.size())==IAP2_ARGUMENT&&rng.calls==0);
    CHECK(pair_store_generate(&s,Rng::read,&rng,id.data(),0)==IAP2_ARGUMENT&&rng.calls==0);
    rng.fail=true;CHECK(pair_store_generate(&s,Rng::read,&rng,id.data(),id.size())==IAP2_PROVIDER_FAILED&&rng.calls==1&&std::memcmp(&s,&saved,sizeof(s))==0);
    rng.fail=false;CHECK(pair_store_generate(&s,Rng::read,&rng,id.data(),id.size())==IAP2_OK&&rng.calls==2&&encode(s)==encode(saved));
    CHECK(pair_store_init(&s,v.at("own_seed").data(),v.at("ctrl_public").data(),id.data(),id.size())==IAP2_AUTH_FAILED&&encode(s)==encode(saved));
    pair_store_clear(&s);pair_store_clear(&saved);
}
int main(int argc,char** argv) { try { CHECK(argc==2);auto v=load_vectors(argv[1],21);codec(v);mappings(v);explicit_creation(v);
    std::cout<<"PASS: portable store canonical codec, every-byte corruption/truncation, conflicts/capacity/history, explicit identity\n";return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; } }
