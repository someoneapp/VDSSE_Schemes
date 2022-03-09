/* 
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 * 
 */

#ifndef VDSSE_CLIENT_H
#define VDSSE_CLIENT_H

#include <grpc++/grpc++.h>
#include "VDSSE.grpc.pb.h"
#include "VDSSE.Util.h"
#include "ae_mhash/mhash.h"
#include <malloc.h>
#include "aes/aes_ctr.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReaderInterface;
using grpc::ClientWriterInterface;
using grpc::ClientAsyncResponseReaderInterface;
using grpc::Status;
using namespace CryptoPP;

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif


byte k_s[17] = "0123456789abcdef";
byte iv_s[17] = "0123456789abcdef";



byte k_r[17] = "abcdef1234567890";
byte iv_r[17] = "0123456789abcdef";


byte k_st[17] = "123456788abcdef0";
byte iv_st[17] = "0abcdef123456789";


extern int max_keyword_length;
extern int max_nodes_number;

namespace VDSSE {
    class Client {
    private:
        std::unique_ptr <RPC::Stub> stub_;
        rocksdb::DB *cs_db;
        std::mutex sc_mtx;
        std::mutex st_mtx;
        std::map <std::string, std::string> proof_mapper;
        std::map <std::string, size_t> uc_mapper;
        std::map <std::string, std::string> st_mapper;
    public:

        Client(std::shared_ptr <Channel> channel, std::string db_path) : stub_(RPC::NewStub(channel)) {
            rocksdb::Options options;
            rocksdb::Options simple_options;
            simple_options.create_if_missing = true;
            simple_options.use_fsync = true;
            rocksdb::Status status = rocksdb::DB::Open(simple_options, db_path, &cs_db);
        }

        ~Client() {

            size_t keyword_counter = 0;
            std::map<std::string, std::string>::iterator it3;
            for (it3 = st_mapper.begin(); it3 != st_mapper.end(); ++it3) {
                store("t" + it3->first, it3->second);
            }

            std::map<std::string, std::string>::iterator it2;
            for (it2 = proof_mapper.begin(); it2 != proof_mapper.end(); ++it2) {
                store("s" + it2->first, it2->second);
            }

            std::map<std::string, size_t>::iterator it;
            for (it = uc_mapper.begin(); it != uc_mapper.end(); ++it) {
                store("u" + it->first, std::to_string(it->second));
            }
            cs_db->Flush(rocksdb::FlushOptions());
            delete cs_db;
            malloc_trim(0);

            std::cout << "Bye~ " << std::endl;
        }

        int store(const std::string k, const std::string v) {
            rocksdb::Status s = cs_db->Delete(rocksdb::WriteOptions(), k);
            s = cs_db->Put(rocksdb::WriteOptions(), k, v);
            if (s.ok()) return 0;
            else return -1;
        }

        std::string get(const std::string k) {
            std::string tmp;
            rocksdb::Status s = cs_db->Get(rocksdb::ReadOptions(), k, &tmp);
            if (s.ok()) return tmp;
            else return "";
        }

        std::string get_proof(std::string w) {
            std::string proof;
            std::map<std::string, std::string>::iterator it;
            it = proof_mapper.find(w);
            if (it != proof_mapper.end()) {
                proof = it->second;
            } else {
                proof = "";
            }
            return proof;
        }

        int set_proof(std::string w, std::string proof) {
            {
                std::lock_guard <std::mutex> lock(sc_mtx);
                proof_mapper[w] = proof;
            }
            return 0;
        }


        std::string get_search_state(std::string w) {
            std::string search_state;
            std::map<std::string, std::string>::iterator it;
            it = st_mapper.find(w);
            if (it != st_mapper.end()) {
                search_state = it->second;
            } else {
                search_state = "";
            }
            return search_state;
        }

        int set_search_state(std::string w, std::string search_state) {
            {
                std::lock_guard <std::mutex> lock(st_mtx);
                st_mapper[w] = search_state;
            }
            return 0;
        }


        size_t get_update_time(std::string w) {
            size_t update_time = 0;
            std::map<std::string, size_t>::iterator it;
            it = uc_mapper.find(w);
            if (it != uc_mapper.end()) {
                update_time = it->second; // TODO need to lock when read, but for our scheme, no need
            }
            return update_time;
        }

        int set_update_time(std::string w, int update_time) {
            {
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                uc_mapper[w] = update_time;
            }
            return 0;
        }

        void increase_update_time(std::string w) {
            {
                set_update_time(w, get_update_time(w) + 1);
            }
        }


        UpdateRequestMessage gen_update_request(mhash_ctx *ctx, std::string op, std::string w, std::string ind) {
            try {
                std::string enc_token;
                UpdateRequestMessage msg;
                std::string tw, l, e, stw;
                size_t uc;
                uc = get_update_time(w);
                if (uc == 0){
                    std::string value;
                    value = get("s" + w);
                    if (value == "" && op == "0"){
                        std::cout << "the keyword " << w << " has not added， " << "can't be deleted!" << std::endl;
                        return msg;
                    } else if (value == ""){
                        uc = 0;
                        uc_mapper[w] = uc;
                    } else if (value != "") {
                        proof_mapper[w] = value;
                        value = get("t" + w);
                        st_mapper[w] = value;
                        value = get("u" + w);
                        uc = std::stoi(value);
                        uc_mapper[w] = uc;
                    }
                }

                std::string st, s1;
                std::string proof = get_proof(w);

                ALIGN(16) unsigned long hash[2] = {0};
                if (proof != ""){
                    char *cs = const_cast<char*>(proof.c_str());
                    const char *d  = "|";
                    char *p = strtok(cs, d);
                    hash[0] = strtoul(p, NULL, 10);
                    p=strtok(NULL, d);
                    hash[1] = strtoul(p, NULL, 10);
                }
                e_ctx* fctx = e_allocate(NULL);
                e_init(fctx, (unsigned char*)k_s, 16);
                ALIGN(16) const char* cw;
                ALIGN(16) char ctw[16];
                cw = w.c_str();
                fencrypt1(fctx, iv_s, cw, w.length(), ctw);
                tw.assign(ctw, 16); 
                ALIGN(16) const char *ep;
                ep = ind.c_str();
                mhash_xor(ctx, ep, 7, hash);
                byte rand[AES128_KEY_LEN];
                AutoSeededRandomPool rnd;
			    rnd.GenerateBlock(rand, AES128_KEY_LEN);
                if (proof == ""){
                    st = std::string((const char*)rand, AES128_KEY_LEN);
                    e = Util::Xor("0000000000000000" + op + ind, Util::H2(tw + st));
                    ep = st.c_str();
                    mhash_xor(ctx, ep, 16, hash);
                } else {
                    s1 = get_search_state(w);
                    st = std::string((const char*)rand, AES128_KEY_LEN);
                    e = Util::Xor(s1 + op + ind, Util::H2(tw + st));
                    ep = st.c_str();
                    mhash_xor(ctx, ep, 16, hash);
                    ep = s1.c_str();
                    mhash_xor(ctx, ep, 16, hash);
                }
                l = Util::H1(tw + st);
                set_proof(w, std::to_string(hash[0])+"|"+std::to_string(hash[1])+"|");
                set_update_time(w, uc + 1);
                set_search_state(w, st);

                msg.set_l(l);
                msg.set_e(e);
                e_clear(fctx);
                e_free(fctx);
                return msg;
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in gen_update_request() " << e.what() << std::endl;
                exit(1);
            }
        }


        int search(const std::string w) {
            std::cout << "client search: " << w << std::endl;
            size_t uc;
            uc = get_update_time(w);
            if (uc == 0){
                std::string value;
                value = get("s" + w);
                if (value == ""){
                    std::cout << "the keyword " << w << " does no exist" << std::endl;
                    return 0;
                }
                proof_mapper[w] = value;
                value = get("t" + w);
                st_mapper[w] = value;
                value = get("u" + w);
                uc = std::stoi(value);
                uc_mapper[w] = uc;
            }

            std::string tw;
            std::string st;
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_s, 16);
            ALIGN(16) const char* cw;
            ALIGN(16) char ctw[16];
            cw = w.c_str();
            fencrypt1(fctx, iv_s, cw, w.length(), ctw);
            tw.assign(ctw, 16); 
            st = get_search_state(w);
            std::unordered_set<std::string> result;
            result = search_server(tw, st, uc);
            bool r = verify(w, st, result);
        

            if (r){
                return result.size();

            } else {
                return 0;
            }
            e_clear(fctx);
            e_free(fctx);
            return result.size();
        }


        std::unordered_set <std::string> search_server(const std::string tw, const std::string st, int uc) {
            SearchRequestMessage request;
            request.set_tw(tw);
            request.set_st(st);
            request.set_uc(uc);
            ClientContext context;
            std::unique_ptr <ClientReaderInterface<SearchReply>> reader = stub_->search(&context, request);
            int counter = 0;
            SearchReply reply;
            std::unordered_set <std::string> result;
            while (reader->Read(&reply)) {
                result.insert(reply.ind());
            }
            return result;
        }

        bool verify(const std::string w, const std::string st, std::unordered_set <std::string> result) {
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_r, 16);
            ALIGN(16) const char* cw = w.c_str();
            ALIGN(16) char key[16];
            fencrypt1(fctx, iv_r, cw, w.length(), key);
            ALIGN(16) const char *ep;
            ALIGN(16) unsigned long hash[2] = {0};
            //strncpy(key, rw.c_str(), 16);
            mhash_ctx* m_ctx = mhash_allocate(NULL);
            mhash_init(m_ctx, (unsigned char*)key, 16);
            ep = st.c_str();
            mhash_xor(m_ctx, ep, 16, hash);
            std::string value;
            for (std::unordered_set<std::string>::iterator i = result.begin(); i != result.end(); i++) {
                value = *i;
                ep = value.c_str();
                mhash_xor(m_ctx, ep, 7, hash);
            }
            std::string proof = get_proof(w);
            std::string hash_string = std::to_string(hash[0]) + "|" + std::to_string(hash[1]) + "|";
            if (hash_string == proof){
                mhash_clear(m_ctx);
                mhash_free(m_ctx);
                e_clear(fctx);
                e_free(fctx);
                return 1;
            } else {
                mhash_clear(m_ctx);
                mhash_free(m_ctx);
                e_clear(fctx);
                e_free(fctx);
                return 0;
            }
        }

        void updates(std::vector<std::pair<std::string, std::string>> index){
            UpdateRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials())));
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));

            std::string keyword;
            std::string ind;
            std::string last = " ";
            mhash_ctx* m_ctx = mhash_allocate(NULL);
            ALIGN(16) const char* key;
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_r, 16);
            ALIGN(16) const char* cw;
            std::pair<std::string, std::string> p; 
            ALIGN(16) char rw[16];

            for (int i=0; i<index.size(); i++){
                p = index.at(i);
                keyword = p.first;
                ind = p.second;
                if (last != keyword){
                cw = keyword.c_str();
                fencrypt1(fctx, iv_r, cw, keyword.length(), rw);
                mhash_init(m_ctx, (unsigned char*)rw, 16);
            }
            request = gen_update_request(m_ctx, "1", keyword, ind);
            if (request.l().length() == 0){
                break;
            } else {
                writer->Write(request);
            }
                last = keyword;

            }
            mhash_clear(m_ctx);
            mhash_free(m_ctx);
            e_clear(fctx);
            e_free(fctx);
            writer->WritesDone();
            Status status = writer->Finish();
            if(!status.ok()){
                std::cout<<"batch update error: "<<status.error_details()<<std::endl;
            }
        }




        void updatetest(std::string keyword, std::vector<std::pair<std::string, std::string>> index){
            UpdateRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials())));
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
            std::string op, ind;
            mhash_ctx* m_ctx = mhash_allocate(NULL);
            ALIGN(16) const char* key;
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_r, 16);
            ALIGN(16) const char* cw;
            std::pair<std::string, std::string> p; 
            ALIGN(16) char rw[16];
             cw = keyword.c_str();
            fencrypt1(fctx, iv_r, cw, keyword.length(), rw);
            mhash_init(m_ctx, (unsigned char*)rw, 16);

            for (int i=0; i<index.size(); i++){
                p = index.at(i);
                op = p.first;
                ind = p.second;
                request = gen_update_request(m_ctx, op, keyword, ind);
                if (request.l().length() == 0){
                    break;
                } else {
                    writer->Write(request);
                }
            }
            mhash_clear(m_ctx);
            mhash_free(m_ctx);
            e_clear(fctx);
            e_free(fctx);
            writer->WritesDone();
            Status status = writer->Finish();
            if(!status.ok()){
                std::cout<<"batch update error: "<<status.error_details()<<std::endl;
            }
        }

    };

} // namespace VDSSE

#endif // VDSSE_CLIENT_H
