/* 
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 * 
 */
#ifndef FT_VDSSE_CLIENT_H
#define FT_VDSSE_CLIENT_H

#include <grpc++/grpc++.h>
#include "FT_VDSSE.grpc.pb.h"
#include "FT_VDSSE.Util.h"
#include "ae_mhash/ae.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <tuple>
#include <iomanip>
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



byte k_p[17] = "abcdef1234567890";
byte iv_p[17] = "0123456789abcdef";

byte k_t[17] = "qwertyuiopasdfgh";
byte iv_t[17] = "wdf3e5f7g9ahcuej";



//ALIGN(16) char indss[7200000];



//extern int max_keyword_length;
//extern int max_nodes_number;

namespace FT_VDSSE {
    /*#if __GNUC__
    #define ALIGN(n)      __attribute__ ((aligned(n))) 
    #elif _MSC_VER
    #define ALIGN(n)      __declspec(align(n))
    #else
    #define ALIGN(n)
    #endif*/

    class Client {
    private:
        std::unique_ptr <RPC::Stub> stub_;
        rocksdb::DB *cs_db;
        std::map <std::string, int> c1_mapper;
        std::map <std::string, int> c2_mapper;
    public:

        Client(std::shared_ptr <Channel> channel, std::string db_path) : stub_(RPC::NewStub(channel)) {
            rocksdb::Options options;
            rocksdb::Options simple_options;
            simple_options.create_if_missing = true;
            //simple_options.merge_operator.reset(new rocksdb::StringAppendOperator());
            simple_options.use_fsync = true;
            rocksdb::Status status = rocksdb::DB::Open(simple_options, db_path, &cs_db);
        }



        ~Client() {
            std::map<std::string, int>::iterator it;
            std::map<std::string, int>::iterator it2;
            for (it = c1_mapper.begin(), it2 = c2_mapper.begin(); it != c1_mapper.end(); ++it, ++it2) {
                store(it->first, std::to_string(it->second) + "|" + std::to_string(it2->second) + "|");
            }
            cs_db->Flush(rocksdb::FlushOptions());
            delete cs_db;

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

        int get_c1(std::string w) {
            int c1;
            std::map<std::string, int>::iterator it;
            it = c1_mapper.find(w);
            if (it != c1_mapper.end()) {
                c1 = it->second; // TODO need to lock when read, but for our scheme, no need
            } else {
                c1 = 0;
                set_c1(w, 0);
                
            }
            return c1;
        }

        int set_c1(std::string w, int c1) {
            {
                //std::lock_guard <std::mutex> lock(uc_mtx);
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                c1_mapper[w] = c1;
            }
            return 0;
        }

        int get_c2(std::string w) {
            int c2;
            std::map<std::string, int>::iterator it;
            it = c2_mapper.find(w);
            if (it != c2_mapper.end()) {
                c2 = it->second; // TODO need to lock when read, but for our scheme, no need
            } else {
                c2 = 0;
                set_c2(w, 0);
                
            }
            return c2;
        }

        int set_c2(std::string w, int c2) {
            {
                //std::lock_guard <std::mutex> lock(uc_mtx);
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                c2_mapper[w] = c2;
            }
            return 0;
        }



         std::string ctrencrypt(const byte *skey, const byte *siv, const std::string plainText){

                e_ctx* encctx = e_allocate(NULL);
                e_init(encctx, (unsigned char*)skey, 16);
                //std::cout<<wc2<<std::endl; 
                ALIGN(16) const char* cplain = plainText.c_str();
                int length = plainText.length();
                ALIGN(16) char ccipher[length];
                encrypt_ctr(encctx, iv_s, cplain, length, ccipher);
                std::string cipher(ccipher, length);
                e_clear(encctx);
                e_free(encctx);
                return cipher;
        }


        std::string ctrdecrypt(const byte *skey, const byte *siv, const std::string cipherText){

                e_ctx* decctx = e_allocate(NULL);
                e_init(decctx, (unsigned char*)skey, 16);
                ALIGN(16) const char* ccipher = cipherText.c_str();
                int length = cipherText.length();
                ALIGN(16) char cplain[length];
                decrypt_ctr(decctx, iv_s, ccipher, length, cplain);
                std::string plain(cplain, length);
                e_clear(decctx);
                e_free(decctx);
                return plain;
        }


        /*std::string CTR_AESEncryptStr(const byte *skey, const byte *siv, const std::string plainText){
            std::string outstr;
            try {
                CTR_Mode<AES>::Encryption e;
                e.SetKeyWithIV(skey, AES128_KEY_LEN, siv, (size_t) AES::BLOCKSIZE);
                /*if (token.length()==16){
                    token_padding = token;
                } else {*/
                    //token_padding = Util::padding(token);
                //}
                //byte cipher_text[token_padding.length()];
                /*StringSource ss2(plainText, true, 
                    new StreamTransformationFilter( e,
                    new StringSink(outstr)
                    )     
                );
                //enc_token = std::string((const char *) cipher_text, token_padding.length());
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in CTR_AESEncryptStr" << e.what() << std::endl;
                exit(1);
            }
            return outstr;
        } 

        /*std::string CTR_AESDecryptStr(const byte *skey, const byte *siv, const std::string cipherText){
            std::string outstr;
            try {
                CTR_Mode<AES>::Decryption e;
                e.SetKeyWithIV(skey, AES128_KEY_LEN, siv, (size_t) AES::BLOCKSIZE);
                /*if (token.length()==16){
                    token_padding = token;
                } else {*/
                    //token_padding = Util::padding(token);
                //}
                //byte cipher_text[token_padding.length()];
                /*StringSource ss2(cipherText, true, 
                    new StreamTransformationFilter( e,
                    new StringSink(outstr)
                    )     
                );
                //enc_token = std::string((const char *) cipher_text, token_padding.length());
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in CTR_AESDecryptStr" << e.what() << std::endl;
                exit(1);
            }
            return outstr;
        } */

       UpdateRequestMessage gen_update_request(ae_ctx *ctx, std::string op, std::string w, std::string ind) {            
            try {

                UpdateRequestMessage msg;
                ALIGN(16) int c1, c2;
                c1 = get_c1(w);
                if (c1 == 0){
                    std::string value;
                    char *cs;
                    const char *d  = "|";
                    char *p;
                    value = get(w);
                    if (value == "" && op == "0"){
                        std::cout << "the keyword " << w << " has not added， " << "can't be deleted!" << std::endl;
                        return msg;
                    } else if (value == "") {
                        c1 = 0;
                        c1_mapper[w] = 0;
                        c2_mapper[w] = 0;
                    } else if (value != "") {
                        cs = const_cast<char*>(value.c_str());
                        p = strtok(cs, d);
                        c1 = atoi(p);
                        c1_mapper[w] = c1;
                        p=strtok(NULL, d);
                        c2_mapper[w] = atoi(p);
                    }
                }
                c2 = get_c2(w);
                std::string sw, st, s1;
                std::string l, e, proof;
                e_ctx* fctx = e_allocate(NULL);
                e_init(fctx, (unsigned char*)k_s, 16);
                ALIGN(16) const char* cw = w.c_str();
                ALIGN(16) char csw[16];
                fencrypt1(fctx, iv_s, cw, w.length(), csw);
                sw.assign(csw, 16);
                ALIGN(16) unsigned long ae_ind;
                ALIGN(16) unsigned long ae_tag;
                std::string opind = op+ind;
                ALIGN(16) const char* indp = opind.c_str();
                e_ctx* fctx2 = e_allocate(NULL);
                e_init(fctx2, (unsigned char*)k_t, 16);
                std::string wc1c2;
                ALIGN(16) const char* cwc1c2;
                ALIGN(16) char cst[16];
                if (c1==0){
                    c1 = 1;
                    wc1c2 = w + std::to_string(c1) + std::to_string(c2); 
                    cwc1c2 = wc1c2.c_str();
                    fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
                    st.assign(cst, 16);
                    e = Util::Xor("0000000000000000" + opind, Util::H2(sw + st));
                    ae_encrypt(ctx, &c1, indp, 8, &ae_ind, &ae_tag);
                    proof = std::to_string(ae_ind) + "|" + std::to_string(ae_tag) + "|";
                } else {
                    wc1c2 = w + std::to_string(c1) + std::to_string(c2); 
                    cwc1c2 = wc1c2.c_str();
                    fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
                    s1.assign(cst, 16);
                    c1 += 1;
                    wc1c2 = w + std::to_string(c1) + std::to_string(c2); 
                    cwc1c2 = wc1c2.c_str();
                    fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
                    st.assign(cst, 16);
                    e = Util::Xor(s1 + opind, Util::H2(sw + st));
                    ae_encrypt(ctx, &c1, indp, 8, &ae_ind, &ae_tag);
                    proof = std::to_string(ae_ind) + "|" + std::to_string(ae_tag) + "|";
                }
                l = Util::H1(sw + st);
                set_c1(w, c1);
                msg.set_l(l);
                msg.set_e(e);
                msg.set_proof(proof);
                e_clear(fctx);
                e_free(fctx);
                e_clear(fctx2);
                e_free(fctx2);
                return msg;
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in gen_update_request() " << e.what() << std::endl;
                exit(1);
            }

           
        }

        int search(const std::string w, std::unordered_set <std::string> &result, int &c1, int &c2, std::string &sw) {
            std::cout << "client search: " << w <<std::endl;
            c1 = get_c1(w);
            if (c1 == 0){
                std::string value;
                char *cs;
                const char *d  = "|";
                char *p;
                value = get(w);
                if (value == ""){
                    std::cout << "the keyword " << w << " does no exist" << std::endl;
                    return 0;
                }
                cs = const_cast<char*>(value.c_str());
                p = strtok(cs, d);
                c1 = atoi(p);
                c1_mapper[w] = c1;
                p=strtok(NULL, d);
                c2_mapper[w] = atoi(p);
            }
            std::string st;
            std::vector <std::string> proofs;
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_s, 16);
            ALIGN(16) const char* cw = w.c_str();
            ALIGN(16) char csw[16];
            fencrypt1(fctx, iv_s, cw, w.length(), csw);
            sw.assign(csw, 16); 
            c2 = get_c2(w);
            bool first = 0;
            if (c2 == 0){
                first = 1;
            }
            e_ctx* fctx2 = e_allocate(NULL);
            e_init(fctx2, (unsigned char*)k_t, 16);
            std::string wc1c2;
            ALIGN(16) const char* cwc1c2;
            ALIGN(16) char cst[16];
            wc1c2 = w + std::to_string(c1) + std::to_string(c2); 
            cwc1c2 = wc1c2.c_str();
            fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
            st.assign(cst, 16);

            result = search_server(sw, st, c1, first, proofs);
            bool r = verify(w, st, result, proofs, c1, c2);
            if (!r){
                return 0;

            } else {
                return result.size();
            }
        }


        int renewproof(std::string w, std::unordered_set <std::string> result, int c, std::string sw){
                int c1 = 1;
                int c2 = c+1;
                set_c1(w, c1);
                set_c2(w, c2);
                std::string st;
                e_ctx* fctx = e_allocate(NULL);
                e_init(fctx, (unsigned char*)k_p, 16);
                std::string wc2 = w + std::to_string(c2); 
                ALIGN(16) const char* cwc2 = wc2.c_str();
                ALIGN(16) char key[16];
                fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
                ae_ctx* ctx = ae_allocate(NULL);
                ae_init(ctx, (unsigned char*)key, 16);
                 e_ctx* fctx2 = e_allocate(NULL);
                e_init(fctx2, (unsigned char*)k_t, 16);
                std::string wc1c2;
                ALIGN(16) const char* cwc1c2;
                ALIGN(16) char cst[16];
                wc1c2 = w + std::to_string(c1) + std::to_string(c2); 
                cwc1c2 = wc1c2.c_str();
                fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
                st.assign(cst, 16);
                std::unordered_set <std::string>::iterator it;
                std::string inds = "";
                for (it = result.begin(); it != result.end(); it++){
                    inds += *it;
                }

                const byte* k_st = (const byte *)st.c_str();
                 std ::string enc_inds = ctrencrypt(k_st, iv_s, inds); 
                int inds_size = inds.length();
                int inds_bytes = inds_size/8; 
                ALIGN(16) const char* indsp = inds.c_str();
                int k;
                ALIGN(16) unsigned long c_inds[inds_bytes];
                ALIGN(16) unsigned long tag;
                ae_encrypt(ctx, &c1, indsp, inds_size, c_inds, &tag);
                std::string proof = "";
                for (int i =0; i<inds_bytes; i++){
                    proof += std::to_string(c_inds[i]);
                    proof += "|";
                }
                proof = proof + std::to_string(tag) + "|";
                ClientContext context;
                ExecuteStatus exec_status;
                UpdateRequestMessage msg;
                std::string l = Util::H1(sw + st);
                msg.set_l(l);
                msg.set_e(enc_inds);
                msg.set_proof(proof);
                ae_clear(ctx);
                ae_free(ctx);
                e_clear(fctx);
                e_free(fctx);
                e_clear(fctx2);
                e_free(fctx2);
                Status status = stub_->update2(&context, msg, &exec_status);
        }



       int search_renew(const std::string w) {
            std::cout << "client search: " << w <<std::endl;
            //double start, end, timeval1, timeval2;
            //start = Util::getCurrentTime();
            int c1, c2;
            c1 = get_c1(w);
            if (c1 == 0){
                std::string value;
                char *cs;
                const char *d  = "|";
                char *p;
                value = get(w);
                if (value == ""){
                    std::cout << "the keyword " << w << " does no exist" << std::endl;
                    return 0;
                }
                cs = const_cast<char*>(value.c_str());
                p = strtok(cs, d);
                c1 = atoi(p);
                c1_mapper[w] = c1;
                p=strtok(NULL, d);
                c2_mapper[w] = atoi(p);
            }

            std::string sw;
            std::string st;
            std::vector <std::string> proofs;
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_s, 16);
            ALIGN(16) const char* cw = w.c_str();
            ALIGN(16) char csw[16];
            fencrypt1(fctx, iv_s, cw, w.length(), csw);
            sw.assign(csw, 16); 
            c2 = get_c2(w);
            bool first = 0;
            if (c2 == 0){
                first = 1;
            }
            e_ctx* fctx2 = e_allocate(NULL);
            e_init(fctx2, (unsigned char*)k_t, 16);
            std::string wc1c2;
            ALIGN(16) const char* cwc1c2;
            ALIGN(16) char cst[16];
            wc1c2 = w + std::to_string(c1) + std::to_string(c2); 
            cwc1c2 = wc1c2.c_str();
            fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
            st.assign(cst, 16);
            //end = Util::getCurrentTime();
            //timeval1 = (end-start)*1000;
            std::unordered_set <std::string> result = search_server(sw, st, c1, first, proofs);
            /*for (auto it = result.begin(); it!=result.end(); it++){
                std::cout<<*it<<std::endl;
            }*/
            //start = Util::getCurrentTime();
            bool r = verify(w, st, result, proofs, c1, c2);
            //end = Util::getCurrentTime();
            //timeval2 = (end-start)*1000;
            if (!r){
                return 0;
            } /*else {
                std::ofstream OsWrite(file,std::ofstream::app);
                OsWrite<<result.size()<<std::endl;
                OsWrite<<timeval1+timeval2<<std::endl;
                OsWrite.close();
            }*/
            
            if (result.size()<c1){
                //std::ofstream OsWrite1("reproof.txt",std::ofstream::app);
                //double start = FT_VDSSE::Util::getCurrentTime();
                c1 = 1;
                c2 += 1;
                set_c1(w, c1);
                set_c2(w, c2);
                e_ctx* fctx = e_allocate(NULL);
                e_init(fctx, (unsigned char*)k_p, 16);
                std::string wc2 = w + std::to_string(c2); 
                ALIGN(16) const char* cwc2 = wc2.c_str();
                ALIGN(16) char key[16];
                fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
                ae_ctx* ctx = ae_allocate(NULL);
                ae_init(ctx, (unsigned char*)key, 16);
                 e_ctx* fctx2 = e_allocate(NULL);
                e_init(fctx2, (unsigned char*)k_t, 16);
                std::string wc1c2;
                ALIGN(16) const char* cwc1c2;
                ALIGN(16) char cst[16];
                wc1c2 = w + std::to_string(c1) + std::to_string(c2); 
                cwc1c2 = wc1c2.c_str();
                fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
                st.assign(cst, 16);
                std::unordered_set <std::string>::iterator it;
                std::string inds = "";
                for (it = result.begin(); it != result.end(); it++){
                    inds += "1" + *it;
                }
                const byte* k_st = (const byte *)st.c_str();
                 std ::string enc_inds = ctrencrypt(k_st, iv_s, inds);
                int inds_size = inds.length();
            
                int inds_bytes = inds_size/8; 
                ALIGN(16) const char* indsp = inds.c_str();
                int k;
                ALIGN(16) unsigned long c_inds[inds_bytes];
                ALIGN(16) unsigned long tag;
                ae_encrypt(ctx, &c1, indsp, inds_size, c_inds, &tag);
                std::string proof = "";
                for (int i =0; i<inds_bytes; i++){
                    proof += std::to_string(c_inds[i]);
                    proof += "|";
                }
                proof = proof + std::to_string(tag) + "|";
                ClientContext context;
                ExecuteStatus exec_status;
                UpdateRequestMessage msg;
                std::string l = Util::H1(sw + st);
                msg.set_l(l);
                msg.set_e(enc_inds);
                msg.set_proof(proof);
                ae_clear(ctx);
                ae_free(ctx);
                e_clear(fctx);
                e_free(fctx);
                e_clear(fctx2);
                e_free(fctx2);
                Status status = stub_->update2(&context, msg, &exec_status);
                //double end = FT_VDSSE::Util::getCurrentTime();
                //double time = (end - start)*1000;
                //OsWrite1<<result.size() << " "<<time<<std::endl;
            }
            return result.size();
        }



       

       std::unordered_set <std::string> search_server(const std::string sw, const std::string st, const int c1, const bool first, std::vector <std::string> &proofs) {
            SearchRequestMessage request;
            request.set_sw(sw);
            request.set_st(st);
            request.set_c1(c1);
            request.set_first(first);
            ClientContext context;
            std::unique_ptr <ClientReaderInterface<SearchReply>> reader = stub_->search(&context, request);
            int counter = 0;
            SearchReply reply;
            std::unordered_set <std::string> result;
            std::string ind;
            while (reader->Read(&reply))  {
                ind = reply.ind();
                if (ind != ""){
                    result.insert(reply.ind());
                } else {
                    break;
                }
            }
            
            proofs.push_back(reply.proof());
            while (reader->Read(&reply)) {
                proofs.push_back(reply.proof());
            }
            return result;
        }

        

       

        bool verify(const std::string w, const std::string st, std::unordered_set <std::string> result, std::vector <std::string> proofs, int c1, int c2) {
            std::unordered_set <std::string>::iterator it;
             e_ctx* fctx = e_allocate(NULL);
             e_init(fctx, (unsigned char*)k_p, 16);
             std::string wc2 = w + std::to_string(c2);
            ALIGN(16) const char* cwc2 = wc2.c_str();
            ALIGN(16) char key[16];
            fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
            ae_ctx* ctx = ae_allocate(NULL);
            ae_init(ctx, (unsigned char*)key, 16);
            
            std::string item;
            int c_ind = 1 ;
            int i = 0;
            char *cs = const_cast<char*>(proofs[c1-1].c_str());
            const char *d  = "|";
            char *p;
            if (c2 > 0){
                p = strtok(cs, d);
                c_ind = atoi(p);
            }
            ALIGN(16) unsigned long ae_inds[c_ind + 1];
            ALIGN(16) unsigned long ae_tag;
            if (c2>0) {
                p=strtok(NULL, d);
                while(p)
                {
                    ae_inds[i++] = strtoul(p, NULL, 10);
                    p=strtok(NULL, d);
                }
            } else {
                p = strtok(cs, d);;
                while(p)
                {
                    ae_inds[i++] = strtoul(p, NULL, 10);
                    p=strtok(NULL, d);
                }
            } 
            int c_inds_bytes = c_ind * 8;
            ALIGN(16) char *inds = new char[c_inds_bytes];
            ALIGN(16) int nonce = 1;
            ae_decrypt(ctx, &nonce, ae_inds, c_inds_bytes, inds, &ae_inds[c_ind]);
            std::unordered_set <std::string> result2;
           char *pos = inds;
           std::string s_ind, op;
            for (i=0; i<c_ind; i++){
                s_ind = std::string(pos+1, pos + 8);
                result2.insert(s_ind);
                pos += 8;
            }
            ALIGN(16) unsigned long ae_ind;
            ALIGN(16) char ind[8];
            int j;
            for (i=c1-2; i>=0; i--){
                nonce += 1;
                cs = const_cast<char*>(proofs[i].c_str());
                p = strtok(cs, d);
                ae_ind = strtoul(p, NULL, 10);
                //std::getline(ss, item, '|');
                p=strtok(NULL, d);
                ae_tag = strtoul(p, NULL, 10);
                ae_decrypt(ctx, &nonce, &ae_ind, 8, ind, &ae_tag);
                op = std::string(ind, ind + 1);
                s_ind = std::string(ind+1, ind + 8);
                if (op == "1"){
                    result2.insert(s_ind);
                } else {
                    it = result2.find(s_ind);
                    if (it != result2.end()){
                        result2.erase(s_ind);
                    } 
                }
                /*it = result2.find(s_ind);
                if (it != result2.end()){
                    result2.erase(s_ind);
                } else{
                    result2.insert(s_ind);
                }*/
            }
            if (result == result2){
                ae_clear(ctx);
                ae_free(ctx);
                e_clear(fctx);
                e_free(fctx);
                return 1;
            } else {
                ae_clear(ctx);
                ae_free(ctx);
                return 0;
            } 

            return 1;

        }




        // used for batch addition
        void updates(std::vector<std::pair<std::string, std::string>> index){
            UpdateRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
            std::string keyword;
             std::string ind;
            std::string last = " ";
            ae_ctx* ctx = ae_allocate(NULL);
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_p, 16);
            int c2;
            std::string wc2; 
            ALIGN(16) const char* cwc2;
            std::pair<std::string, std::string> p; 
            // int count =0;
            ALIGN(16) char pw[16];
            for (int i=0; i<index.size(); i++){
                p = index.at(i);
                keyword = p.first;
                ind = p.second;
                if (last != keyword){
                    c2 = get_c2(keyword);
                    wc2 = keyword + std::to_string(c2);
                    cwc2 = wc2.c_str();
                    fencrypt1(fctx, iv_s, cwc2, wc2.length(), pw);
                    ae_init(ctx, (unsigned char*)pw, 16);
                }
                request = gen_update_request(ctx, "1", keyword, ind);
                if (request.l().length() == 0){
                    break;
                } else {
                    writer->Write(request);
                }
                last = keyword;
            }
            ae_clear(ctx);
            ae_free(ctx);
            e_clear(fctx);
            e_free(fctx);
            writer->WritesDone();
             Status status = writer->Finish();
                if(!status.ok()){
                  std::cout<<"batch_update error"<<std::endl;
    
                }        



            
    }







    //used for updates in trace simulation
    void updatetest(std::string keyword, std::vector<std::pair<std::string, std::string>> index){
            UpdateRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
            std::string op;
             std::string ind;
            ae_ctx* ctx = ae_allocate(NULL);
            e_ctx* fctx = e_allocate(NULL);
            e_init(fctx, (unsigned char*)k_p, 16);
            int c1, c2;
            std::string wc2; 
            ALIGN(16) const char* cwc2;
            std::pair<std::string, std::string> pair; 
            ALIGN(16) char pw[16];
            std::string value;
            char *cs;
            const char *d  = "|";
            char *p;
            value = get(keyword);
            if (value == "") {
                c1_mapper[keyword] = 0;
                c2_mapper[keyword] = 0;
            } else if (value != "") {
                cs = const_cast<char*>(value.c_str());
                p = strtok(cs, d);
                c1 = atoi(p);
                c1_mapper[keyword] = c1;
                p=strtok(NULL, d);
                c2_mapper[keyword] = atoi(p);
            }
            c2 = get_c2(keyword);
            wc2 = keyword + std::to_string(c2);
            cwc2 = wc2.c_str();
            fencrypt1(fctx, iv_s, cwc2, wc2.length(), pw);
            ae_init(ctx, (unsigned char*)pw, 16);
            for (int i=0; i<index.size(); i++){
                pair= index.at(i);
                op = pair.first;
                ind = pair.second;
                request = gen_update_request(ctx, op, keyword, ind);
                if (request.l().length() == 0){
                    break;
                } else {
                    writer->Write(request);
                }
            }
            ae_clear(ctx);
            ae_free(ctx);
            e_clear(fctx);
            e_free(fctx);
            writer->WritesDone();
            Status status = writer->Finish();
            if(!status.ok()){
                std::cout<<"batch_update error"<<std::endl;
            }   
    }

    };

} // namespace FT_VDSSE

#endif // FT_VDSSE_CLIENT_H
