/* 
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 * 
 */
#ifndef FT_VDSSE_SERVER_H
#define FT_VDSSE_SERVER_H
#include <grpc++/grpc++.h>
#include "FT_VDSSE.grpc.pb.h"
#include "FT_VDSSE.Util.h"
#include <unordered_set>
#include <aes/aes_ctr.h>
#include <string>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerWriter;
using grpc::Status;

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

CryptoPP::byte iv_s[17] = "0123456789abcdef";

namespace FT_VDSSE {
    class FT_VDSSEServiceImpl final : public RPC::Service {
    private:
        static rocksdb::DB *ss_db;
    public:
        FT_VDSSEServiceImpl(const std::string db_path) {
            signal(SIGINT, abort);
            rocksdb::Options options;
            options.create_if_missing = true;
            rocksdb::Status s1 = rocksdb::DB::Open(options, db_path, &ss_db);
            if (!s1.ok()) {
                std::cerr << "open ssdb error:" << s1.ToString() << std::endl;
            }
        }
        static void abort(int signum) {
            ss_db->Flush(rocksdb::FlushOptions());
            delete ss_db;
            std::cout << "abort: " << signum << std::endl;
            exit(signum);
        }
        static int store(rocksdb::DB *&db, const std::string l, const std::string e, const std::string proof) {
            rocksdb::Status s;
            rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
            {
                s = db->Put(write_option, l, e + proof);
            }
            assert(s.ok());
            if (s.ok()) return 0;
            else {
                std::cerr << s.ToString() << std::endl;
                return -1;
            }
        }

        static int store2(rocksdb::DB *&db, const std::string l, const std::string e, const std::string proof) {
            rocksdb::Status s;
            rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
            size_t c_ind = e.length()/8;
            {
                s = db->Put(write_option, l, std::to_string(c_ind) + "|" + e + proof);
            }
            assert(s.ok());
            if (s.ok()) return 0;
            else {
                return -1;
            }
        }

        static std::string get(rocksdb::DB *&db, const std::string l) {
            std::string tmp;
            rocksdb::Status s;
            {
                s = db->Get(rocksdb::ReadOptions(), l, &tmp);
            }
            return tmp;
        }

        static bool get(rocksdb::DB *&db, const std::string l, std::string &e) {

            rocksdb::Status s;
            {
                s = db->Get(rocksdb::ReadOptions(), l, &e);
            }
            return s.ok();
        }


        static int delete_entry(rocksdb::DB *&db, const std::string l) {
            int status = -1;
            try {
                rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
                rocksdb::Status s;
                s = db->Delete(write_option, l);
                if (s.ok()) status = 0;
            } catch (std::exception &e) {
                std::cerr << "in delete_entry() " << e.what() << std::endl;
                exit(1);
            }
            return status;
        }



        static void parse(std::string str, std::string &st, std::string &op, std::string &ind) {
            st = str.substr(0, 16);
            op = str.substr(16, 1);
            ind = str.substr(17, 7);
        }



        /*std::string CTR_AESDecryptStr(const CryptoPP::byte *skey, const CryptoPP::byte *siv, const std::string cipherText){
            std::string outstr;
            try {
                CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption e;
                e.SetKeyWithIV(skey, AES128_KEY_LEN, siv, (size_t) CryptoPP::AES::BLOCKSIZE);
                /*if (token.length()==16){
                    token_padding = token;
                } else {*/
                    //token_padding = Util::padding(token);
                //}
                //byte cipher_text[token_padding.length()];
                /*CryptoPP::StringSource ss2(cipherText, true, 
                    new CryptoPP::StreamTransformationFilter( e,
                    new CryptoPP::StringSink(outstr)
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


         std::string ctrdecrypt(const CryptoPP::byte *skey, const CryptoPP::byte *siv, const std::string cipherText){

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


        Status search(ServerContext *context, const SearchRequestMessage *request, ServerWriter <SearchReply> *writer) {
            std::cout << "server: search(ServerContext *context, const SearchRequestMessage *request, ServerWriter <SearchReply> *writer)"<< std::endl;
            std::string sw = request->sw();
            std::string st = request->st();
            int c1 = request->c1();
            bool first = request->first();
            double start, end;
            start = Util::getCurrentTime();
            std::string ep, e, proof, value, op, ind;
            std::unordered_set <std::string> result;
            std::unordered_set <std::string> del;
            std::vector <std::string> proofs;
            std::unordered_set <std::string>::iterator it;
            int i;
            std::string l;
            std::unordered_set<std::string> uts;
            for(i=0; i<c1-1; i++) {
                l = Util::H1(sw + st);
                uts.insert(l);
                bool found = get(ss_db, l, ep);
                if (found) {
                    e = ep.substr(0, 24);
                    proof = ep.substr(24);
                    value = Util::Xor(e, Util::H2(sw + st));
                    std::string op, ind;
                    parse(value, st, op, ind);
                    if (op == "0"){
                        del.insert(ind);
                    } else {
                        if (del.empty()){
                            result.insert(ind);
                        } else {
                            it = del.find(ind);
                            if (it == del.end()) {
                                result.insert(ind);
                            }
                        }
                        
                    }
                    proofs.push_back(proof);
                } else {
                    std::cout << "error: We were supposed to find something!" << std::endl;
                }
            }
            l = Util::H1(sw + st);
            uts.insert(l);
            bool found = get(ss_db, l, ep);
            if (found) {
                if (first){
                    e = ep.substr(0, 24);
                    proof = ep.substr(24);
                    value = Util::Xor(e, Util::H2(sw + st));
                    std::string op, ind;
                    parse(value, st, op, ind);
                    if (del.empty()){
                            result.insert(ind);
                    } else {
                        it = del.find(ind);
                        if (it == del.end()) {
                            result.insert(ind);
                        }
                    }
                    proofs.push_back(proof);

                } else {
                    char *cs = const_cast<char*>(ep.c_str());
                    const char *d  = "|";
                    char *p = strtok(cs, d);
                    std::string item = p;  
                    int c_ind;
                    c_ind = atoi(p);
                    int index = strlen(p);

                    std::string enc_inds = ep.substr(index + 1, c_ind * 8);
                    const CryptoPP::byte* k_st = (const CryptoPP::byte*)st.c_str();
                    std::string inds = ctrdecrypt(k_st, iv_s, enc_inds); 

                    index += c_ind * 8;
                    int j = 0;
                    for (i=0; i<c_ind; i++){
                        ind = inds.substr(j+1, 7);
                        j += 8;
                        if (del.empty()){
                            result.insert(ind);
                        } else {
                            it = del.find(ind);
                            //it = del.find(ind);
                            if (it == del.end()) {
                                result.insert(ind);
                            }
                        }

                    }
                    proof = ep.substr(index + 1);
                    proofs.push_back(item + "|" + proof);
                }
            } else {
                std::cout << "error: We were supposed to find something!" << std::endl;
            }


             //end=Util::getCurrentTime();
            SearchReply reply;
            for (std::unordered_set<std::string>::iterator i = result.begin(); i != result.end(); i++) {
                reply.set_ind(*i);
                writer->Write(reply);
            }

            std::vector<std::string>::iterator j = proofs.begin();
            std::string qq = *j;
            reply.set_proof(*j);
            reply.set_ind("");
            writer->Write(reply);
            

            for (j = proofs.begin() + 1; j != proofs.end(); j++) { // proofs 的begin是最后一个proof
                reply.set_proof(*j);
                writer->Write(reply);
            }
           if (proofs.size() > result.size()){

                for (std::unordered_set<std::string>::iterator i = uts.begin(); i != uts.end(); i++) {
                    delete_entry(ss_db, *i);
                }
                    
            }
            return Status::OK;
        } 



        // update()实现单次更新操作
        Status update(ServerContext *context, const UpdateRequestMessage *request, ExecuteStatus *response) {
            std::string l = request->l();
            std::string e = request->e();
            std::string proof = request->proof();
            std::cout << "server: update(ServerContext *context, const UpdateRequestMessage *request, ExecuteStatus *response): "<< std::endl;
            int status = store(ss_db, l, e, proof);
            if (status != 0) {
                response->set_status(false);
                return Status::CANCELLED;
            }
            response->set_status(true);
            return Status::OK;
        }

        Status update2(ServerContext *context, const UpdateRequestMessage *request, ExecuteStatus *response) {
            std::string l = request->l();
            std::string e = request->e();
            std::string proof = request->proof();
            std::cout << "server: update2(ServerContext *context, const UpdateRequestMessage *request, ExecuteStatus *response): "<< std::endl;
            int status = store2(ss_db, l, e, proof);
            if (status != 0) {
                response->set_status(false);
                return Status::CANCELLED;
            }
            response->set_status(true);
            return Status::OK;
        }



        // batch_update()实现批量更新操作
        Status batch_update(ServerContext *context, ServerReader <UpdateRequestMessage> *reader, ExecuteStatus *response) {
            double start, end;
            std::string l;
            std::string e;
            std::string proof;
            std::cout << "server: batch_update(ServerContext *context, ServerReader<UpdateRequestMessage> *reader, ExecuteStatus *response)"<< std::endl;
            UpdateRequestMessage request;
            int i =0;
            while (reader->Read(&request)) {
                i++;
                l = request.l();
                e = request.e();
                proof = request.proof();
                store(ss_db, l, e, proof);
            }
            response->set_status(true);
            return Status::OK;
        }

    };

}// namespace FT_VDSSE

// static member must declare out of main function !!!
rocksdb::DB *FT_VDSSE::FT_VDSSEServiceImpl::ss_db;

void RunServer(std::string db_path) {
    std::string server_address("0.0.0.0:50051");
    FT_VDSSE::FT_VDSSEServiceImpl service(db_path);
    ServerBuilder builder;
     builder.SetMaxMessageSize(INT_MAX);
    builder.SetMaxReceiveMessageSize(INT_MAX);
    builder.SetMaxSendMessageSize(INT_MAX);
    //builder.SetMaxMessageSize(INT_MAX);
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr <Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

#endif // FT_VDSSE_SERVER_H
