/* 
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 * 
 */

#ifndef VDSSE_SERVER_H
#define VDSSE_SERVER_H
#include <grpc++/grpc++.h>
#include "VDSSE.grpc.pb.h"
#include "VDSSE.Util.h"
#include <unordered_set>

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

namespace VDSSE {
    class VDSSEServiceImpl final : public RPC::Service {
    private:
        static rocksdb::DB *ss_db;
    public:
        VDSSEServiceImpl(const std::string db_path) {
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
        static int store(rocksdb::DB *&db, const std::string l, const std::string e) {
            rocksdb::Status s;
            rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
            {
                s = db->Put(write_option, l, e);
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




        static void parse(std::string str, std::string &st, std::string &op, std::string &ind) {
            st = str.substr(0, 16);
            op = str.substr(16, 1);
            ind = str.substr(17, 7);
        }

        Status search(ServerContext *context, const SearchRequestMessage *request, ServerWriter <SearchReply> *writer) {
            std::cout << "server: search(ServerContext *context, const SearchRequestMessage *request, ServerWriter <SearchReply> *writer)"<< std::endl;
            //std::string kw = request->kw();
        
            std::string tw = request->tw();
            std::string st = request->st();
            int uc = request->uc();

            double start, end;
           
            std::unordered_set <std::string> result;
            std::unordered_set <std::string> del;
            std::unordered_set <std::string>::iterator it;
            std::string u, e;
             start = Util::getCurrentTime();
            for (int i = 0; i <uc; i++) {
                u = Util::H1(tw + st);
                bool found = get(ss_db, u, e);
                if (found) {
                    std::string value = Util::Xor(e, Util::H2(tw + st));
                    
                    std::string op, ind;
                    parse(value, st, op, ind);
                    if (op == "0"){
                        del.insert(ind);
                    } else {
                        if (del.empty()){
                            result.insert(ind);
                        } else {
                            it = del.find(ind);
                            if (it != del.end()) {
                                result.erase(ind);
                            } else {
                                result.insert(ind);
                            }
                        }
                        
                    }
                } else {
                    std::cout << "error: We were supposed to find something!" << std::endl;
                }
            }


           /* u = Util::H1(tw + st);
                bool found = get(ss_db, u, e);
                if (found) {
                    std::string value = Util::Xor(e, Util::H2(tw + st));
                    
                    std::string op, ind;
                    parse(value, st, op, ind);
                    if (op == "0"){
                        del.insert(ind);
                    } else {
                        if (del.empty()){
                            result.insert(ind);
                        } else {
                            it = del.find(ind);
                            if (it != del.end()) {
                                result.erase(ind);
                            } else {
                                result.insert(ind);
                            }
                        }
                        
                    }
                } else {
                    std::cout << "error: We were supposed to find something!" << std::endl;
                }*/

            SearchReply reply;

            for (std::unordered_set<std::string>::iterator i = result.begin(); i != result.end(); i++) {
                reply.set_ind(*i);
                writer->Write(reply);
            }
            return Status::OK;
        }

        Status update(ServerContext *context, const UpdateRequestMessage *request, ExecuteStatus *response) {
            std::string l = request->l();
            std::string e = request->e();
            std::cout << "server: update(ServerContext *context, const UpdateRequestMessage *request, ExecuteStatus *response): "<< std::endl;
            int status = store(ss_db, l, e);
            if (status != 0) {
                response->set_status(false);
                return Status::CANCELLED;
            }
            response->set_status(true);
            return Status::OK;
        }


        Status batch_update(ServerContext *context, ServerReader <UpdateRequestMessage> *reader, ExecuteStatus *response) {
            std::string l;
            std::string e;
            std::cout << "server: batch_update(ServerContext *context, ServerReader<UpdateRequestMessage> *reader, ExecuteStatus *response)"<< std::endl;
            UpdateRequestMessage request;
            while (reader->Read(&request)) {
                l = request.l();
                e = request.e();
                store(ss_db, l, e);
            }
            response->set_status(true);
            return Status::OK;
        }

    };

}// namespace VDSSE

// static member must declare out of main function !!!
rocksdb::DB *VDSSE::VDSSEServiceImpl::ss_db;


void RunServer(std::string db_path) {
    std::string server_address("0.0.0.0:50051");
    VDSSE::VDSSEServiceImpl service(db_path);
    ServerBuilder builder;
    builder.SetMaxMessageSize(INT_MAX);
    builder.SetMaxReceiveMessageSize(INT_MAX);
    builder.SetMaxSendMessageSize(INT_MAX);
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr <Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

#endif // VDSSE_SERVER_H
