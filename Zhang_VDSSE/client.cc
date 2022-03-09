#include "VDSSE.client.h"
#include "ae_mhash/mhash.h"
#include <cstdlib>
#include <cmath>
#include <utility>
#include <vector>
#include <stdio.h>
#include "aes/aes_ctr.h"

using VDSSE::SearchRequestMessage;
using VDSSE::UpdateRequestMessage;
using VDSSE::ExecuteStatus;
using VDSSE::RPC;
using VDSSE::SearchReply;

using VDSSE::SearchRequestMessage;

void readfile(std::string file, int number, std::vector<std::pair<std::string, std::string>>& index){
    FILE *fp;
	fp = fopen(file.c_str(), "r");
   	if(fp == NULL) {
      perror("open file error");
   	}
    char s1[100];
    char s2[100];
    int id;
    int count = 0;
    std::string keyword, ind;
    while (fgets(s1, 100, fp)){
        count ++;
        if (count > number && number != 0){
            break;
        }
        sscanf(s1, "%s%d", s2, &id);
        keyword  = s2;
        ind = std::to_string(1000000 + id);
        ind = ind.substr(0, 7);
        std::pair<std::string, std::string> p(keyword, ind); 
        index.push_back(p);
    }
    fclose(fp);
    return;
}



void synthetic_updates(VDSSE::Client &client, int n){
    int i, j;
    std::string keyword, ind;
    int id;

    UpdateRequestMessage request;
    ClientContext context;
    ExecuteStatus exec_status;
    std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials())));
    std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));

    mhash_ctx* m_ctx = mhash_allocate(NULL);
    e_ctx* fctx = e_allocate(NULL);
    e_init(fctx, (unsigned char*)k_r, 16);
    ALIGN(16) const char* cw;
    ALIGN(16) char key[16]; 
    
    for (i=0; i < n*79/200; i++){
        keyword = "0keyword" + std::to_string(i);
        id = rand()%899999;
        ind = std::to_string(1000000 + id);
        cw = keyword.c_str();
        fencrypt1(fctx, iv_r, cw, keyword.length(), key);
        mhash_init(m_ctx, key, 16);
        request = client.gen_update_request(m_ctx, "1", keyword, ind);
        writer->Write(request);
    }

    for (i=0; i < n/2; i++){
        keyword = "1keyword" + std::to_string(i);
        cw = keyword.c_str();
        fencrypt1(fctx, iv_r, cw, keyword.length(), key);
        mhash_init(m_ctx, key, 16);
        for (j=0; j<10; j++){
            id = rand()%8999999;
            ind = std::to_string(1000000 + id);
            request = client.gen_update_request(m_ctx, "1", keyword, ind);
            writer->Write(request);
        }
    }
    // 1/10 *n个关键字，每个关键字对应100个文档
    for (i=0; i < n/10; i++){
        keyword = "2keyword" + std::to_string(i);
        cw = keyword.c_str();
        fencrypt1(fctx, iv_r, cw, keyword.length(), key);
        mhash_init(m_ctx, key, 16);
        for (j=0; j<100; j++){
            id = rand()%8999999;
            ind = std::to_string(1000000 + id);
            request = client.gen_update_request(m_ctx, "1", keyword, ind);
            writer->Write(request);
        }
    }
    // 1/200 *n个关键字，每个关键字对应100个文档
    for (i=0; i < n/200; i++){
        keyword = "3keyword" + std::to_string(i);
        //rw = client.gen_enc_token2(keyword, k_r);
        //key = rw.c_str();
         cw = keyword.c_str();
        fencrypt1(fctx, iv_r, cw, keyword.length(), key);
        mhash_init(m_ctx, key, 16);
        for (j=0; j<1000; j++){
            id = rand()%8999999;
            ind = std::to_string(1000000 + id);
            request = client.gen_update_request(m_ctx, "1", keyword, ind);
            writer->Write(request);
        }
    }
    mhash_clear(m_ctx);
    mhash_free(m_ctx);
    writer->WritesDone();
    Status status = writer->Finish();
}

void del(VDSSE::Client &client, std::string file){
    FILE *fp;
	fp = fopen(file.c_str(), "r");
   	if(fp == NULL) {
      perror("open file error");
   	}
    char s1[100];
    char s2[100];
    int id;
    int count = 0;

    UpdateRequestMessage request;
    ClientContext context;
    ExecuteStatus exec_status;
    std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials())));
    std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));

    std::string keyword;
    std::string ind;
    std::string last = " ";
    mhash_ctx* m_ctx = mhash_allocate(NULL);
    e_ctx* fctx = e_allocate(NULL);
    e_init(fctx, (unsigned char*)k_r, 16);
    ALIGN(16) const char* cw;
    ALIGN(16) char key[16]; 

    while (fgets(s1, 100, fp)){
        sscanf(s1, "%s%d", s2, &id);
        count ++;
        keyword  = s2;
        ind = std::to_string(1000000 + id);
        ind = ind.substr(0, 7);
        if (last != keyword){
            cw = keyword.c_str();
            fencrypt1(fctx, iv_r, cw, keyword.length(), key);
            mhash_init(m_ctx, key, 16);
        }
        request = client.gen_update_request(m_ctx, "0", keyword, ind);
        writer->Write(request);
        last = keyword;
    }
    mhash_clear(m_ctx);
    mhash_free(m_ctx);
    fclose(fp);
    writer->WritesDone();
    Status status = writer->Finish();
}

int main(int argc, char **argv) {
    std::string cdb = std::string(argv[1]);
    int flag = atoi(argv[2]);
    
    std::string result;
    int searchresult;
    if (flag == 1) {
        VDSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()),
                           cdb);
        int n = atoi(argv[3]);
        std::string file = std::string(argv[4]);                  
        std::vector<std::pair<std::string, std::string>> index;
        readfile(file, n, index);
        //double start = VDSSE::Util::getCurrentTime();
        client.updates(index);
        //double end = VDSSE::Util::getCurrentTime();
    }  else if (flag ==2) {
        VDSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()),
                           cdb);
        int n = atoi(argv[3]);
        synthetic_updates(client, n);
    }  else if (flag == 3) {
        grpc::ChannelArguments channel_args;
        channel_args.SetInt(GRPC_ARG_MAX_RECEIVE_MESSAGE_LENGTH, INT_MAX);
       
        VDSSE::Client client(grpc::CreateCustomChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials(), channel_args),
                          cdb);
        std::string w = std::string(argv[3]);
        searchresult = client.search(w);
        if (searchresult > 0){
            std::cout << "search done: " << std::endl;
        } else {
            std::cout << "search error: " << std::endl;
        }
    } else if (flag == 4) {
        VDSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()),
                           cdb);
        std::string file = std::string(argv[3]);
        del(client, file);
    } else if (flag ==9){
        std::ofstream OsWrite1("zhang_trace_time_20.txt",std::ofstream::app);
        FILE *fp;
        std::string file = "traces_20.txt";
	    fp = fopen(file.c_str(), "r");
   	    if(fp == NULL) {
            perror("open file error");
   	    }
        char s1[100];
        char s2[100];
        int id;
        int upds;
        std::string keyword = "pray22";
        std::vector<std::pair<std::string, std::string>> updates;
        std::string function, op, ind;
        while (fgets(s1, 100, fp)){
            sscanf(s1, "%d %s %d", &upds, s2, &id);
            function  = s2;
            if (function == "add"){
                op = "1";
                ind = std::to_string(1000000 + id);
                std::pair<std::string, std::string> p(op, ind);
                updates.push_back(p); 
            } else if (function == "del"){
                op = "0";
                ind = std::to_string(1000000 + id);
                std::pair<std::string, std::string> p(op, ind);
                updates.push_back(p); 
            } else if (function == "search"){
                grpc::ChannelArguments channel_args;
                    channel_args.SetInt(GRPC_ARG_MAX_RECEIVE_MESSAGE_LENGTH, INT_MAX);
                 VDSSE::Client client(grpc::CreateCustomChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials(), channel_args),
                                cdb);
                client.updatetest(keyword, updates);
                updates.clear();
                double start = VDSSE::Util::getCurrentTime();
                searchresult = client.search(keyword);
                double end = VDSSE::Util::getCurrentTime();
                if (searchresult > 0){
                    OsWrite1<<upds << " "<<(end -start) *1000 <<std::endl;
                    std::cout << "search done: " << std::endl;
                } else {
                    std::cout << "search error: " << std::endl;
                }
            }
        }
        fclose(fp);
        OsWrite1.close();
    } else {
        std::cout << "input error." << std::endl;
    }
    return 0;
}


