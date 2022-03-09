/* 
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 * 
 */
#include "FT_VDSSE.client.h"
#include "ae_mhash/mhash.h"
#include <utility>
#include <vector>
#include <stdio.h>
#include "aes/aes_ctr.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using FT_VDSSE::SearchRequestMessage;
using FT_VDSSE::UpdateRequestMessage;
using FT_VDSSE::ExecuteStatus;
using FT_VDSSE::RPC;

using FT_VDSSE::SearchRequestMessage;



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



void synthetic_updates(FT_VDSSE::Client &client, int n){
    int i, j;
    std::string keyword, ind;
    int id;

    UpdateRequestMessage request;
    ClientContext context;
    ExecuteStatus exec_status;
    std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
    std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));

    ae_ctx* ctx = ae_allocate(NULL);
    int c2;
    e_ctx* fctx = e_allocate(NULL);
    e_init(fctx, (unsigned char*)k_p, 16);
    std::string wc2; 
    ALIGN(16) const char* cwc2;
    ALIGN(16) char key[16];
    
    
    // generate 79/200 * n keywords, every keyword matches a document
    for (i=0; i < n*79/200; i++){
        keyword = "0keyword" + std::to_string(i);
        id = rand()%8999999;
        ind = std::to_string(1000000 + id);
        c2 = client.get_c2(keyword);
        wc2 = keyword + std::to_string(c2);
        cwc2 = wc2.c_str();
        fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
        ae_init(ctx, (unsigned char*)key, 16);
        request = client.gen_update_request(ctx, "1", keyword, ind);
        writer->Write(request);
    }
    // generate 1/2 * n keywords，every keyword macthes 10 documents
    for (i=0; i < n/2; i++){
        keyword = "1keyword" + std::to_string(i);
        c2 = client.get_c2(keyword);
        wc2 = keyword + std::to_string(c2);
        cwc2 = wc2.c_str();
        fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
        ae_init(ctx, (unsigned char*)key, 16);
        for (j=0; j<10; j++){
            id = rand()%8999999;
            ind = std::to_string(1000000 + id);
            request = client.gen_update_request(ctx, "1", keyword, ind);
            writer->Write(request);
        }
    }
    // generate 1/10 *n keywords， every keyword matches 100 docuemnts
    for (i=0; i < n/10; i++){
        keyword = "2keyword" + std::to_string(i);
        c2 = client.get_c2(keyword);
        wc2 = keyword + std::to_string(c2);
        cwc2 = wc2.c_str();
        fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
        ae_init(ctx, (unsigned char*)key, 16);
        for (j=0; j<100; j++){
            id = rand()%8999999;
            ind = std::to_string(1000000 + id);
            request = client.gen_update_request(ctx, "1", keyword, ind);
            writer->Write(request);
        }
    }
    // generate 1/200 *n keywords， every keyword macthes 1000 documents
    for (i=0; i < n/200; i++){
        keyword = "3keyword" + std::to_string(i);
        c2 = client.get_c2(keyword);
        wc2 = keyword + std::to_string(c2);
        cwc2 = wc2.c_str();
        fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
        ae_init(ctx, (unsigned char*)key, 16);
        for (j=0; j<1000; j++){
            id = rand()%8999999;
            ind = std::to_string(1000000 + id);
            request = client.gen_update_request(ctx, "1", keyword, ind);
            writer->Write(request);
        }
    }
    ae_clear(ctx);
    ae_free(ctx);
    e_clear(fctx);
    e_free(fctx);
    writer->WritesDone();
    Status status = writer->Finish();
}

void del(FT_VDSSE::Client &client, std::string file){
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
    std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
    std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));


    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    std::string keyword;
    std::string ind;
    std::string last = " ";
    ae_ctx* ctx = ae_allocate(NULL);
    int c2;
    e_ctx* fctx = e_allocate(NULL);
    e_init(fctx, (unsigned char*)k_p, 16);
    std::string wc2; 
    ALIGN(16) const char* cwc2;
    ALIGN(16) char key[16];

    while (fgets(s1, 100, fp)){
        sscanf(s1, "%s%d", s2, &id);
        count ++;
        keyword  = s2;
        ind = std::to_string(1000000 + id);
        ind = ind.substr(0, 7);
        if (last != keyword){
            c2 = client.get_c2(keyword);
            wc2 = keyword + std::to_string(c2);
            cwc2 = wc2.c_str();
            fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
            ae_init(ctx, (unsigned char*)key, 16);
        }
        request = client.gen_update_request(ctx, "0", keyword, ind);
        writer->Write(request);
        last = keyword;
    }
    ae_clear(ctx);
    ae_free(ctx);
    e_clear(fctx);
    e_free(fctx);
    fclose(fp);
    writer->WritesDone();
    Status status = writer->Finish();
}

int main(int argc, char **argv) {
    std::string cdb = std::string(argv[1]);
    int flag = atoi(argv[2]);
    
    std::string result;
    int searchresult;
   if (flag == 1) { //bacth updates 0<= document identifier <= 8999999 
        FT_VDSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()),
                           cdb);
        int n = atoi(argv[3]);
        std::string file = std::string(argv[4]);
        std::vector<std::pair<std::string, std::string>> index;
        readfile(file, n, index);
        //double start = FT_VDSSE::Util::getCurrentTime();
        client.updates(index);
        //double end = FT_VDSSE::Util::getCurrentTime();

    } else if (flag ==2) { // create the synthetic database
        FT_VDSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()),
                           cdb);
        int n = atoi(argv[3]);
        synthetic_updates(client, n); 
    } else if (flag == 3) { //search+ renew proof      
        grpc::ChannelArguments channel_args;
        channel_args.SetInt(GRPC_ARG_MAX_RECEIVE_MESSAGE_LENGTH, INT_MAX);
        FT_VDSSE::Client client(grpc::CreateCustomChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials(), channel_args),
                          cdb);
        std::string w = std::string(argv[3]);
    
        searchresult = client.search_renew(w);
        if (searchresult > 0){
            std::cout << "search done: " << std::endl;
        } else {
            std::cout << "search error: " << std::endl;
        }
    } else if (flag == 4) { // batch deletes
        FT_VDSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()),
                           cdb);
        std::string file = std::string(argv[3]);
        del(client, file);
    } else if (flag == 5){ //trace simulation
        std::ofstream OsWrite1("trace_time_20.txt",std::ofstream::app);
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
                 FT_VDSSE::Client client(grpc::CreateCustomChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials(), channel_args),
                                cdb);
                client.updatetest(keyword, updates);
                updates.clear();
                std::unordered_set <std::string> result;
                int c3, c4;
                std::string sw;
                double start = FT_VDSSE::Util::getCurrentTime();
                searchresult = client.search(keyword, result, c3, c4, sw); 
                double end = FT_VDSSE::Util::getCurrentTime();
                if (searchresult > 0){
                    OsWrite1<<upds << " "<<(end -start) *1000 <<std::endl;
                    std::cout << "search done: " << std::endl;
                    if(searchresult < c3){
                        client.renewproof(keyword, result, c4,sw);
                    }
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

