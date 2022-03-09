#include <iostream>
#include <cstdio>
#include <cmath>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;
int main(){
    std::ofstream OsWrite1("traces_20.txt",std::ofstream::app);
    int p = 1000;
    int id = 0;
    vector<int> inds;
    int upds =0;
    int del =0;

    for (int i=0; i<1000000; i++){
        int r = rand()%p;
        if (r<=9){
            if (inds.size() >=1){
                upds++;
                OsWrite1<<upds << " "<< "search " <<0<<std::endl;
            }
        }else if (r >=10&&r<800){ 
            upds++;
            id++;
            inds.push_back(id);
            OsWrite1<<upds <<" "<< "add "<<id<<std::endl;
        }else if (r>=800&&r<=999){  
            if (inds.size() >=1){
                upds++;
                int loc = rand()%inds.size();
                del = inds.at(loc);
                inds.erase(inds.begin() + loc);
                OsWrite1<<upds <<" "<< "del "<<del<<std::endl;
            }                
        }
    }
    OsWrite1.close();

}