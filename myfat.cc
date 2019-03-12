#include "myfat.h"
#include <unistd.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include <iostream>

//mount file system
bool FAT_mount(const char *path) {
    FILE *disk_fp = fopen(path, "rb+");
    if ( disk_fp == NULL ) {
        std::cerr << "cannot open disk image!" << std::endl;
        return false;
    }
    //load bpb
    size_t bpb_size = sizeof(bpbFat32);
    void* buf = malloc(bpb_size);
    size_t ret_code = fread(buf, bpb_size, 1, disk_fp);
    if ( ret_code != 1 ) {
        std::cerr << "cannot read bpb!" << std::endl; 
    }
    bpbFat32* bpb = (bpbFat32*)buf;
    //initialize file descriptors
    fileDesc file_descriptors[FILE_DESCRIPTOR_LIMIT];
    for (int i=0;i<FILE_DESCRIPTOR_LIMIT;i++) {
        file_descriptors[i].used = false;
        file_descriptors[i].offset = 0;
        file_descriptors[i].cluster = 0;
    }
    //initialize fdCount
    int fdCount = 0;
    //initialize cwdPath
    char* cwdPath = "/";
    //initialize global varibles
    uint32_t CLUSTER_SIZE = bpb->bpb_secPerClus * bpb->bpb_bytesPerSec;
    return true;
}

//read a sector into buf
void read_sector(uint32_t sector_index, void* buf) {
    ssize_t bytes_read = pread(fileno(disk_fp), buf, bpb->bpb_bytesPerSec, sector_index*bpb->bpb_bytesPerSec);
}

//read a cluster into buf
void read_cluster(uint32_t cluster_index, void* buf) {
    //compute sector index
    uint32_t RootDirSectors = ((bpb->bpb_rootEntCnt * 32) + (bpb->bpb_bytesPerSec - 1)) / bpb->bpb_bytesPerSec;
    uint32_t FATSz = bpb->bpb_FATSz32;
    uint32_t FirstDataSector = bpb->bpb_rsvdSecCnt + (bpb->bpb_numFATs*FATSz) + RootDirSectors;
    uint32_t FirstSectorofCluster = ((cluster_index-2)*bpb->bpb_secPerClus) + FirstDataSector;
    ssize_t bytes_read = pread(fileno(disk_fp), buf, bpb->bpb_secPerClus*bpb->bpb_bytesPerSec, FirstDataSector*bpb->bpb_bytesPerSec);
}

//follow FAT cluster chain to read a vector of clusters
std::vector<void*> read_cluster_chain(uint32_t cluster_index) {
    std::vector<void*> result;
    void* data = malloc(bpb->bpb_bytesPerSec*bpb->bpb_secPerClus);
    read_cluster(cluster_index, data);
    result.push_back(data);
    uint32_t fat_entry = read_FAT(cluster_index);
    while (fat_entry < 0x0FFFFFF8) {
        //fat_entry not eof
        cluster_index = fat_entry;
        data = malloc(bpb->bpb_bytesPerSec*bpb->bpb_secPerClus);
        read_cluster(cluster_index, data);
        result.push_back(data);
        fat_entry = read_FAT(cluster_index);
    }
    return result;
}

//follow the chain to read all clusters of given entry
uint32_t read_FAT(uint32_t cluster_index) {
    //cluster_index: 32bytes
    //only consider FAT32
    uint32_t FATSz = bpb->bpb_FATSz32;
    uint32_t FATOffset = cluster_index*4;
    uint32_t ThisFATSecNum = bpb->bpb_rsvdSecCnt + (FATOffset / bpb->bpb_bytesPerSec);
    uint32_t ThisFATEntOffset = FATOffset % bpb->bpb_bytesPerSec;
    char* buf = (char*)malloc(bpb->bpb_bytesPerSec);
    read_sector(ThisFATSecNum, buf);
    //read entry from sector
    uint32_t entry;
    memcpy(&entry, buf+ThisFATEntOffset, sizeof(uint32_t));
    //first 4 bit unused
    entry = entry & 0x0fffffff;
    free(buf);
    return entry;
}

dirEnt* OS_readDir(const char *dirname) {
    std::string dirstr(dirname);
    uint32_t dir_count = 0;
    bool absolute = false;
    if (dirstr[0] == '/') {
        absolute = true;
        if (dirstr.length() == 1) {
            //read root directory
            std::vector<void*> data = read_cluster_chain(bpb->bpb_RootClus);
            uint32_t dirent_per_cluster = (bpb->bpb_secPerClus*bpb->bpb_bytesPerSec) / sizeof(dirEnt);
            dirEnt* result = (dirEnt*)malloc(dirent_per_cluster*data.size()*sizeof(dirEnt));
            dirEnt* result_ptr = result;
            //copy data to dirEnt array
            for (int i=0;i<data.size();i++) {
                memcpy(result_ptr, data[i], sizeof(dirEnt)*dirent_per_cluster);
                result_ptr += dirent_per_cluster;
            }
            return result;
        } else {
            //remove leading '/'
            dirstr = dirstr.substr(1, dirstr.length()-1);
        }
    }
    //break dirstr into dirname tokens
    std::vector<std::string> dir_names;
    std::string::size_type i = 0;
    std::string::size_type j = dirstr.find('/');
    while (j!=std::string::npos) {
        dir_names.push_back(dirstr.substr(i,j-i));
        i = ++j;
        j = dirstr.find('/', j);
    }
    if (j==std::string::npos && i < dirstr.length()) {
        dir_names.push_back(dirstr.substr(i, dirstr.length()));
    }
    if (absolute) {
        //absolute path
    } else {
        //relative path
    }
}

int main() {
    FAT_mount("sampledisk32.raw");
}