#include "myfat.h"

char* cwdPath;
int fdCount;
FILE* disk_fp;
bpbFat32* bpb;
dirEnt* cwd_dir_entries;
fileDesc* file_descriptors;

//merge 2 string
char* merge_str(const char* a, const char* b) {
    char* result = (char*)malloc(strlen(a)+strlen(b));
    memcpy(result, a, strlen(a));
    strcat(result, b);
    return result;
}

//trim a string
std::string trim(const std::string& str)
{
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first)
    {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

//read a sector into buf
void read_sector(uint32_t sector_index, void* buf) {
    ssize_t bytes_read = pread(fileno(disk_fp), buf, bpb->bpb_bytesPerSec, sector_index*bpb->bpb_bytesPerSec);
    if (bytes_read < 0) {
        std::cerr << "cannot read sector!" << std::endl; 
    }
}

//read a cluster into buf
void read_cluster(uint32_t cluster_index, void* buf) {
    //compute sector index
    uint32_t RootDirSectors = ((bpb->bpb_rootEntCnt * 32) + (bpb->bpb_bytesPerSec - 1)) / bpb->bpb_bytesPerSec;
    uint32_t FATSz = bpb->bpb_FATSz32;
    uint32_t FirstDataSector = bpb->bpb_rsvdSecCnt + (bpb->bpb_numFATs*FATSz) + RootDirSectors;
    uint32_t FirstSectorofCluster = ((cluster_index-2)*bpb->bpb_secPerClus) + FirstDataSector;
    ssize_t bytes_read = pread(fileno(disk_fp), buf, bpb->bpb_secPerClus*bpb->bpb_bytesPerSec, FirstSectorofCluster*bpb->bpb_bytesPerSec);
    if (bytes_read < 0) {
        std::cerr << "cannot read cluster!" << std::endl; 
    }
}

//follow the chain to read all clusters of given entry
uint32_t read_FAT(uint32_t cluster_index) {
    //cluster_index: 32bytes
    //only consider FAT32
    //uint32_t FATSz = bpb->bpb_FATSz32;
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

bool legal_dir_name(std::string dir_name) {
    dir_name = trim(dir_name);
    //for cases of . and ..
    if (dir_name.compare(".") == 0 || dir_name.compare("..") == 0) {
        return true;
    }
    if (dir_name.size() == 0 || dir_name[0] == '.') {
        return false;
    }
    std::string::size_type dot_idx = dir_name.find('.');
    if (dot_idx == std::string::npos) {
        //no extension
        if (dir_name.size() > 8) {
            return false;
        }
    } else if (dot_idx > 8) {
        return false;
    } else if (dir_name.size() -1 - 8 > 3) {
        return false;
    }
    return true;
}

uint8_t* to_sys_name(std::string dir_name) {
    dir_name = trim(dir_name);
    //convert dirname into system array repr
    uint8_t* dir_name_sys = (uint8_t*)calloc(11, sizeof(uint8_t));
    for(size_t i = 0; i < 11; i++) {
        dir_name_sys[i] = 0x20;
    }
    std::string::size_type dot_idx = dir_name.find('.');
    if (dot_idx == std::string::npos || dir_name.compare(".") == 0 || dir_name.compare("..") == 0) {
        //no extension
        for(size_t j = 0; j < dir_name.size() ; j++) {
            dir_name_sys[j] = toupper(dir_name[j]);
        }
    } else {
        //has extension
        for(size_t j = 0; j < dot_idx ; j++) {
            dir_name_sys[j] = toupper(dir_name[j]);
        }
        //extension
        size_t idx = 8;
        for(size_t j = dot_idx+1 ; j < dir_name.size() ; j++) {
            dir_name_sys[idx++] = toupper(dir_name[j]);
        }
    }
    return dir_name_sys;
}

uint32_t extract_cluster_idx(dirEnt entry) {
    u_int32_t cluster_idx = 0;
    cluster_idx = cluster_idx | entry.dir_fstClusHI;
    cluster_idx = cluster_idx << 16;
    cluster_idx = cluster_idx | entry.dir_fstClusLO;
    return cluster_idx;
}

// read a cluster for directory entries
dirEnt* read_cluster_dir_entries(uint32_t cluster_idx, uint32_t* dir_count) {
    if (cluster_idx == 0) {
        cluster_idx = bpb->bpb_RootClus;
    }
    std::vector<void*> data = read_cluster_chain(cluster_idx);
    uint32_t dirent_per_cluster = (bpb->bpb_secPerClus*bpb->bpb_bytesPerSec) / sizeof(dirEnt);
    dirEnt* result = (dirEnt*)malloc(dirent_per_cluster*data.size()*sizeof(dirEnt));
    dirEnt* result_ptr = result;
    //copy data to dirEnt array
    for (unsigned int i=0;i<data.size();i++) {
        memcpy(result_ptr, data[i], sizeof(dirEnt)*dirent_per_cluster);
        result_ptr += dirent_per_cluster;
    }
    *dir_count = dirent_per_cluster*data.size();
    return result;
}

//mount file system
bool FAT_mount(const char *path) {
    disk_fp = fopen(path, "rb+");
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
    bpb = (bpbFat32*)buf;
    //initialize file descriptors
    fileDesc file_descriptors[FILE_DESCRIPTOR_LIMIT];
    for (int i=0;i<FILE_DESCRIPTOR_LIMIT;i++) {
        file_descriptors[i].used = false;
        file_descriptors[i].offset = 0;
        file_descriptors[i].cluster = 0;
    }
    //initialize fdCount
    fdCount = 0;
    //initialize cwdPath
    cwdPath = (char*)malloc(2*sizeof(char));
    strcpy(cwdPath, "/");
    cwd_dir_entries = OS_readDir(cwdPath);
    return true;
}

dirEnt* OS_readDir(const char *dirname) {
    std::string dirstr(dirname);
    dirstr = trim(dirstr);
    if (dirstr[0] == '/') {
        if (dirstr.length() == 1) {
            //read root directory
            uint32_t entry_count = 0;
            return read_cluster_dir_entries(bpb->bpb_RootClus, &entry_count);
        } else {
            //remove leading '/'
            dirstr = dirstr.substr(1, dirstr.length()-1);
        }
    } else {
        char* absolute_path;
        //reduce the relative path problem to absolute path problem
        if (strcmp(cwdPath, "/") == 0) {
            //cwd is root
            absolute_path = merge_str(cwdPath, dirname);
        } else {
            char* temp = merge_str(cwdPath, "/");
            absolute_path = merge_str(temp, dirname);
            free(temp);
        }
        return OS_readDir(absolute_path);
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
    uint32_t cur_entries_count;
    dirEnt* cur_entries;
    cur_entries_count = 0;
    cur_entries = read_cluster_dir_entries(bpb->bpb_RootClus, &cur_entries_count);
    for(unsigned int i = 0; i < dir_names.size(); i++) {
        if (!legal_dir_name(dir_names[i])) {
            //illegal name in path
            return NULL;
        }
        uint8_t* dir_name_sys = to_sys_name(dir_names[i]);
        //iterate through current dirEnt list to find the matching directory
        bool match = true;
        for(uint32_t j=0; j<cur_entries_count ; j++) {
            //check dir name
            if (cur_entries[j].dir_name[0] == 0xE5) {
                continue;
            } else if (cur_entries[j].dir_name[0] == 0x00) {
                break;
            } else if (cur_entries[j].dir_name[0] == 0x05) {
                //japanese case
                cur_entries[j].dir_name[0] = 0xE5;
            }
            //check directory
            if ((cur_entries[j].dir_attr & 0x10) == 0) {
                //not directory
                continue;
            }
            //name compare
            match = true;
            for(size_t k = 0;k<11 ; k++) {
                if (cur_entries[j].dir_name[k] != dir_name_sys[k]) {
                    match = false;
                    break;
                }
                if (cur_entries[j].dir_name[k] == 0) {
                    break;
                }
            }
            if (match) {
                uint32_t cluster_idx = extract_cluster_idx(cur_entries[j]);
                //debug
                //std::cout << unsigned(cluster_idx) <<std::endl;
                //read root directory
                cur_entries = read_cluster_dir_entries(cluster_idx, &cur_entries_count);
                break;
            }
        }
        //no match found
        if (!match) {
            return NULL;
        }
    }
    return cur_entries;
}

int FAT_cd(const char *path) {
    std::string pathstr(path);
    pathstr = trim(pathstr);
    dirEnt* new_entries;
    char* new_cwd_path;
    if (pathstr[0] == '/') {
        //absolute path
        new_cwd_path = (char*)malloc(strlen(path));
        strcpy(new_cwd_path, path);
        new_entries = OS_readDir(new_cwd_path);
        if (new_entries == NULL) {
            free(new_cwd_path);
            return -1;
        }
    } else {
        //relative path
        if (strcmp(cwdPath, "/") == 0) {
            new_cwd_path = merge_str(cwdPath, path);            
        } else {
            char* temp = merge_str(cwdPath, "/");
            new_cwd_path = merge_str(temp, path);
            free(temp);
        }
        new_entries = OS_readDir(new_cwd_path); 
        if (new_entries == NULL) {
            free(new_cwd_path);
            return -1;
        }
    }
    //cd success
    free(cwd_dir_entries);
    cwd_dir_entries = new_entries;
    free(cwdPath);
    cwdPath = new_cwd_path;
    return 1;
}

// debug helpers
void print_dir_entries(const char* path) {
    dirEnt* testEntries = OS_readDir(path);
    //print out one block of filenames
    int entry_count = bpb->bpb_bytesPerSec*bpb->bpb_secPerClus / sizeof(dirEnt);
    for(int i=0;i<entry_count;i++) {
        if (testEntries[i].dir_name[0] == 0) {
            break;
        }
        char output_str[12];
        memcpy(output_str, testEntries[i].dir_name, 11);
        output_str[11] = '\0';
        printf("%s\n", output_str);
    }
}

int main() {
    FAT_mount("sampledisk32.raw");
    //std::cout << "mounted" << std::endl;
    //debug
    FAT_cd("people");
    print_dir_entries(".");
    FAT_cd("..");
    FAT_cd("people");
    print_dir_entries("yyz5w");
}