#include <iostream>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <openssl/evp.h>

namespace fs = std::filesystem;

std::string calculate_md5(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << filepath << std::endl;
        return "";
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Error initializing MD5 context." << std::endl;
        return "";
    }

    const EVP_MD* md = EVP_md5();
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        std::cerr << "Error initializing MD5 digest." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            std::cerr << "Error updating MD5 digest." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return "";
        }
    }
    if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
        std::cerr << "Error updating MD5 digest." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;
    if (EVP_DigestFinal_ex(mdctx, result, &result_len) != 1) {
        std::cerr << "Error finalizing MD5 digest." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    EVP_MD_CTX_free(mdctx);

    char md5string[33];
    for (unsigned int i = 0; i < result_len; ++i) {
        sprintf(&md5string[i * 2], "%02x", result[i]);
    }

    return std::string(md5string);
}

void find_duplicates(const std::string& directory) {
    std::unordered_map<std::string, std::vector<std::string>> hash_map;

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            std::string filepath = entry.path().string();
            std::string file_hash = calculate_md5(filepath);

            if (!file_hash.empty()) {
                hash_map[file_hash].push_back(filepath);
            }
        }
    }

    bool duplicates_found = false;

    for (const auto& [hash, files] : hash_map) {
        if (files.size() > 1) {
            duplicates_found = true;
            std::cout << "Duplicate files found (MD5: " << hash << "):\n";
            for (size_t i = 0; i < files.size(); ++i) {
                std::cout << "  " << i + 1 << ". " << files[i] << std::endl;
            }

            std::cout << "Do you want to delete all except the first file? (y/n): ";
            char choice;
            std::cin >> choice;

            if (choice == 'y' || choice == 'Y') {
                for (size_t i = 1; i < files.size(); ++i) {
                    try {
                        fs::remove(files[i]);
                        std::cout << "Deleted: " << files[i] << std::endl;
                    } catch (const fs::filesystem_error& e) {
                        std::cerr << "Error deleting file: " << files[i] << " (" << e.what() << ")" << std::endl;
                    }
                }
            }
        }
    }

    if (!duplicates_found) {
        std::cout << "No duplicate files found in " << fs::relative(directory).string() << "!" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <directory>" << std::endl;
        return 1;
    }

    std::string directory = argv[1];
    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        std::cerr << "Error: The specified path is not a valid directory." << std::endl;
        return 1;
    }

    find_duplicates(directory);
    return 0;
}
