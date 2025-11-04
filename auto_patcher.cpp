#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <direct.h>
#include <windows.h>
#include <ShlObj.h>

#pragma pack(push, 1)
struct DOS_HEADER { uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc; uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss; uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc; uint16_t e_ovno; uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo; uint16_t e_res2[10]; int32_t e_lfanew; };
struct PE_HEADER { uint32_t Signature; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; };
struct OPTIONAL_HEADER64 { uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion; uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData; uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion; uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion; uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion; uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue; uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics; uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit; uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit; uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes; };
struct SECTION_HEADER { char Name[8]; uint32_t VirtualSize; uint32_t VirtualAddress; uint32_t SizeOfRawData; uint32_t PointerToRawData; uint32_t PointerToRelocations; uint32_t PointerToLinenumbers; uint16_t NumberOfRelocations; uint16_t NumberOfLinenumbers; uint32_t Characteristics; };
#pragma pack(pop)

std::string GetDownloadsPath() {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path) == S_OK) {
        std::string user = path;
        return user + "\\Downloads\\Valex_External\\Valex_External.exe";
    }
    return "";
}

int main() {
    system("cls");
    std::cout << "========================================\n";
    std::cout << "     VALEX EXTERNAL AUTO PATCHER v2     \n";
    std::cout << "========================================\n\n";

    // 1. Find Valex_External.exe
    std::string exe_path = GetDownloadsPath();
    if (exe_path.empty() || !std::ifstream(exe_path)) {
        std::cout << "ERROR: Valex_External.exe not found!\n\n";
        std::cout << "Put it in:\n";
        std::cout << "C:\\Users\\YourName\\Downloads\\Valex_External\\\n\n";
        system("pause");
        return 1;
    }

    std::string folder = exe_path.substr(0, exe_path.find_last_of("\\"));
    std::string output = folder + "\\patched_Valex_External.exe";

    std::cout << "Found: " << exe_path << "\n\n";
    std::cout << "Patching... Please wait...\n\n";

    // Load file
    std::ifstream in(exe_path, std::ios::binary);
    in.seekg(0, std::ios::end);
    size_t size = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> buf(size);
    in.read((char*)buf.data(), size);
    in.close();

    // Parse PE
    auto* dos = (DOS_HEADER*)buf.data();
    if (dos->e_magic != 0x5A4D) { std::cout << "Not MZ\n"; system("pause"); return 1; }
    auto* pe = (PE_HEADER*)(buf.data() + dos->e_lfanew);
    if (pe->Signature != 0x4550) { std::cout << "Not PE\n"; system("pause"); return 1; }
    auto* opt = (OPTIONAL_HEADER64*)((uint8_t*)pe + sizeof(PE_HEADER));
    if (opt->Magic != 0x20B) { std::cout << "Not x64\n"; system("pause"); return 1; }
    uint64_t image_base = opt->ImageBase;
    auto* sections = (SECTION_HEADER*)((uint8_t*)opt + pe->SizeOfOptionalHeader);

    // Strings
    std::string failed_str = "Authentication failed";
    std::string success_str = "Authentication successful.";
    std::vector<size_t> failed_pos, success_pos;
    for (size_t i = 0; i <= size - failed_str.size(); ++i)
        if (memcmp(&buf[i], failed_str.c_str(), failed_str.size()) == 0) failed_pos.push_back(i);
    for (size_t i = 0; i <= size - success_str.size(); ++i)
        if (memcmp(&buf[i], success_str.c_str(), success_str.size()) == 0) success_pos.push_back(i);

    if (failed_pos.empty() || success_pos.empty()) {
        std::cout << "Auth strings not found!\n"; system("pause"); return 1;
    }

    auto file_to_va = [&](size_t off) -> uint64_t {
        for (int s = 0; s < pe->NumberOfSections; ++s) {
            auto& sec = sections[s];
            if (off >= sec.PointerToRawData && off < sec.PointerToRawData + sec.SizeOfRawData)
                return image_base + sec.VirtualAddress + (off - sec.PointerToRawData);
        }
        return 0;
        };

    uint64_t failed_lea_va = 0, success_lea_va = 0, jne_va = 0;
    int32_t jne_rel = 0;

    // Find LEAs
    for (int s = 0; s < pe->NumberOfSections; ++s) {
        auto& sec = sections[s];
        if (!(sec.Characteristics & 0x20000000)) continue;
        size_t start = sec.PointerToRawData;
        size_t end = start + sec.SizeOfRawData;
        uint32_t rva_base = sec.VirtualAddress;

        for (size_t i = start; i + 7 < end; ++i) {
            if (buf[i] == 0x48 && buf[i + 1] == 0x8D && buf[i + 2] == 0x05) {
                int32_t rel = *(int32_t*)&buf[i + 3];
                uint64_t instr_va = image_base + rva_base + (i - start);
                uint64_t target = instr_va + 7 + rel;
                for (auto pos : failed_pos) if (file_to_va(pos) == target) failed_lea_va = instr_va;
                for (auto pos : success_pos) if (file_to_va(pos) == target) success_lea_va = instr_va;
            }
        }
    }

    if (failed_lea_va == 0 || success_lea_va == 0) {
        std::cout << "LEA not found!\n"; system("pause"); return 1;
    }

    // Find jne near success LEA
    for (int s = 0; s < pe->NumberOfSections; ++s) {
        auto& sec = sections[s];
        if (!(sec.Characteristics & 0x20000000)) continue;
        size_t start = sec.PointerToRawData;
        size_t end = start + sec.SizeOfRawData;
        uint32_t rva_base = sec.VirtualAddress;

        for (size_t i = start; i + 6 < end; ++i) {
            if (buf[i] == 0x84 && buf[i + 1] == 0xC0 && buf[i + 2] == 0x0F && buf[i + 3] == 0x85) {
                int32_t rel = *(int32_t*)&buf[i + 4];
                uint64_t instr_va = image_base + rva_base + (i - start);
                uint64_t target = instr_va + 6 + rel;
                if (target >= success_lea_va - 8 && target <= success_lea_va + 8) {
                    jne_va = instr_va;
                    jne_rel = rel;
                    break;
                }
            }
        }
        if (jne_va) break;
    }

    if (jne_va == 0) {
        std::cout << "Auth check not found!\n"; system("pause"); return 1;
    }

    // Patch
    auto patch = [&](uint64_t va, auto func) {
        size_t rva = va - image_base;
        for (int s = 0; s < pe->NumberOfSections; ++s) {
            auto& sec = sections[s];
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.SizeOfRawData) {
                size_t off = sec.PointerToRawData + (rva - sec.VirtualAddress);
                func(off);
                return;
            }
        }
        };

    patch(failed_lea_va, [&](size_t off) {
        int64_t rel = file_to_va(success_pos[0]) - (failed_lea_va + 7);
        *(int32_t*)&buf[off + 3] = (int32_t)rel;
        });

    patch(jne_va, [&](size_t off) {
        buf[off + 2] = 0xE9;
        *(int32_t*)&buf[off + 3] = jne_rel + 1;
        });

    // Save
    std::ofstream out(output, std::ios::binary);
    out.write((char*)buf.data(), size);
    out.close();

    // SUCCESS
    system("cls");
    std::cout << "========================================\n";
    std::cout << "           PATCH SUCCESSFUL!           \n";
    std::cout << "========================================\n\n";
    std::cout << "No key needed!\n";
    std::cout << "Output: patched_Valex_External.exe\n\n";
    std::cout << "Launching in 3 seconds...\n\n";

    Sleep(3000);
    ShellExecuteA(NULL, "open", output.c_str(), NULL, NULL, SW_SHOW);

    return 0;
}
