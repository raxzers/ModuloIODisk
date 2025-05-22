#include <iostream>
#include <fstream>
#include <vector>

std::vector<char> loadFileToMemory(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error al abrir el archivo." << std::endl;
        return {};
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Error al leer el archivo en memoria." << std::endl;
        return {};
    }
    
    return buffer;
}

int main() {
    std::string filename = "archivo.txt";
    
    std::vector<char> fileData = loadFileToMemory(filename);
    if (!fileData.empty()) {
        std::cout << "Archivo cargado en memoria. Contenido: " << std::string(fileData.begin(), fileData.end()) << std::endl;
    }
    std::cin.get();
    return 0;
}