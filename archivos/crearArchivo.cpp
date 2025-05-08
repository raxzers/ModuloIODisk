#include <iostream>
#include <fstream>
#include <vector>

void createFileWithSize(const std::string& filename, std::size_t size) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error al crear el archivo." << std::endl;
        return;
    }
    
    // Reservar espacio con caracteres nulos
    std::vector<char> buffer(size, '\0');
    file.write(buffer.data(), buffer.size());
    
    // Regresar al inicio para escribir contenido real
    file.seekp(0);
    file << "Este es un archivo preasignado.";
    
    file.close();
    std::cout << "Archivo creado con " << size << " bytes reservados." << std::endl;
}

int main() {
    std::string filename = "archivo.txt";
    std::size_t size = 1024; // Especifica el tamaño en bytes
    
    createFileWithSize(filename, size);
    
    return 0;
}
