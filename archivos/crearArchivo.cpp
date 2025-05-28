
#include <unistd.h>   // Para fsync
#include <fcntl.h>    // Para open
#include <sys/types.h>
#include <sys/stat.h>
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
    //file << "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque vulputate sodales justo, eu tristique quam. Suspendisse mattis vestibulum neque, quis laoreet mauris iaculis egestas. Fusce eu ipsum imperdiet elit dictum mattis nec id risus. Nullam posuere ligula ante, tempor pretium velit volutpat sit amet. Suspendisse quis purus lorem. Quisque sollicitudin arcu fermentum libero finibus condimentum. Proin ultricies erat vitae nunc commodo tempor. Nam viverra a justo vel facilisis.Fusce posuere dictum ligula. Quisque erat leo, auctor non quam in, finibus dictum nisl. Fusce facilisis tortor ac urna eleifend, quis varius augue lobortis. Praesent rhoncus sagittis libero eu tincidunt. Aenean sed cursus nisl, id fringilla felis. Curabitur lacinia semper massa, id dictum dui. Phasellus auctor elit suscipit mattis cursus. Sed quis felis pretium lectus tincidunt vulputate. Vivamus lorem leo, lobortis et sollicitudin quis, elementum in dui. Vestibulum facilisis orci venenatis, pharetra turpis eu, varius efficitur.";
    const char c = 'a';
    for (std::size_t i = 0; i < size; ++i) {
        file << c;  // Esto genera una syscall por buffer pequeño, más fácil de rastrear
    }
    file.flush();


    file.close();
    /*int fd = open(filename.c_str(), O_WRONLY);
    if (fd != -1) {
        fsync(fd);  // Fuerza escritura al disco
        close(fd);
    }*/

    
}

int main() {
    //std::cin.get();

    // Tamaños en bytes: 10 MB, 20 MB, 30 MB
    std::vector<std::pair<std::string, std::size_t>> archivos = {
        {"archivo_10MB.bin", 10 * 1024 * 1024}
    };

    for (const auto& [nombre, tam] : archivos) {
        createFileWithSize(nombre, tam);
    }

 
    return 0;
}

