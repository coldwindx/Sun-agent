#pragma once
#include <fstream>

class Saver
{
    std::ofstream out;

public:
    Saver(const std::string &filename) : out(filename, std::ios::out | std::ios::app) {}
    void write(const std::string &s)
    {
        // out << s;
    }
    ~Saver()
    {
        out.close();
    }
};
