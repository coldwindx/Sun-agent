// export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/zhulin/anaconda3/envs/torch/lib
// g++ -std=c++11 -W -o main main.cpp -I /home/zhulin/anaconda3/envs/torch/include/python3.8 -I /home/zhulin/anaconda3/envs/torch/lib/python3.8/site-packages/numpy/core/include -I./include -L /home/zhulin/anaconda3/envs/torch/lib -lpython3.8 -lpthread
#include <iostream>
#include "py/python.h"
using namespace std;
using namespace py;

int main()
{
    auto py = Python();
    py.run("import sys");
    // 相对于build文件夹的路径
    py.run("sys.path.append('./../')");
    try
    {
        Module mod("test1");
        Function func(mod, "add");
        cout << func.call<double>(1, 2.5) << endl;
    }
    catch (std::exception &e)
    {
        cout << e.what() << endl;
    }
}