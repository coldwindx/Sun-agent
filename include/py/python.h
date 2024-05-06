#pragma once

#include <Python.h>
#include <string>

namespace py
{
    class Module;
    class Function;
    class Class;
    class Object;

    class Python
    {
    private:
    public:
        Python()
        {
            Py_Initialize();
            if (!Py_IsInitialized())
                throw std::runtime_error("Python init failed!");
        }
        ~Python()
        {
            Py_Finalize();
        }
        void run(const std::string &cmdline)
        {
            PyRun_SimpleString(cmdline.c_str());
        }
    };

    class Argument
    {
        friend class Object;
        friend class Function;

    public:
        Argument() : m_args(nullptr), m_num(0), m_pos(0) {}
        ~Argument() = default;

        template <typename... Args>
        void bind(Args... args)
        {
            m_num = sizeof...(args);
            m_pos = 0;
            m_args = PyTuple_New(m_num);
            bind_inner(args...);
        }

        template <typename R>
        R parse(PyObject *ret)
        {
            R ans;
            std::string flag = data_flag<R>();
            PyArg_Parse(ret, flag.c_str(), &ans);
            return ans;
        }

    protected:
        void bind_inner() {}
        template <typename T, typename... Args>
        void bind_inner(T arg, Args... args)
        {
            std::string flag = data_flag<T>();
            PyObject *value = Py_BuildValue(flag.c_str(), arg);
            PyTuple_SetItem(m_args, m_pos++, value);
            bind_inner(args...);
        }

        template <typename T>
        static std::string data_flag()
        {
            if (typeid(T) == typeid(bool))
                return "b";
            if (typeid(T) == typeid(int))
                return "i";
            if (typeid(T) == typeid(unsigned int))
                return "I";
            if (typeid(T) == typeid(float))
                return "f";
            if (typeid(T) == typeid(double))
                return "d";
            if (typeid(T) == typeid(const char *))
                return "s";
            return "";
        }

    private:
        int m_num, m_pos;
        PyObject *m_args;
    };

    class Module
    {
        friend class Class;
        friend class Function;

    public:
        Module(const std::string &name)
        {
            this->m_module = PyImport_ImportModule(name.c_str());
            if (m_module == nullptr)
                throw std::runtime_error("Module not found: " + name);
        }

        void import(const std::string &name)
        {
            this->m_module = PyImport_ImportModule(name.c_str());
            if (m_module == nullptr)
                throw std::runtime_error("Module not found: " + name);
        }

    private:
        PyObject *m_module = nullptr;
    };

    class Object
    {
        friend class Function;

    public:
        Object() = default;
        Object(const Class &cls)
        {
        }
        template <typename... Args>
        Object(const Class &cls, Args... args)
        {
        }

    private:
        PyObject *m_obj;
    };

    class Class
    {
        friend class Object;

    public:
        Class() = default;
        Class(const Module &module, const std::string &name)
        {
            m_class = PyObject_GetAttrString(module.m_module, name.c_str());
            if (!m_class)
                std::runtime_error("Class not found: " + name);
        }
        ~Class() = default;

    private:
        PyObject *m_class;
    };

    class Function
    {
    public:
        Function() = default;
        Function(const Module &module, const std::string &name)
        {
            m_func = PyObject_GetAttrString(module.m_module, name.c_str());
            if (!m_func || !PyCallable_Check(m_func))
                throw std::runtime_error("Function not found: " + name);
        }
        Function(const Object &obj, const std::string &name)
        {
            m_func = PyObject_GetAttrString(obj.m_obj, name.c_str());
            if (!m_func || !PyCallable_Check(m_func))
                throw std::runtime_error("Function not found: " + name);
        }
        ~Function() = default;

        void call()
        {
            PyObject_CallObject(m_func, nullptr);
        }
        template <typename R>
        R call()
        {
            auto arg = Argument();
            PyObject *ans = PyObject_CallObject(m_func, arg.m_args);
            return arg.parse<R>(ans);
        }
        template <typename R, typename... Args>
        R call(Args... args)
        {
            auto arg = Argument();
            arg.bind(args...);
            PyObject *ans = PyObject_CallObject(m_func, arg.m_args);
            return arg.parse<R>(ans);
        }

    private:
        PyObject *m_func = nullptr;
    };
}
