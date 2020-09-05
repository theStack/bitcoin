#include <pybind11/pybind11.h>
#include "../src/crypto/sha3.h"

namespace py = pybind11;

PYBIND11_MODULE(sha3_sipa, m) {
    py::class_<SHA3_256>(m, "SHA3_256")
        .def(py::init<>()) // empty constructor
        .def("Write", [](SHA3_256 &s, const py::bytes &b) {
            return s.Write(MakeUCharSpan(std::string(b)));
        })
        .def("Finalize", [](SHA3_256 &s) {
            unsigned char result[SHA3_256::OUTPUT_SIZE];
            s.Finalize(result);
            return py::bytes((const char*)result, SHA3_256::OUTPUT_SIZE);
        })
        .def("Reset", &SHA3_256::Reset);
}
