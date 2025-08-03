#include <stdint.h>
#if defined(__i386__)

// For 32-bit x86
static __inline__ uint64_t rdtsc(void) {
    uint64_t x;
    __asm__ volatile ("rdtsc" : "=A" (x));
    return x;
}

#elif defined(__x86_64__)

// For 64-bit x86
static __inline__ uint64_t rdtsc(void) {
    uint32_t hi, lo;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}

#else
#error "RDTSC not supported on this architecture"
#endif

#include <Python.h>

// Python wrapper
static PyObject* py_cycles(PyObject *self, PyObject *args) {
    uint64_t cycles = rdtsc();
    return PyLong_FromUnsignedLongLong(cycles);
}

static PyMethodDef methods[] = {
    {"rdtsc", py_cycles, METH_NOARGS, "Return CPU cycle counter"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "cycles", NULL, -1, methods
};

PyMODINIT_FUNC PyInit_cycles(void) {
    return PyModule_Create(&module);
}
