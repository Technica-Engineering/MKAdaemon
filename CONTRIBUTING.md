# Contributions to MACsec Key Agreement (MKA) daemon
Contributions are always welcome. However we ask contributors to comply with a set of rules:

1. **Contribution License Agreement**  
Prior to any contribution, the contributor has to sign a [Contribution License Agreement](Technica-CLA.docx) document and send it to us macsec@technica-engineering.de .

2. **Unit testing**  
Merge requests breaking existing unit tests will not be accepted. Please run unit tests and make sure all pass.  
If a new feature is contributed, we ask contributors to add new tests or test cases to cover the new functionality, especially for code inside PAE module.

3. **Language**  
This software is implemented in C. Unit tests are implemented in C++.

4. **Coding rules: MISRA C 2012**  
Since part of the code is reused in embedded systems, we try to adhere to MISRA C 2012 rules using a static analysis tool called PC-Lint.  
We do not expect for contributors to have this tool available, but we would appreciate if MISRA rules are considered, and exceptions are documented.

5. **Doxygen**  
Although we are not generating Doxygen reports here at the moment, we do integrate this software in projects with Doxygen, and this is something we would like to do here in the future.  
For this reason please add documentation in doxygen format when possible, especially in header files exposing public functions.

6. **Memory management**  
Please avoid usage of dynamic memory inside src/pae code, in order to minimise issues integrating the code on small embedded systems.  
For the same reason, please be careful with large stack allocations and avoid them when possible (pay attention when >=512 bytes).

7. **Indentation / braces**  
Please try to follow K&R style regarding braces and indentation, using four spaces as indentation unit.

8. **Naming**  
8.1 Try to use short acronyms for the components to keep the names short when possible.  
8.2 Prepend public macros (#define's) with "MKA\_".  
8.3 Regarding public functions, please prepend them with "MKA\_" followed by the name of the component that implements it and followed by underscore (e.g.: MKA\_LOGON\_SetKayEnabled).  
8.4 Types in general are prepended with "t\_". Public types are prepended with "t\_MKA\_".  
8.5 Global variables dont' need to be prepended with anything, because they should not exist :). Please declare private variables only.  

9. **Structure**  
9.1 Please add doxygen-like headers in all code files.  
9.2 Please add C++ include guards in header files.  
9.3 Headers shall consist of the following areas in order: external includes, defines, type definitions, variable declarations, function prototypes, function definitions (static inline ONLY). See existing code for reference.  
9.4 C code shall consist of the following areas in order: external includes, defines, type definitions, variable declarations, function prototypes, function definitions. See existing code for reference.  
9.5 To ensure compatibility with embedded systems, inside pae/ please try to have a Init function to initialise the module and a MainFunction that is cyclically called.  

10. **Other**  
10.1 Please avoid native C types (int, char, short, long, etc.), and instead use types defined in <stdint.h>.  
10.2 Limit lines to 100 characters wide.  
10.3 Please try to achieve >90% unit test code coverage with PAE modules.  

