# Assembly_debugger
I wrote some code to help me debug my assembly programs better than my register debugger code.
In the program, there is an example of incorrect usage of the SYS_SOCKET call, which should return error code 97. 
The error code is used as an index in an array of pointers to the error messages.
The length of the error message is calculated by the numerical value of the next address in the array minus the numerical value of the current error message address.
