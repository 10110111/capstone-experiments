capst: Makefile capst.c
	gcc capst.c -o capst -g3 -lcapstone ${CFLAGS} ${LDFLAGS}
string-insns-test-gen: Makefile string-insns-test-gen.cpp
	g++ -Wall -Wextra -pedantic -std=c++0x string-insns-test-gen.cpp -o string-insns-test-gen -g3 -lcapstone ${CFLAGS} ${LDFLAGS}
tests: Makefile tests.cpp
	g++ -Wall -Wextra -pedantic -std=c++0x tests.cpp -o tests -g3 -lcapstone ${CFLAGS} ${LDFLAGS}
string-instructions: Makefile string-instructions.c
	gcc string-instructions.c -o string-instructions -g3 -lcapstone ${CFLAGS} ${LDFLAGS}
att-syntax-operands: Makefile att-syntax-operands.c
	gcc att-syntax-operands.c -o att-syntax-operands -g3 -lcapstone ${CFLAGS} ${LDFLAGS}
call-instructions: Makefile call-instructions.c
	gcc call-instructions.c -o call-instructions -g3 -lcapstone ${CFLAGS} ${LDFLAGS}

