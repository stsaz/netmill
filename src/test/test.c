/** netmill: tester
2023, Simon Zolin */

#include <netmill.h>
#include <ffsys/test.h>
#include <ffsys/globals.h>

struct ffos_test fftest;

int main()
{
	fflog("Test checks made: %u", fftest.checks_success);
	return 0;
}
