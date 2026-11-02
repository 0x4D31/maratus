#include <unistd.h>

static char *const arguments[] = {"display-name", "", "inert", 0};

int main(void) {
    return execv("/usr/bin/printf", arguments);
}
