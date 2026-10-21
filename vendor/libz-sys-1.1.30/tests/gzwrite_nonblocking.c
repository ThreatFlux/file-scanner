/* Local regression for upstream zlib commit df84af25 (CVE-2026-85091).
 * A full nonblocking pipe makes a direct gzwrite stall while input remains.
 * The next, smaller write must use the owned buffer, not the previous caller's.
 */
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include "gzguts.h"

int main(void) {
    int fds[2];
    unsigned char fill[4096] = {0};
    unsigned char user_input[32] = {0};
    assert(pipe(fds) == 0);
    assert(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
    while (write(fds[1], fill, sizeof(fill)) > 0) {}
    /* Exhaust any residual space smaller than the chunk above. */
    while (write(fds[1], fill, 1) > 0) {}
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    gzFile file = gzdopen(fds[1], "wbT");
    assert(file != NULL);
    assert(gzbuffer(file, 16) == 0);
    assert(gzwrite(file, user_input, sizeof(user_input)) == 0);
    gz_statep state = (gz_statep)file;
    assert(state->again);
    assert(state->strm.avail_in == 0);
    assert(state->strm.next_in == state->in);
    assert(gzwrite(file, user_input, 1) == 1);
    (void)gzclose(file);
    close(fds[0]);
    return 0;
}
