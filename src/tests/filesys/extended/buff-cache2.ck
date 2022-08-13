# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(buff-cache) begin
(buff-cache) create "example"
(buff-cache) open "example"
(buff-cache) The number of writes is on the order of 128
(buff-cache) read "example"
(buff-cache) The number of writes is on the order of 128
(buff-cache) close "example"
EOF
pass;
