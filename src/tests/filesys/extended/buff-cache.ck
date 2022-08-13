# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(buff-cache) begin
(buff-cache) create "example"
(buff-cache) open "example"
(buff-cache) write "example"
(buff-cache) read "example"
(buff-cache) close "example"
(buff-cache) open "example"
(buff-cache) read "example"
(buff-cache) cache_hr is greater than cold_hr
(buff-cache) close "example"
EOF
pass;
