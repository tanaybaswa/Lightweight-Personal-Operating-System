# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(tell) begin
(tell) create "test.txt"
(tell) open "test.txt"
(tell) end
tell: exit(0)
EOF
pass;