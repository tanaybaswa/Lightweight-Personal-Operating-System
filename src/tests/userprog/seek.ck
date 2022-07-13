# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seek) begin
(seek) create "test.txt"
(seek) open "test.txt"
(seek) end
seek: exit(0)
EOF
pass;