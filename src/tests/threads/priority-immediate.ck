# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-immediate) begin
(priority-immediate) magic is initially 13
(priority-immediate) This thread should have priority 32.  Actual priority: 32.
(priority-immediate) magic is 5
(priority-immediate) acquire1: done
(priority-immediate) magic is now 28. It should be 28.
(priority-immediate) acquire1 must already have finished.
(priority-immediate) This should be the last line before finishing this test.
(priority-immediate) end
EOF
pass;
