#!/usr/bin/env fish

set timeout 600  # 10 minutes in seconds
set targets fuzz_varint fuzz_primitives fuzz_network fuzz_script_differential
set pids

for target in $targets
    cargo +nightly fuzz run $target -- -max_total_time=$timeout &
    set pids $pids $last_pid
end

for pid in $pids
    wait $pid
end
