//
// Copyright © 2025 Santiago Alvarez. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//


#include <stdio.h>
#include "ESUtils.h"


uint64_t AddNanosecsToMachTime(uint64_t nanosec_to_add) {
    // Get the current Mach time
    uint64_t mach_time = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);

    // Convert nanoseconds to Mach time units
    // Mach time units are based on a timebase info structure obtained from mach_timebase_info()
    mach_timebase_info_data_t timebase_info;
    mach_timebase_info(&timebase_info);
    uint64_t mach_time_units = nanosec_to_add * timebase_info.denom / timebase_info.numer;

    // Add the Mach time units to the current Mach time
    uint64_t new_mach_time = mach_time + mach_time_units;

    return new_mach_time;
};

es_message_t BuildEmptyESMessage(void) {
    es_message_t msg = {};
    return msg;
};

es_process_t BuildEmptyESProcess(void) {
    es_process_t proc = {};
    return proc;
};

es_events_t BuildESExecEvent(es_process_t *target, es_file_t *cwd,
                             es_file_t *script) {
    es_event_exec_t exec;
    exec.target = target;
    exec.cwd = cwd;
    exec.script = script;

    es_events_t events;
    events.exec = exec;

    return events;
};

es_events_t BuildESWriteEvent(es_file_t *file) {
    es_event_write_t write;
    write.target = file;

    es_events_t events;
    events.write = write;

    return events;
};

es_events_t BuildESForkEvent(es_process_t *child) {
    es_event_fork_t fork;
    fork.child = child;

    es_events_t events;
    events.fork = fork;

    return events;
};

audit_token_t BuildAuditToken(pid_t pid, pid_t pid_version) {
    // audit_token_t format taken from xnu/kern_prot.c
    /*
     audit_token.val[0] = my_cred->cr_audit.as_aia_p->ai_auid;
     audit_token.val[1] = my_pcred->cr_uid;
     audit_token.val[2] = my_pcred->cr_gid;
     audit_token.val[3] = my_pcred->cr_ruid;
     audit_token.val[4] = my_pcred->cr_rgid;
     audit_token.val[5] = p->p_pid;
     audit_token.val[6] = my_cred->cr_audit.as_aia_p->ai_asid;
     audit_token.val[7] = p->p_idversion;
     */

    audit_token_t tok = {
        .val = {
            0,
            1,
            1,
            1,
            1,
            (unsigned int)pid,
            1,
            (unsigned int)pid_version
        }
    };
    return tok;
};

uint32_t ESMessageVersionForOS(void) {
    if (@available(macOS 13.0, *)) {
        return 6;
    } else if (@available(macOS 12.3, *)) {
        return 5;
    } else if (@available(macOS 11.0, *)) {
        return 4;
    } else if (@available(macOS 10.15.4, *)) {
        return 2;
    } else {
        return 1;
    }
};

