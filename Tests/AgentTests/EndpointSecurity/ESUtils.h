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

#ifndef ESUtils_h
#define ESUtils_h


#endif /* ESUtils */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <mach/mach_time.h>


es_process_t BuildEmptyESProcess(void);

es_message_t BuildEmptyESMessage(void);

es_events_t BuildESForkEvent(es_process_t *child);

es_events_t BuildESExecEvent(es_process_t *target, es_file_t *cwd, es_file_t *script);

es_events_t BuildESWriteEvent(es_file_t *file);

audit_token_t BuildAuditToken(pid_t pid, pid_t pid_version);

uint64_t AddNanosecsToMachTime(uint64_t nanosec_to_add);

uint32_t ESMessageVersionForOS(void);
